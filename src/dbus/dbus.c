/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "dbus.h"
#include "../platform/linux/process_identity.h"
#include "../platform/linux/cgroup_v2.h"
#include "../session/termination.h"
#include "../session/termination_store.h"
#include "../runtime/runtime.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DL_LOGIN1_NAME "org.freedesktop.login1"
#define DL_LOGIN1_PATH "/org/freedesktop/login1"
#define DL_LOGIN1_IFACE "org.freedesktop.login1.Manager"
#define DL_INHIBITORS_MAX 4096u

#ifndef DL_POLKIT_AUTH_TIMEOUT_USEC
#define DL_POLKIT_AUTH_TIMEOUT_USEC (30ULL * 1000ULL * 1000ULL)
#endif

enum session_operation {
    SESSION_OP_ACTIVATE,
    SESSION_OP_TERMINATE,
    SESSION_OP_KILL_LEADER,
    SESSION_OP_KILL_ALL,
    SESSION_OP_LOCK,
    SESSION_OP_UNLOCK,
    SESSION_OP_SET_USER_LINGER
};

struct pending_authorization {
    struct dbus_context *ctx;
    sd_bus_slot *slot;
    sd_bus_message *request;
    char session_id[DL_SESSION_ID_MAX];
    enum session_operation operation;
    int32_t signal_number;
    uint32_t user_uid;
    bool user_linger_enabled;
    uint32_t polkit_flags;
    struct pending_authorization *next;
};

struct inhibitor_record {
    int write_fd;
    uint32_t uid;
    uint32_t pid;
    char what[DL_METADATA_MAX];
    char who[DL_METADATA_MAX];
    char why[DL_METADATA_MAX];
    char mode[16];
    struct inhibitor_record *next;
};

struct dbus_context {
    dl_manager *manager;
    sd_bus *bus;
    struct pending_authorization *pending;
    dl_termination_queue terminations;
    uint32_t terminate_timeout_sec;
    dl_termination_store termination_store;
    bool termination_store_open;
    dl_runtime_paths runtime_paths;
    struct inhibitor_record *inhibitors;
};

static int session_from_message(sd_bus_message *m, struct dbus_context *ctx,
                                dl_session **ret_session);
static int path_for_user(uint32_t uid, char *path, size_t size);

struct termination_payload {
    dl_linux_cgroup_v2_session cgroup;
    dl_termination_store *store;
    char session_id[DL_SESSION_ID_MAX];
};

static int termination_cgroup_kill(void *payload);
static void termination_cgroup_release(void *payload);
static int termination_recover_all(struct dbus_context *ctx);

static void pending_authorization_remove(struct pending_authorization *pending)
{
    struct pending_authorization **link;
    if (!pending || !pending->ctx) return;
    for (link = &pending->ctx->pending; *link; link = &(*link)->next) {
        if (*link == pending) {
            *link = pending->next;
            break;
        }
    }
}

static void pending_authorization_free(struct pending_authorization *pending)
{
    if (!pending) return;
    pending_authorization_remove(pending);
    sd_bus_slot_unref(pending->slot);
    sd_bus_message_unref(pending->request);
    free(pending);
}

static int session_authorization_reply(sd_bus_message *reply, void *userdata,
                                       sd_bus_error *ret_error)
{
    struct pending_authorization *pending = userdata;
    struct dbus_context *ctx = pending->ctx;
    dl_session *session = NULL;
    int authorized = 0, challenge = 0, r = 0;
    const char *member = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    (void)ret_error;

    if (sd_bus_message_is_method_error(reply, NULL) > 0 ||
        sd_bus_message_read(reply, "bb", &authorized, &challenge) < 0 ||
        sd_bus_message_skip(reply, "a{ss}") < 0 ||
        sd_bus_message_at_end(reply, 1) <= 0 || !authorized) {
        sd_bus_error_set_const(&error, "org.freedesktop.DBus.Error.AccessDenied",
                               challenge ? "Polkit authorization requires interaction" :
                                           "Polkit authorization was denied or unavailable");
        (void)sd_bus_reply_method_error(pending->request, &error);
        sd_bus_error_free(&error);
        pending_authorization_free(pending);
        return 1;
    }

    if (pending->operation == SESSION_OP_SET_USER_LINGER) {
        struct passwd pwd, *result = NULL;
        char scratch[16384];
        int lookup = getpwuid_r((uid_t)pending->user_uid, &pwd, scratch,
                                sizeof(scratch), &result);
        if (lookup != 0 || !result) {
            sd_bus_error_set_const(&error, "org.freedesktop.login1.NoSuchUser",
                                   "The requested UID has no passwd entry");
            (void)sd_bus_reply_method_error(pending->request, &error);
        } else {
            dl_result runtime_result = dl_runtime_set_linger(
                &ctx->runtime_paths, pending->user_uid,
                pending->user_linger_enabled);
            if (runtime_result != DL_OK) {
                sd_bus_error_set_const(&error,
                    runtime_result == DL_ERR_NOT_FOUND ?
                    "org.freedesktop.DBus.Error.NotSupported" :
                    "org.freedesktop.login1.OperationFailed",
                    "Persistent linger storage is unavailable or unsafe");
                (void)sd_bus_reply_method_error(pending->request, &error);
            } else if (dl_user_set_linger(ctx->manager, pending->user_uid,
                                          pending->user_linger_enabled) != DL_OK) {
                /* The persistent marker remains authoritative; retrying the
                 * request will reconcile the in-memory state. */
                sd_bus_error_set_const(&error,
                    "org.freedesktop.login1.OperationFailed",
                    "Unable to update the user state");
                (void)sd_bus_reply_method_error(pending->request, &error);
            } else {
                (void)sd_bus_reply_method_return(pending->request, "");
            }
        }
        sd_bus_error_free(&error);
        pending_authorization_free(pending);
        return 1;
    }

    session = dl_session_find(ctx->manager, pending->session_id);
    if (!session || dl_session_get_state(session) == DL_SESSION_CLOSED) {
        sd_bus_error_set_const(&error, "org.freedesktop.login1.NoSuchSession",
                               "Session closed while authorization was pending");
        (void)sd_bus_reply_method_error(pending->request, &error);
        sd_bus_error_free(&error);
        pending_authorization_free(pending);
        return 1;
    }

    switch (pending->operation) {
    case SESSION_OP_ACTIVATE:
        if (dl_session_activate(ctx->manager, dl_session_id(session)) != DL_OK)
            r = -EIO;
        break;
    case SESSION_OP_TERMINATE: {
        dl_linux_cgroup_v2 parent = {-1, {0}};
        dl_linux_cgroup_v2_session cgroup_session = {-1, -1, {0}};
        struct termination_payload *payload = NULL;
        dl_termination_record record;
        dl_process_identity leader = dl_session_leader(session);
        struct stat parent_st, child_st;
        struct timespec deadline;
        char boot_id[DL_TERMINATION_BOOT_ID_MAX];
        bool journal_written = false;

        if (dl_session_is_stopping(session) ||
            dl_termination_queue_contains(&ctx->terminations,
                                         pending->session_id)) {
            r = 0;
            break;
        }
        if (!ctx->termination_store_open) { r = -ENOTSUP; break; }
        r = dl_linux_cgroup_v2_open_current(&parent);
        if (r < 0) { r = -ENOTSUP; break; }
        r = dl_linux_cgroup_v2_session_open(
            &parent, pending->session_id, &leader, &cgroup_session);
        if (r == 0)
            r = dl_linux_cgroup_v2_session_kill_all_available(&cgroup_session);
        if (r == 0 && (fstat(parent.fd, &parent_st) != 0 ||
                       fstat(cgroup_session.fd, &child_st) != 0))
            r = -errno;
        if (r == 0 && clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
            r = -errno;
        if (r == 0 && (uint64_t)deadline.tv_sec >
                      UINT64_MAX - ctx->terminate_timeout_sec)
            r = -EOVERFLOW;
        if (r == 0) {
            deadline.tv_sec += (time_t)ctx->terminate_timeout_sec;
            if (deadline.tv_sec < 0) r = -EOVERFLOW;
        }
        if (r == 0) r = dl_termination_store_read_boot_id(boot_id);
        if (r == 0) {
            memset(&record, 0, sizeof(record));
            (void)snprintf(record.session_id, sizeof(record.session_id), "%s",
                           pending->session_id);
            (void)snprintf(record.boot_id, sizeof(record.boot_id), "%s", boot_id);
            (void)snprintf(record.cgroup_name, sizeof(record.cgroup_name), "%s",
                           cgroup_session.name);
            record.deadline_sec = (uint64_t)deadline.tv_sec;
            record.deadline_nsec = (uint32_t)deadline.tv_nsec;
            record.parent_dev = (uint64_t)parent_st.st_dev;
            record.parent_ino = (uint64_t)parent_st.st_ino;
            record.cgroup_dev = (uint64_t)child_st.st_dev;
            record.cgroup_ino = (uint64_t)child_st.st_ino;
            record.leader_pid = leader.pid;
            record.leader_start_time = leader.process_start_time;
            record.pid_namespace_inode = leader.pid_namespace_inode;
            /* Durable intent must reach stable storage before signals/ack. */
            r = dl_termination_store_put(&ctx->termination_store, &record);
            if (r == 0) journal_written = true;
        }
        if (r == 0) {
            payload = calloc(1, sizeof(*payload));
            if (!payload) r = -ENOMEM;
            else {
                payload->cgroup = cgroup_session;
                payload->store = &ctx->termination_store;
                (void)snprintf(payload->session_id, sizeof(payload->session_id),
                               "%s", pending->session_id);
                cgroup_session.fd = -1;
                cgroup_session.parent_fd = -1;
                cgroup_session.name[0] = '\0';
            }
        }
        if (r == 0) {
            r = dl_termination_queue_schedule_at(
                &ctx->terminations, pending->session_id, &deadline, payload,
                termination_cgroup_kill, termination_cgroup_release);
            if (r == 0) {
                struct termination_payload *queued_payload = payload;
                int term_result, cont_result, hup_result;
                payload = NULL;
                if (dl_session_begin_stop(ctx->manager,
                                          pending->session_id) != DL_OK) {
                    r = -ESTALE;
                    (void)dl_termination_store_remove(&ctx->termination_store,
                                                      pending->session_id);
                } else {
                    term_result = dl_linux_cgroup_v2_session_signal_all(
                        &queued_payload->cgroup, SIGTERM);
                    cont_result = dl_linux_cgroup_v2_session_signal_all(
                        &queued_payload->cgroup, SIGCONT);
                    hup_result = dl_linux_cgroup_v2_session_signal_all(
                        &queued_payload->cgroup, SIGHUP);
                    if (term_result < 0 || cont_result < 0 || hup_result < 0) {
                        fprintf(stderr,
                            "dinit-logind: initial signals for %s failed "
                            "(TERM=%d CONT=%d HUP=%d); retaining durable SIGKILL\n",
                            pending->session_id, term_result, cont_result, hup_result);
                        r = term_result < 0 ? term_result :
                            cont_result < 0 ? cont_result : hup_result;
                    }
                }
            }
        }
        if (payload) {
            if (journal_written)
                (void)dl_termination_store_remove(&ctx->termination_store,
                                                 pending->session_id);
            termination_cgroup_release(payload);
        } else if (journal_written &&
                   !dl_termination_queue_contains(&ctx->terminations,
                                                  pending->session_id)) {
            /* No deferred owner accepted the payload; discard the intent. */
            (void)dl_termination_store_remove(&ctx->termination_store,
                                             pending->session_id);
        }
        dl_linux_cgroup_v2_session_release(&cgroup_session);
        dl_linux_cgroup_v2_close(&parent);
        if (r == -ENOENT || r == -ENODEV || r == -EACCES ||
            r == -EPERM || r == -EXDEV || r == -EINVAL)
            r = -ENOTSUP;
        break;
    }
    case SESSION_OP_KILL_ALL: {
        dl_linux_cgroup_v2 parent = {-1, {0}};
        dl_linux_cgroup_v2_session cgroup_session = {-1, -1, {0}};
        dl_process_identity leader = dl_session_leader(session);
        r = dl_linux_cgroup_v2_open_current(&parent);
        if (r < 0) {
            r = -ENOTSUP;
            break;
        }
        r = dl_linux_cgroup_v2_session_open(
            &parent, pending->session_id, &leader, &cgroup_session);
        if (r == 0) {
            r = pending->signal_number == SIGKILL ?
                dl_linux_cgroup_v2_session_kill_all(&cgroup_session) :
                dl_linux_cgroup_v2_session_signal_all(
                    &cgroup_session, pending->signal_number);
            dl_linux_cgroup_v2_session_release(&cgroup_session);
        }
        dl_linux_cgroup_v2_close(&parent);
        if (r == -ENOENT || r == -ENODEV || r == -EACCES ||
            r == -EPERM || r == -EXDEV || r == -EINVAL)
            r = -ENOTSUP;
        break;
    }
    case SESSION_OP_KILL_LEADER: {
        dl_process_identity leader = dl_session_leader(session);
        r = dl_linux_process_signal(&leader, pending->signal_number);
        break;
    }

    case SESSION_OP_LOCK:
    case SESSION_OP_UNLOCK:
        member = pending->operation == SESSION_OP_LOCK ? "Lock" : "Unlock";
        r = sd_bus_emit_signal(ctx->bus, sd_bus_message_get_path(pending->request),
                               "org.freedesktop.login1.Session", member, "");
        break;
    case SESSION_OP_SET_USER_LINGER:
        r = -EINVAL; /* Handled before resolving a session object. */
        break;
    }

    if (r < 0) {
        sd_bus_error_set_const(&error,
            r == -ENOTSUP ? "org.freedesktop.DBus.Error.NotSupported" :
                            "org.freedesktop.login1.OperationFailed",
            r == -ENOTSUP ? "Safe session signaling requires cgroup v2 and pidfd support" :
                            "The authorized session operation failed");
        (void)sd_bus_reply_method_error(pending->request, &error);
    } else {
        (void)sd_bus_reply_method_return(pending->request, "");
    }
    sd_bus_error_free(&error);
    pending_authorization_free(pending);
    return 1;
}

static int authorize_session_async(sd_bus_message *m, struct dbus_context *ctx,
                                   const char *action,
                                   enum session_operation operation,
                                   int32_t signal_number,
                                   sd_bus_error *error)
{
    struct pending_authorization *pending = NULL;
    sd_bus_message *call = NULL;
    dl_session *session = NULL;
    const char *sender;
    int r;

    r = session_from_message(m, ctx, &session);
    if (r < 0)
        return sd_bus_error_set_const(error, "org.freedesktop.login1.NoSuchSession",
                                      "Session no longer exists");
    sender = sd_bus_message_get_sender(m);
    if (!sender || sender[0] != ':')
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.AccessDenied",
                                      "A unique D-Bus sender is required for authorization");

    pending = calloc(1, sizeof(*pending));
    if (!pending)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.NoMemory",
                                      "Unable to allocate authorization request");
    pending->ctx = ctx;
    pending->operation = operation;
    pending->signal_number = signal_number;
    (void)snprintf(pending->session_id, sizeof(pending->session_id), "%s",
                   dl_session_id(session));
    pending->request = sd_bus_message_ref(m);
    pending->next = ctx->pending;
    ctx->pending = pending;

    r = sd_bus_message_new_method_call(ctx->bus, &call,
        "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
    if (r >= 0) r = sd_bus_message_open_container(call, 'r', "sa{sv}");
    if (r >= 0) r = sd_bus_message_append(call, "s", "system-bus-name");
    if (r >= 0) r = sd_bus_message_open_container(call, 'a', "{sv}");
    if (r >= 0) r = sd_bus_message_append(call, "{sv}", "name", "s", sender);
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_append(call, "s", action);
    if (r >= 0) r = sd_bus_message_open_container(call, 'a', "{ss}");
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_append(call, "us", pending->polkit_flags, "");
    if (r >= 0) r = sd_bus_call_async(ctx->bus, &pending->slot, call,
                                      session_authorization_reply, pending,
                                      DL_POLKIT_AUTH_TIMEOUT_USEC);
    sd_bus_message_unref(call);
    if (r < 0) {
        pending_authorization_free(pending);
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.AccessDenied",
                                      "Unable to contact Polkit authority");
    }
    return 1;
}

static int method_set_user_linger(sd_bus_message *m, void *userdata,
                                    sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    struct pending_authorization *pending = NULL;
    sd_bus_message *call = NULL;
    const char *sender;
    uint32_t uid;
    int enable, interactive, r;

    r = sd_bus_message_read(m, "ubb", &uid, &enable, &interactive);
    if (r < 0) return r;
    if (enable != 0 && enable != 1)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                                      "Invalid linger enable flag");
    if (interactive != 0 && interactive != 1)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                                      "Invalid interactive flag");
    if (uid == 0)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                                      "Linger for the root user is not supported");
    sender = sd_bus_message_get_sender(m);
    if (!sender || sender[0] != ':')
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.AccessDenied",
                                      "A unique D-Bus sender is required for authorization");

    pending = calloc(1, sizeof(*pending));
    if (!pending)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.NoMemory",
                                      "Unable to allocate authorization request");
    pending->ctx = ctx;
    pending->operation = SESSION_OP_SET_USER_LINGER;
    pending->user_uid = uid;
    pending->user_linger_enabled = enable != 0;
    pending->polkit_flags = interactive ? 1u : 0u;
    pending->request = sd_bus_message_ref(m);
    pending->next = ctx->pending;
    ctx->pending = pending;

    r = sd_bus_message_new_method_call(ctx->bus, &call,
        "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
    if (r >= 0) r = sd_bus_message_open_container(call, 'r', "sa{sv}");
    if (r >= 0) r = sd_bus_message_append(call, "s", "system-bus-name");
    if (r >= 0) r = sd_bus_message_open_container(call, 'a', "{sv}");
    if (r >= 0) r = sd_bus_message_append(call, "{sv}", "name", "s",
                                           sender);
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_append(call, "s",
                                           "org.freedesktop.login1.set-user-linger");
    if (r >= 0) r = sd_bus_message_open_container(call, 'a', "{ss}");
    if (r >= 0) r = sd_bus_message_close_container(call);
    if (r >= 0) r = sd_bus_message_append(call, "us", pending->polkit_flags, "");
    if (r >= 0) r = sd_bus_call_async(ctx->bus, &pending->slot, call,
                                      session_authorization_reply, pending,
                                      DL_POLKIT_AUTH_TIMEOUT_USEC);
    sd_bus_message_unref(call);
    if (r < 0) {
        pending_authorization_free(pending);
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.AccessDenied",
                                      "Unable to contact Polkit authority");
    }
    return 1;
}

static void pending_authorizations_cancel(struct dbus_context *ctx)
{
    while (ctx && ctx->pending) {
        struct pending_authorization *pending = ctx->pending;
        ctx->pending = pending->next;
        pending->ctx = NULL;
        sd_bus_slot_unref(pending->slot);
        sd_bus_message_unref(pending->request);
        free(pending);
    }
}

static int termination_cgroup_kill(void *userdata)
{
    struct termination_payload *payload = userdata;
    int r;
    if (!payload) return -EINVAL;
    r = dl_linux_cgroup_v2_session_kill_all(&payload->cgroup);
    if (r == 0 && payload->store)
        r = dl_termination_store_remove(payload->store, payload->session_id);
    return r;
}

static void termination_cgroup_release(void *userdata)
{
    struct termination_payload *payload = userdata;
    if (!payload) return;
    dl_linux_cgroup_v2_session_release(&payload->cgroup);
    free(payload);
}

static int make_object_path(const char *kind, const char *id,
                            char *buffer, size_t size)
{
    size_t used;
    const unsigned char *p;
    int n;
    if (!kind || !id || !buffer || size == 0) return -EINVAL;
    n = snprintf(buffer, size, DL_LOGIN1_PATH "/%s/", kind);
    if (n < 0 || (size_t)n >= size) return -ENAMETOOLONG;
    used = (size_t)n;
    for (p = (const unsigned char *)id; *p; ++p) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9')  ) {
            if (used + 1 >= size) return -ENAMETOOLONG;
            buffer[used++] = (char)*p;
        } else {
            n = snprintf(buffer + used, size - used, "_%02x", (unsigned int)*p);
            if (n < 0 || (size_t)n >= size - used) return -ENAMETOOLONG;
            used += (size_t)n;
        }
    }
    if (used + 1 > size) return -ENAMETOOLONG;
    buffer[used] = '\0';
    return 0;
}

static int uid_to_name(uint32_t uid, char *name, size_t size)
{
    struct passwd pwd, *result = NULL;
    char scratch[16384];
    int r;
    r = getpwuid_r((uid_t)uid, &pwd, scratch, sizeof(scratch), &result);
    if (r == 0 && result && result->pw_name) {
        if (snprintf(name, size, "%s", result->pw_name) >= (int)size)
            return -ENAMETOOLONG;
        return 0;
    }
    if (snprintf(name, size, "%u", (unsigned int)uid) >= (int)size)
        return -ENAMETOOLONG;
    return 0;
}

static int path_for_user(uint32_t uid, char *path, size_t size);

static void inhibitor_remove(struct dbus_context *ctx,
                             struct inhibitor_record **link)
{
    struct inhibitor_record *record;
    if (!ctx || !link || !*link) return;
    record = *link;
    *link = record->next;
    if (record->write_fd >= 0) close(record->write_fd);
    free(record);
}

/* The client owns the read end of a pipe; the daemon retains the write end.
 * POLLERR on the write end means every client copy of the inhibitor FD closed. */
static void inhibitors_emit_changed(struct dbus_context *ctx)
{
    if (!ctx || !ctx->bus) return;
    (void)sd_bus_emit_properties_changed(ctx->bus, DL_LOGIN1_PATH,
        DL_LOGIN1_IFACE, "NCurrentInhibitors", "BlockInhibited",
        "DelayInhibited", NULL);
}

static void inhibitors_reap(struct dbus_context *ctx)
{
    struct inhibitor_record **link;
    bool changed = false;
    if (!ctx) return;
    for (link = &ctx->inhibitors; *link;) {
        struct pollfd pfd = { .fd = (*link)->write_fd, .events = POLLERR | POLLHUP };
        int r = poll(&pfd, 1, 0);
        if (r > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            inhibitor_remove(ctx, link);
            changed = true;
        }
        else
            link = &(*link)->next;
    }
    if (changed) inhibitors_emit_changed(ctx);
}

static int method_inhibit(sd_bus_message *m, void *userdata,
                          sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    struct inhibitor_record *record = NULL;
    sd_bus_creds *creds = NULL;
    const char *what, *who, *why, *mode;
    uid_t uid;
    pid_t pid;
    struct inhibitor_record *existing;
    size_t inhibitor_count = 0;
    int fds[2] = {-1, -1};
    int r;

    r = sd_bus_message_read(m, "ssss", &what, &who, &why, &mode);
    if (r < 0) return r;
    if (!what || !what[0] || !who || !who[0] || !why || !mode ||
        (strcmp(mode, "block") != 0 && strcmp(mode, "delay") != 0) ||
        strnlen(what, DL_METADATA_MAX) >= DL_METADATA_MAX ||
        strnlen(who, DL_METADATA_MAX) >= DL_METADATA_MAX ||
        strnlen(why, DL_METADATA_MAX) >= DL_METADATA_MAX)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.InvalidArgs",
            "Inhibit requires bounded what/who/why strings and block or delay mode");

    if (strcmp(mode, "delay") == 0)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.NotSupported",
            "Delay inhibitors are unavailable until power-transition coordination is enabled");

    r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID | SD_BUS_CREDS_PID, &creds);
    if (r < 0)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.AccessDenied",
            "Unable to determine inhibitor owner credentials");
    r = sd_bus_creds_get_euid(creds, &uid);
    if (r >= 0) r = sd_bus_creds_get_pid(creds, &pid);
    sd_bus_creds_unref(creds);
    if (r < 0)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.AccessDenied",
            "Unable to determine inhibitor owner credentials");

    for (existing = ctx->inhibitors; existing; existing = existing->next)
        ++inhibitor_count;
    if (inhibitor_count >= DL_INHIBITORS_MAX)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.LimitsExceeded",
            "The inhibitor limit has been reached");

    record = calloc(1, sizeof(*record));
    if (!record)
        return sd_bus_error_set_const(error,
            "org.freedesktop.DBus.Error.NoMemory",
            "Unable to allocate inhibitor record");
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        free(record);
        return sd_bus_error_setf(error,
            "org.freedesktop.login1.OperationFailed",
            "Unable to create inhibitor descriptor: %s", strerror(errno));
    }
    record->write_fd = fds[1];
    record->uid = (uint32_t)uid;
    record->pid = (uint32_t)pid;
    (void)snprintf(record->what, sizeof(record->what), "%s", what);
    (void)snprintf(record->who, sizeof(record->who), "%s", who);
    (void)snprintf(record->why, sizeof(record->why), "%s", why);
    (void)snprintf(record->mode, sizeof(record->mode), "%s", mode);

    r = sd_bus_reply_method_return(m, "h", fds[0]);
    /* sd-bus may retain the descriptor number until queued output is flushed.
     * Keep the read end open until the SCM_RIGHTS transfer is complete. */
    if (r >= 0) r = sd_bus_flush(ctx->bus);
    close(fds[0]);
    if (r < 0) {
        close(record->write_fd);
        free(record);
        return r;
    }
    record->next = ctx->inhibitors;
    ctx->inhibitors = record;
    inhibitors_emit_changed(ctx);
    return r;
}

static int method_list_inhibitors(sd_bus_message *m, void *userdata,
                                  sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    struct inhibitor_record *record;
    sd_bus_message *reply = NULL;
    int r;
    (void)error;
    inhibitors_reap(ctx);
    r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "(ssssuu)");
    for (record = ctx->inhibitors; r >= 0 && record; record = record->next)
        r = sd_bus_message_append(reply, "(ssssuu)", record->what, record->who,
                                  record->why, record->mode, record->uid, record->pid);
    if (r >= 0) r = sd_bus_message_close_container(reply);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
    sd_bus_message_unref(reply);
    return r;
}

static void inhibitors_finish(struct dbus_context *ctx)
{
    while (ctx && ctx->inhibitors)
        inhibitor_remove(ctx, &ctx->inhibitors);
}

static int method_get_session(sd_bus_message *m, void *userdata,
                              sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    const char *id;
    char path[256];
    if (sd_bus_message_read(m, "s", &id) < 0) return -EINVAL;
    if (!dl_session_find(ctx->manager, id) ||
        dl_session_get_state(dl_session_find(ctx->manager, id)) == DL_SESSION_CLOSED)
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSuchSession", "No session '%s'", id);
    if (make_object_path("session", id, path, sizeof(path)) < 0)
        return sd_bus_error_set_const(ret_error,
            "org.freedesktop.DBus.Error.InvalidArgs", "Invalid session identifier");
    return sd_bus_reply_method_return(m, "o", path);
}


static int identity_for_pid_argument(sd_bus_message *m, uint32_t requested_pid,
                                     dl_process_identity *identity)
{
    uint32_t pid = requested_pid;
    int r;

    if (pid == 0) {
        sd_bus_creds *creds = NULL;
        pid_t sender_pid = 0;

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_PID, &creds);
        if (r < 0) return r;
        r = sd_bus_creds_get_pid(creds, &sender_pid);
        sd_bus_creds_unref(creds);
        if (r < 0) return r;
        if (sender_pid <= 0) return -EINVAL;
        pid = (uint32_t)sender_pid;
    }

    return dl_linux_process_identity_read(pid, identity) == DL_OK ? 0 : -ESRCH;
}

static int method_get_session_by_pid(sd_bus_message *m, void *userdata,
                                     sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    uint32_t pid;
    dl_process_identity identity;
    dl_session *session;
    char path[256];
    int r;

    if (sd_bus_message_read(m, "u", &pid) < 0) return -EINVAL;
    r = identity_for_pid_argument(m, pid, &identity);
    if (r < 0)
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSessionForPID",
            "PID %u does not belong to a tracked session", pid);
    session = dl_session_find_by_identity(ctx->manager, &identity);
    if (session == NULL)
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSessionForPID",
            "PID %u does not belong to a tracked session", pid);
    if (make_object_path("session", dl_session_id(session), path, sizeof(path)) < 0)
        return sd_bus_error_set_const(ret_error,
            "org.freedesktop.DBus.Error.InvalidArgs", "Invalid session identifier");
    return sd_bus_reply_method_return(m, "o", path);
}

static int method_get_user_by_pid(sd_bus_message *m, void *userdata,
                                  sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    uint32_t pid, uid;
    dl_process_identity identity;
    char path[256];
    int r;

    if (sd_bus_message_read(m, "u", &pid) < 0) return -EINVAL;
    r = identity_for_pid_argument(m, pid, &identity);
    if (r < 0 || dl_linux_process_uid_read(identity.pid, &uid) != DL_OK)
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoUserForPID",
            "PID %u has no readable, stable user identity", pid);
    if (dl_user_find(ctx->manager, uid) == NULL)
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoUserForPID",
            "PID %u does not belong to a tracked user session", pid);
    if (path_for_user(uid, path, sizeof(path)) < 0)
        return sd_bus_error_set_const(ret_error,
            "org.freedesktop.DBus.Error.InvalidArgs", "Invalid user identifier");
    return sd_bus_reply_method_return(m, "o", path);
}

static int method_get_user(sd_bus_message *m, void *userdata,
                           sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    uint32_t uid;
    char path[256];
    if (sd_bus_message_read(m, "u", &uid) < 0) return -EINVAL;
    if (!dl_user_find(ctx->manager, uid))
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSuchUser", "No user with UID %u", uid);
    if (path_for_user(uid, path, sizeof(path)) < 0)
        return sd_bus_error_set_const(ret_error,
            "org.freedesktop.DBus.Error.InvalidArgs", "Invalid user identifier");
    return sd_bus_reply_method_return(m, "o", path);
}

static int method_get_seat(sd_bus_message *m, void *userdata,
                           sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    const char *id;
    char path[256];
    if (sd_bus_message_read(m, "s", &id) < 0) return -EINVAL;
    if (!dl_seat_find(ctx->manager, id))
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSuchSeat", "No seat '%s'", id);
    if (make_object_path("seat", id, path, sizeof(path)) < 0)
        return sd_bus_error_set_const(ret_error,
            "org.freedesktop.DBus.Error.InvalidArgs", "Invalid seat identifier");
    return sd_bus_reply_method_return(m, "o", path);
}

static int method_list_sessions(sd_bus_message *m, void *userdata,
                                sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    sd_bus_message *reply = NULL;
    size_t i;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "(susso)");
    for (i = 0; r >= 0 && i < dl_manager_session_count(ctx->manager); ++i) {
        const dl_session *session = dl_manager_session_at(ctx->manager, i);
        char path[256], username[256];
        const char *seat = dl_session_seat(session);
        uint32_t uid = dl_session_uid(session);
        if (!session || make_object_path("session", dl_session_id(session),
                                         path, sizeof(path)) < 0 ||
            uid_to_name(uid, username, sizeof(username)) < 0) {
            r = -EINVAL;
            break;
        }
        r = sd_bus_message_append(reply, "(susso)", dl_session_id(session),
                                  uid, username, seat ? seat : "", path);
    }
    if (r >= 0) r = sd_bus_message_close_container(reply);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
    sd_bus_message_unref(reply);
    (void)ret_error;
    return r;
}

static int method_list_users(sd_bus_message *m, void *userdata,
                             sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    sd_bus_message *reply = NULL;
    size_t i;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "(uso)");
    for (i = 0; r >= 0 && i < dl_manager_user_count(ctx->manager); ++i) {
        const dl_user *user = dl_manager_user_at(ctx->manager, i);
        uint32_t uid = dl_user_uid(user);
        char username[256], path[256];
        if (uid_to_name(uid, username, sizeof(username)) < 0 ||
            path_for_user(uid, path, sizeof(path)) < 0) {
            r = -EINVAL;
            break;
        }
        r = sd_bus_message_append(reply, "(uso)", uid, username, path);
    }
    if (r >= 0) r = sd_bus_message_close_container(reply);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
    sd_bus_message_unref(reply);
    (void)ret_error;
    return r;
}

static int method_list_seats(sd_bus_message *m, void *userdata,
                             sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    sd_bus_message *reply = NULL;
    size_t i;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r < 0) return r;
    r = sd_bus_message_open_container(reply, 'a', "(so)");
    for (i = 0; r >= 0 && i < dl_manager_seat_count(ctx->manager); ++i) {
        const dl_seat *seat = dl_manager_seat_at(ctx->manager, i);
        char path[256];
        if (make_object_path("seat", dl_seat_id(seat), path, sizeof(path)) < 0) {
            r = -EINVAL;
            break;
        }
        r = sd_bus_message_append(reply, "(so)", dl_seat_id(seat), path);
    }
    if (r >= 0) r = sd_bus_message_close_container(reply);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(m), reply, NULL);
    sd_bus_message_unref(reply);
    (void)ret_error;
    return r;
}



static int decode_component(const char *path, const char *prefix,
                            char *out, size_t out_size)
{
    size_t used = 0;
    const char *p;
    if (!path || !prefix || !out || strncmp(path, prefix, strlen(prefix)) != 0)
        return -EINVAL;
    p = path + strlen(prefix);
    if (*p == '\0' || strchr(p, '/') != NULL) return -EINVAL;
    while (*p) {
        unsigned int value;
        if (*p == '_') {
            char hex[3];
            char *end = NULL;
            if (!p[1] || !p[2]) return -EINVAL;
            hex[0] = p[1]; hex[1] = p[2]; hex[2] = '\0';
            value = (unsigned int)strtoul(hex, &end, 16);
            if (end == hex || *end != '\0' || value == 0) return -EINVAL;
            p += 3;
        } else {
            value = (unsigned char)*p++;
        }
        if (used + 1 >= out_size) return -ENAMETOOLONG;
        out[used++] = (char)value;
    }
    out[used] = '\0';
    return 0;
}

static int path_for_user(uint32_t uid, char *path, size_t size)
{
    int n = snprintf(path, size, DL_LOGIN1_PATH "/user/_%u",
                     (unsigned int)uid);
    if (n < 0) return -EINVAL;
    return (size_t)n >= size ? -ENAMETOOLONG : 0;
}

static int property_unknown(sd_bus_error *error, const char *name)
{
    return sd_bus_error_setf(error, "org.freedesktop.DBus.Error.UnknownProperty",
                             "Unknown property '%s'", name);
}

static int session_property(sd_bus *bus, const char *path, const char *interface,
                            const char *property, sd_bus_message *reply,
                            void *userdata, sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    char id[DL_SESSION_ID_MAX], object[256], username[256];
    dl_session *session;
    uint32_t uid;
    int r;
    (void)bus; (void)interface;
    r = decode_component(path, DL_LOGIN1_PATH "/session/", id, sizeof(id));
    if (r < 0 || !(session = dl_session_find(ctx->manager, id)) ||
        dl_session_get_state(session) == DL_SESSION_CLOSED)
        return sd_bus_error_set_const(error, "org.freedesktop.login1.NoSuchSession",
                                      "Session no longer exists");
    uid = dl_session_uid(session);
    if (strcmp(property, "Id") == 0)
        return sd_bus_message_append(reply, "s", dl_session_id(session));
    if (strcmp(property, "User") == 0) {
        if (path_for_user(uid, object, sizeof(object)) < 0) return -EINVAL;
        return sd_bus_message_append(reply, "(uo)", uid, object);
    }
    if (strcmp(property, "Name") == 0) {
        if (uid_to_name(uid, username, sizeof(username)) < 0) return -EINVAL;
        return sd_bus_message_append(reply, "s", username);
    }
    if (strcmp(property, "Timestamp") == 0 ||
        strcmp(property, "TimestampMonotonic") == 0 ||
        strcmp(property, "LeaderPIDFDId") == 0)
        return sd_bus_message_append(reply, "t", (uint64_t)0);
    if (strcmp(property, "VTNr") == 0)
        return sd_bus_message_append(reply, "u", dl_session_vtnr(session));
    if (strcmp(property, "Seat") == 0) {
        const char *seat = dl_session_seat(session);
        if (seat && make_object_path("seat", seat, object, sizeof(object)) < 0)
            return -EINVAL;
        return sd_bus_message_append(reply, "(so)", seat ? seat : "",
                                     seat ? object : "/");
    }
    if (strcmp(property, "TTY") == 0)
        return sd_bus_message_append(reply, "s", dl_session_tty(session) ?
                                     dl_session_tty(session) : "");
    if (strcmp(property, "Display") == 0)
        return sd_bus_message_append(reply, "s", dl_session_display(session) ?
                                     dl_session_display(session) : "");
    if (strcmp(property, "Remote") == 0)
        return sd_bus_message_append(reply, "b", dl_session_is_remote(session));
    if (strcmp(property, "RemoteHost") == 0)
        return sd_bus_message_append(reply, "s", dl_session_remote_host(session) ?
                                     dl_session_remote_host(session) : "");
    if (strcmp(property, "RemoteUser") == 0)
        return sd_bus_message_append(reply, "s", dl_session_remote_user(session) ?
                                     dl_session_remote_user(session) : "");
    if (strcmp(property, "Service") == 0)
        return sd_bus_message_append(reply, "s", dl_session_service(session) ?
                                     dl_session_service(session) : "");
    if (strcmp(property, "Leader") == 0)
        return sd_bus_message_append(reply, "u", dl_session_leader(session).pid);
    if (strcmp(property, "Type") == 0)
        return sd_bus_message_append(reply, "s", dl_session_type(session) ?
                                     dl_session_type(session) : "");
    if (strcmp(property, "Class") == 0)
        return sd_bus_message_append(reply, "s", dl_session_class(session) ?
                                     dl_session_class(session) : "");
    if (strcmp(property, "Active") == 0)
        return sd_bus_message_append(reply, "b",
                                     dl_session_get_state(session) == DL_SESSION_ACTIVE);
    if (strcmp(property, "State") == 0)
        return sd_bus_message_append(reply, "s",
            dl_session_is_stopping(session) ? "closing" :
            dl_session_get_state(session) == DL_SESSION_ACTIVE ? "active" : "online");
    if (strcmp(property, "CanIdle") == 0 || strcmp(property, "CanLock") == 0 ||
        strcmp(property, "LockedHint") == 0 || strcmp(property, "IdleHint") == 0)
        return sd_bus_message_append(reply, "b", 0);
    if (strcmp(property, "IdleSinceHint") == 0 ||
        strcmp(property, "IdleSinceHintMonotonic") == 0)
        return sd_bus_message_append(reply, "t", (uint64_t)0);
    return property_unknown(error, property);
}

static int user_property(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    const char *uid_text;
    char *end = NULL, name[256], object[256];
    unsigned long parsed;
    const dl_user *user;
    struct passwd pwd, *result = NULL;
    char scratch[16384];
    bool linger_enabled;
    size_t i;
    int r;
    (void)bus; (void)interface;
    if (strncmp(path, DL_LOGIN1_PATH "/user/_",
                strlen(DL_LOGIN1_PATH "/user/_")) != 0)
        return property_unknown(error, property);
    uid_text = path + strlen(DL_LOGIN1_PATH "/user/_");
    if (*uid_text == '\0' || strchr(uid_text, '/') != NULL)
        return property_unknown(error, property);
    errno = 0;
    parsed = strtoul(uid_text, &end, 10);
    if (errno || end == uid_text || *end || parsed > UINT32_MAX)
        return property_unknown(error, property);
    user = dl_user_find(ctx->manager, (uint32_t)parsed);
    if (!user) return sd_bus_error_set_const(error, "org.freedesktop.login1.NoSuchUser",
                                              "User no longer exists");
    linger_enabled = dl_user_linger_enabled(user);
    {
        bool persisted = false;
        if (dl_runtime_get_linger(&ctx->runtime_paths, (uint32_t)parsed,
                                  &persisted) == DL_OK)
            linger_enabled = persisted;
    }
    if (strcmp(property, "UID") == 0)
        return sd_bus_message_append(reply, "u", (uint32_t)parsed);
    if (strcmp(property, "GID") == 0) {
        r = getpwuid_r((uid_t)parsed, &pwd, scratch, sizeof(scratch), &result);
        return sd_bus_message_append(reply, "u",
            r == 0 && result ? (uint32_t)result->pw_gid : (uint32_t)parsed);
    }
    if (strcmp(property, "Name") == 0) {
        if (uid_to_name((uint32_t)parsed, name, sizeof(name)) < 0) return -EINVAL;
        return sd_bus_message_append(reply, "s", name);
    }
    if (strcmp(property, "Timestamp") == 0 ||
        strcmp(property, "TimestampMonotonic") == 0 ||
        strcmp(property, "IdleSinceHint") == 0 ||
        strcmp(property, "IdleSinceHintMonotonic") == 0)
        return sd_bus_message_append(reply, "t", (uint64_t)0);
    if (strcmp(property, "RuntimePath") == 0 ||
        strcmp(property, "Service") == 0 || strcmp(property, "Slice") == 0)
        return sd_bus_message_append(reply, "s", "");
    if (strcmp(property, "State") == 0) {
        const char *state = dl_user_active_session_count(user) ? "active" :
            dl_user_session_count(user) ? "online" :
            linger_enabled ? "lingering" : "offline";
        return sd_bus_message_append(reply, "s", state);
    }
    if (strcmp(property, "Display") == 0)
        return sd_bus_message_append(reply, "(so)", "", "/");
    if (strcmp(property, "Linger") == 0)
        return sd_bus_message_append(reply, "b", linger_enabled);
    if (strcmp(property, "IdleHint") == 0)
        return sd_bus_message_append(reply, "b", 0);
    if (strcmp(property, "Sessions") == 0) {
        r = sd_bus_message_open_container(reply, 'a', "(so)");
        for (i = 0; r >= 0 && i < dl_manager_session_count(ctx->manager); ++i) {
            const dl_session *s = dl_manager_session_at(ctx->manager, i);
            if (dl_session_uid(s) != (uint32_t)parsed) continue;
            if (make_object_path("session", dl_session_id(s), object,
                                sizeof(object)) < 0) return -EINVAL;
            r = sd_bus_message_append(reply, "(so)", dl_session_id(s), object);
        }
        if (r >= 0) r = sd_bus_message_close_container(reply);
        return r;
    }
    return property_unknown(error, property);
}

static int seat_property(sd_bus *bus, const char *path, const char *interface,
                         const char *property, sd_bus_message *reply,
                         void *userdata, sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    char id[DL_METADATA_MAX], object[256];
    const dl_seat *seat;
    size_t i;
    int r;
    (void)bus; (void)interface;
    r = decode_component(path, DL_LOGIN1_PATH "/seat/", id, sizeof(id));
    if (r < 0 || !(seat = dl_seat_find(ctx->manager, id)))
        return sd_bus_error_set_const(error, "org.freedesktop.login1.NoSuchSeat",
                                      "Seat no longer exists");
    if (strcmp(property, "Id") == 0)
        return sd_bus_message_append(reply, "s", dl_seat_id(seat));
    if (strcmp(property, "ActiveSession") == 0) {
        const char *active = dl_seat_active_session_id(seat);
        if (active && make_object_path("session", active, object, sizeof(object)) < 0)
            return -EINVAL;
        return sd_bus_message_append(reply, "(so)", active ? active : "",
                                     active ? object : "/");
    }
    if (strcmp(property, "CanTTY") == 0 || strcmp(property, "CanGraphical") == 0 ||
        strcmp(property, "IdleHint") == 0)
        return sd_bus_message_append(reply, "b", 0);
    if (strcmp(property, "IdleSinceHint") == 0 ||
        strcmp(property, "IdleSinceHintMonotonic") == 0)
        return sd_bus_message_append(reply, "t", (uint64_t)0);
    if (strcmp(property, "Sessions") == 0) {
        r = sd_bus_message_open_container(reply, 'a', "(so)");
        for (i = 0; r >= 0 && i < dl_manager_session_count(ctx->manager); ++i) {
            const dl_session *s = dl_manager_session_at(ctx->manager, i);
            const char *session_seat = dl_session_seat(s);
            if (!session_seat || strcmp(session_seat, id) != 0) continue;
            if (make_object_path("session", dl_session_id(s), object,
                                sizeof(object)) < 0) return -EINVAL;
            r = sd_bus_message_append(reply, "(so)", dl_session_id(s), object);
        }
        if (r >= 0) r = sd_bus_message_close_container(reply);
        return r;
    }
    return property_unknown(error, property);
}


static int session_from_message(sd_bus_message *m, struct dbus_context *ctx,
                                dl_session **ret_session)
{
    const char *path = sd_bus_message_get_path(m);
    char id[DL_SESSION_ID_MAX];
    dl_session *session;
    if (!path || decode_component(path, DL_LOGIN1_PATH "/session/",
                                  id, sizeof(id)) < 0)
        return -EINVAL;
    session = dl_session_find(ctx->manager, id);
    if (!session || dl_session_get_state(session) == DL_SESSION_CLOSED)
        return -ENOENT;
    *ret_session = session;
    return 0;
}

static int method_session_activate(sd_bus_message *m, void *userdata,
                                   sd_bus_error *error)
{
    return authorize_session_async(m, userdata, "org.freedesktop.login1.chvt",
                                   SESSION_OP_ACTIVATE, 0, error);
}

static int method_session_terminate(sd_bus_message *m, void *userdata,
                                    sd_bus_error *error)
{
    return authorize_session_async(m, userdata, "org.freedesktop.login1.manage",
                                   SESSION_OP_TERMINATE, 0, error);
}

static int method_session_kill(sd_bus_message *m, void *userdata,
                               sd_bus_error *error)
{
    const char *whom = NULL;
    int32_t signo = 0;
    int r = sd_bus_message_read(m, "si", &whom, &signo);
    if (r < 0) return r;
    if (!whom || (strcmp(whom, "leader") != 0 && strcmp(whom, "") != 0 &&
                  strcmp(whom, "all") != 0))
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                                      "Kill target must be 'leader' or 'all'");
    if (signo <= 0 || signo >= NSIG)
        return sd_bus_error_set_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                                      "Invalid signal number");
    if (strcmp(whom, "all") == 0 || strcmp(whom, "") == 0)
        return authorize_session_async(m, userdata,
            "org.freedesktop.login1.manage", SESSION_OP_KILL_ALL, signo, error);
    return authorize_session_async(m, userdata, "org.freedesktop.login1.manage",
                                   SESSION_OP_KILL_LEADER, signo, error);
}

static int method_session_lock(sd_bus_message *m, void *userdata,
                               sd_bus_error *error)
{
    const char *member = sd_bus_message_get_member(m);
    enum session_operation operation;
    if (!member) return -EINVAL;
    operation = strcmp(member, "Unlock") == 0 ?
                SESSION_OP_UNLOCK : SESSION_OP_LOCK;
    return authorize_session_async(m, userdata,
        "org.freedesktop.login1.lock-sessions", operation, 0, error);
}

static const sd_bus_vtable session_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Id", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("User", "(uo)", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Name", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Timestamp", "t", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("TimestampMonotonic", "t", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("VTNr", "u", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Seat", "(so)", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("TTY", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Display", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Remote", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("RemoteHost", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("RemoteUser", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Service", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Leader", "u", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Type", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Class", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Active", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("State", "s", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("CanIdle", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("CanLock", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("LockedHint", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleHint", "b", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHint", "t", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", session_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_METHOD("Activate", "", "", method_session_activate, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Terminate", "", "", method_session_terminate, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Kill", "si", "", method_session_kill, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Lock", "", "", method_session_lock, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Unlock", "", "", method_session_lock, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable user_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("UID", "u", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("GID", "u", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Name", "s", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Timestamp", "t", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("TimestampMonotonic", "t", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("RuntimePath", "s", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Service", "s", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Slice", "s", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Display", "(so)", user_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("State", "s", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Sessions", "a(so)", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleHint", "b", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHint", "t", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Linger", "b", user_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable seat_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Id", "s", seat_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("ActiveSession", "(so)", seat_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("CanTTY", "b", seat_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("CanGraphical", "b", seat_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Sessions", "a(so)", seat_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleHint", "b", seat_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHint", "t", seat_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", seat_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END
};


static int fallback_object_find(sd_bus *bus, const char *path,
                                const char *interface, void *userdata,
                                void **ret_found, sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    char id[DL_METADATA_MAX];
    int r = 0;
    (void)bus;
    (void)error;
    if (strcmp(interface, "org.freedesktop.login1.Session") == 0) {
        r = decode_component(path, DL_LOGIN1_PATH "/session/", id, sizeof(id));
        if (r >= 0 && dl_session_find(ctx->manager, id) != NULL &&
            dl_session_get_state(dl_session_find(ctx->manager, id)) != DL_SESSION_CLOSED) {
            *ret_found = userdata;
            return 1;
        }
    } else if (strcmp(interface, "org.freedesktop.login1.User") == 0) {
        const char *uid_text;
        char *end = NULL;
        unsigned long uid;
        if (strncmp(path, DL_LOGIN1_PATH "/user/_",
                    strlen(DL_LOGIN1_PATH "/user/_")) == 0) {
            uid_text = path + strlen(DL_LOGIN1_PATH "/user/_");
            if (*uid_text == '\0' || strchr(uid_text, '/') != NULL)
                return 0;
            errno = 0;
            uid = strtoul(uid_text, &end, 10);
            if (!errno && end != uid_text && *end == '\0' && uid <= UINT32_MAX &&
                dl_user_find(ctx->manager, (uint32_t)uid) != NULL) {
                *ret_found = userdata;
                return 1;
            }
        }
    } else if (strcmp(interface, "org.freedesktop.login1.Seat") == 0) {
        r = decode_component(path, DL_LOGIN1_PATH "/seat/", id, sizeof(id));
        if (r >= 0 && dl_seat_find(ctx->manager, id) != NULL) {
            *ret_found = userdata;
            return 1;
        }
    }
    return r < 0 ? r : 0;
}

static bool inhibitor_value_has_token(const char *value, const char *token,
                                      size_t token_len)
{
    const char *p = value;
    while (p && *p) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == token_len && memcmp(p, token, len) == 0) return true;
        if (!end) break;
        p = end + 1;
    }
    return false;
}

static int manager_property(sd_bus *bus, const char *path,
                            const char *interface, const char *property,
                            sd_bus_message *reply, void *userdata,
                            sd_bus_error *error)
{
    struct dbus_context *ctx = userdata;
    struct inhibitor_record *record;
    char value[4096];
    size_t used = 0;
    uint64_t count = 0;
    bool delay;
    (void)bus;
    (void)interface;

    if (!path || strcmp(path, DL_LOGIN1_PATH) != 0)
        return property_unknown(error, property);
    inhibitors_reap(ctx);
    if (strcmp(property, "NCurrentInhibitors") == 0) {
        for (record = ctx->inhibitors; record; record = record->next) ++count;
        return sd_bus_message_append(reply, "t", count);
    }
    if (strcmp(property, "InhibitDelayMaxUSec") == 0)
        return sd_bus_message_append(reply, "t", (uint64_t)0);
    if (strcmp(property, "BlockInhibited") != 0 &&
        strcmp(property, "DelayInhibited") != 0)
        return property_unknown(error, property);

    delay = strcmp(property, "DelayInhibited") == 0;
    value[0] = '\0';
    for (record = ctx->inhibitors; record; record = record->next) {
        const char *p = record->what;
        if ((strcmp(record->mode, "delay") == 0) != delay) continue;
        while (p && *p) {
            const char *end = strchr(p, ':');
            size_t len = end ? (size_t)(end - p) : strlen(p);
            bool duplicate;
            if (len == 0) { p = end ? end + 1 : NULL; continue; }
            duplicate = inhibitor_value_has_token(value, p, len);
            if (!duplicate) {
                if (used) {
                    if (used + 1 >= sizeof(value)) return -ENOBUFS;
                    value[used++] = ':';
                }
                if (len >= sizeof(value) - used) return -ENOBUFS;
                memcpy(value + used, p, len);
                used += len;
                value[used] = '\0';
            }
            if (!end) break;
            p = end + 1;
        }
    }
    return sd_bus_message_append(reply, "s", value);
}

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("BlockInhibited", "s", manager_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("DelayInhibited", "s", manager_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("NCurrentInhibitors", "t", manager_property, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("InhibitDelayMaxUSec", "t", manager_property, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_METHOD("GetSession", "s", "o", method_get_session, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetSessionByPID", "u", "o", method_get_session_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetUser", "u", "o", method_get_user, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetUserByPID", "u", "o", method_get_user_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetSeat", "s", "o", method_get_seat, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Inhibit", "ssss", "h", method_inhibit, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListInhibitors", "", "a(ssssuu)", method_list_inhibitors, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSessions", "", "a(susso)", method_list_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListUsers", "", "a(uso)", method_list_users, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSeats", "", "a(so)", method_list_seats, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SetUserLinger", "ubb", "", method_set_user_linger, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("SessionNew", "so", 0),
    SD_BUS_SIGNAL("SessionRemoved", "so", 0),
    SD_BUS_SIGNAL("UserNew", "uo", 0),
    SD_BUS_SIGNAL("UserRemoved", "uo", 0),
    SD_BUS_SIGNAL("SeatNew", "so", 0),
    SD_BUS_SIGNAL("SeatRemoved", "so", 0),
    SD_BUS_VTABLE_END
};

#define DL_TERMINATION_STATE_PARENT "/var/lib/dinit-logind"
#define DL_TERMINATION_STATE_PATH "/var/lib/dinit-logind/terminations"

struct termination_recovery_context {
    struct dbus_context *dbus;
    dl_linux_cgroup_v2 *parent;
    char boot_id[DL_TERMINATION_BOOT_ID_MAX];
};

static int termination_recover_record(const dl_termination_record *record,
                                      void *userdata)
{
    struct termination_recovery_context *recovery = userdata;
    struct dbus_context *ctx = recovery->dbus;
    dl_linux_cgroup_v2_session cgroup = {-1, -1, {0}};
    struct termination_payload *payload;
    struct timespec deadline;
    bool same_boot = strcmp(record->boot_id, recovery->boot_id) == 0;
    int r;

    if (dl_termination_queue_contains(&ctx->terminations, record->session_id))
        return 0;
    r = dl_linux_cgroup_v2_session_open_recovery(
        recovery->parent, record->cgroup_name,
        record->parent_dev, record->parent_ino,
        record->cgroup_dev, record->cgroup_ino, &cgroup);
    if (r == -ENOENT) {
        /* The exact recorded cgroup is gone; no process can be targeted. */
        return dl_termination_store_remove(&ctx->termination_store,
                                           record->session_id);
    }
    if (r < 0) {
        fprintf(stderr,
            "dinit-logind: refusing termination recovery for %s: cgroup identity check failed (%d)\n",
            record->session_id, r);
        return 0; /* Preserve the record for an administrator/retry. */
    }
    if (!same_boot) {
        /* CLOCK_MONOTONIC is boot-relative. Never replay an old deadline. */
        dl_linux_cgroup_v2_session_release(&cgroup);
        fprintf(stderr,
            "dinit-logind: preserving stale-boot termination record for %s; not replaying it\n",
            record->session_id);
        return 0;
    }
    deadline.tv_sec = (time_t)record->deadline_sec;
    deadline.tv_nsec = (long)record->deadline_nsec;
    if (deadline.tv_sec < 0 || (uint64_t)deadline.tv_sec != record->deadline_sec) {
        dl_linux_cgroup_v2_session_release(&cgroup);
        return -ERANGE;
    }
    if (strnlen(record->session_id, sizeof(payload->session_id)) >=
        sizeof(payload->session_id)) {
        dl_linux_cgroup_v2_session_release(&cgroup);
        return -EBADMSG;
    }
    payload = calloc(1, sizeof(*payload));
    if (!payload) {
        dl_linux_cgroup_v2_session_release(&cgroup);
        return -ENOMEM;
    }
    payload->cgroup = cgroup;
    payload->store = &ctx->termination_store;
    memcpy(payload->session_id, record->session_id,
           strlen(record->session_id) + 1);
    cgroup.fd = -1;
    cgroup.parent_fd = -1;
    cgroup.name[0] = '\0';
    r = dl_termination_queue_schedule_at(
        &ctx->terminations, record->session_id, &deadline, payload,
        termination_cgroup_kill, termination_cgroup_release);
    if (r < 0) {
        termination_cgroup_release(payload);
        if (r == -EALREADY) return 0;
        return r;
    }
    fprintf(stderr,
        "dinit-logind: restored pending termination for session %s\n",
        record->session_id);
    return 0;
}

static int ensure_linger_directory(void)
{
    int parent = -1, child = -1, r = 0;
    struct stat st;

    parent = open(DL_TERMINATION_STATE_PARENT,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -errno;
    if (fstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0022) != 0) {
        close(parent);
        return -EPERM;
    }
    if (mkdirat(parent, "linger", 0755) != 0 && errno != EEXIST) {
        r = -errno;
        close(parent);
        return r;
    }
    child = openat(parent, "linger",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0) {
        r = -errno;
        close(parent);
        return r;
    }
    if (fstat(child, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0022) != 0)
        r = -EPERM;
    close(child);
    close(parent);
    return r;
}

static int termination_recover_all(struct dbus_context *ctx)
{
    struct termination_recovery_context recovery;
    dl_linux_cgroup_v2 parent = {-1, {0}};
    struct stat st;
    int r;

    if (!ctx || !ctx->termination_store_open) return -EINVAL;
    if (mkdir(DL_TERMINATION_STATE_PARENT, 0755) != 0 && errno != EEXIST)
        return -errno;
    if (lstat(DL_TERMINATION_STATE_PARENT, &st) != 0) return -errno;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0)
        return -EPERM;
    r = dl_linux_cgroup_v2_open_current(&parent);
    if (r < 0) {
        fprintf(stderr,
            "dinit-logind: cannot inspect delegated cgroup for termination recovery (%d); records retained\n",
            r);
        return 0;
    }
    memset(&recovery, 0, sizeof(recovery));
    recovery.dbus = ctx;
    recovery.parent = &parent;
    r = dl_termination_store_read_boot_id(recovery.boot_id);
    if (r == 0)
        r = dl_termination_store_foreach(&ctx->termination_store,
                                         termination_recover_record,
                                         &recovery);
    if (r < 0)
        fprintf(stderr,
            "dinit-logind: termination journal scan/recovery stopped safely (%d)\n",
            r);
    dl_linux_cgroup_v2_close(&parent);
    return 0; /* Invalid records must not prevent the login service starting. */
}

static int dl_dbus_open_internal(dl_dbus *dbus, dl_manager *manager,
                                 const char *address)
{
    struct dbus_context *ctx;
    int r;
    if (!dbus || !manager) return -EINVAL;
    memset(dbus, 0, sizeof(*dbus));
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -ENOMEM;
    ctx->manager = manager;
    ctx->runtime_paths.runtime_base = "/run/user";
    ctx->runtime_paths.linger_directory = "/var/lib/dinit-logind/linger";
    ctx->runtime_paths.trusted_owner = 0;
    ctx->terminate_timeout_sec = 90;
    dl_termination_queue_init(&ctx->terminations, 90);
    dbus->manager = manager;
    dbus->event_cursor = dl_manager_event_generation(manager);
    if (address) {
        r = sd_bus_new(&dbus->bus);
        if (r >= 0) r = sd_bus_set_address(dbus->bus, address);
        if (r >= 0) r = sd_bus_set_bus_client(dbus->bus, 1);
        if (r >= 0) r = sd_bus_start(dbus->bus);
    } else {
        r = sd_bus_open_system(&dbus->bus);
    }
    if (r < 0) {
        sd_bus_unref(dbus->bus);
        dbus->bus = NULL;
        free(ctx);
        return r;
    }
    r = sd_bus_add_object_vtable(dbus->bus, &dbus->manager_slot,
                                 DL_LOGIN1_PATH, DL_LOGIN1_IFACE,
                                 manager_vtable, ctx);
    if (r < 0) { sd_bus_unref(dbus->bus); dbus->bus = NULL; free(ctx); return r; }
    r = sd_bus_add_fallback_vtable(dbus->bus, &dbus->session_slot,
                                   DL_LOGIN1_PATH "/session", "org.freedesktop.login1.Session",
                                   session_vtable, fallback_object_find, ctx);
    if (r < 0) {
        sd_bus_slot_unref(dbus->seat_slot);
        sd_bus_slot_unref(dbus->user_slot);
        sd_bus_slot_unref(dbus->session_slot);
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus); dbus->bus = NULL; free(ctx); return r;
    }
    r = sd_bus_add_fallback_vtable(dbus->bus, &dbus->user_slot,
                                   DL_LOGIN1_PATH "/user", "org.freedesktop.login1.User",
                                   user_vtable, fallback_object_find, ctx);
    if (r < 0) {
        sd_bus_slot_unref(dbus->session_slot);
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus); dbus->bus = NULL; free(ctx); return r;
    }
    r = sd_bus_add_fallback_vtable(dbus->bus, &dbus->seat_slot,
                                   DL_LOGIN1_PATH "/seat", "org.freedesktop.login1.Seat",
                                   seat_vtable, fallback_object_find, ctx);
    if (r < 0) {
        sd_bus_slot_unref(dbus->user_slot);
        sd_bus_slot_unref(dbus->session_slot);
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus); dbus->bus = NULL; free(ctx); return r;
    }
    ctx->bus = dbus->bus;
    if (mkdir(DL_TERMINATION_STATE_PARENT, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr,
            "dinit-logind: durable termination journal unavailable (%s); Terminate disabled\n",
            strerror(errno));
    } else {
        struct stat state_parent;
        if (lstat(DL_TERMINATION_STATE_PARENT, &state_parent) != 0 ||
            !S_ISDIR(state_parent.st_mode) || state_parent.st_uid != 0 ||
            (state_parent.st_mode & 0022) != 0) {
            fprintf(stderr,
                "dinit-logind: unsafe termination state directory; Terminate disabled\n");
        } else {
            r = dl_termination_store_open(&ctx->termination_store,
                                          DL_TERMINATION_STATE_PATH, 1);
            if (r < 0) {
                fprintf(stderr,
                    "dinit-logind: cannot open termination journal (%d); Terminate disabled\n",
                    r);
            } else {
                ctx->termination_store_open = true;
                (void)termination_recover_all(ctx);
            }
        }
    }
    if (geteuid() == 0) {
        r = ensure_linger_directory();
        if (r < 0)
            fprintf(stderr, "dinit-logind: persistent linger storage unavailable or unsafe (%s)\n",
                    strerror(-r));
    }
    r = sd_bus_request_name(dbus->bus, DL_LOGIN1_NAME, 0);
    if (r < 0) {
        sd_bus_slot_unref(dbus->seat_slot);
        sd_bus_slot_unref(dbus->user_slot);
        sd_bus_slot_unref(dbus->session_slot);
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus);
        dbus->bus = NULL;
        if (ctx->termination_store_open)
            dl_termination_store_close(&ctx->termination_store);
        free(ctx);
        return r;
    }
    return 0;
}


static int emit_manager_object_signal(dl_dbus *dbus, const char *member,
                                       const char *signature, const char *id,
                                       uint32_t uid, const char *kind)
{
    char path[256];
    if (strcmp(kind, "user") == 0) {
        if (path_for_user(uid, path, sizeof(path)) < 0) return -EINVAL;
        return sd_bus_emit_signal(dbus->bus, DL_LOGIN1_PATH, DL_LOGIN1_IFACE,
                                  member, signature, uid, path);
    }
    if (make_object_path(kind, id, path, sizeof(path)) < 0) return -EINVAL;
    return sd_bus_emit_signal(dbus->bus, DL_LOGIN1_PATH, DL_LOGIN1_IFACE,
                              member, signature, id, path);
}

static int emit_user_state_changed(dl_dbus *dbus, uint32_t uid)
{
    char path[256];
    if (path_for_user(uid, path, sizeof(path)) < 0) return -EINVAL;
    return sd_bus_emit_properties_changed(dbus->bus, path,
        "org.freedesktop.login1.User", "State", NULL);
}

static int emit_session_state_changed(dl_dbus *dbus, const dl_event *event)
{
    char path[256];
    int r = 0;
    if (event->new_state != DL_SESSION_CLOSED) {
        if (make_object_path("session", event->session_id, path, sizeof(path)) < 0)
            return -EINVAL;
        r = sd_bus_emit_properties_changed(dbus->bus, path,
            "org.freedesktop.login1.Session", "Active", "State", NULL);
        if (r < 0) return r;
    }
    return emit_user_state_changed(dbus, event->uid);
}

static int emit_seat_active_changed(dl_dbus *dbus, const dl_event *event)
{
    char path[256];
    if (make_object_path("seat", event->seat_id, path, sizeof(path)) < 0)
        return -EINVAL;
    return sd_bus_emit_properties_changed(dbus->bus, path,
        "org.freedesktop.login1.Seat", "ActiveSession", NULL);
}

static int emit_user_linger_changed(dl_dbus *dbus, uint32_t uid)
{
    char path[256];
    if (path_for_user(uid, path, sizeof(path)) < 0) return -EINVAL;
    return sd_bus_emit_properties_changed(dbus->bus, path,
        "org.freedesktop.login1.User", "Linger", "State", NULL);
}

static int emit_resnapshot_properties(dl_dbus *dbus, dl_manager *manager)
{
    size_t i;
    int r;
    for (i = 0; i < dl_manager_session_count(manager); ++i) {
        const dl_session *session = dl_manager_session_at(manager, i);
        dl_event event = {0};
        event.uid = dl_session_uid(session);
        event.new_state = dl_session_get_state(session);
        (void)snprintf(event.session_id, sizeof(event.session_id), "%s",
                       dl_session_id(session));
        r = emit_session_state_changed(dbus, &event);
        if (r < 0) return r;
    }
    for (i = 0; i < dl_manager_user_count(manager); ++i) {
        const dl_user *user = dl_manager_user_at(manager, i);
        char path[256];
        if (path_for_user(dl_user_uid(user), path, sizeof(path)) < 0)
            return -EINVAL;
        r = sd_bus_emit_properties_changed(dbus->bus, path,
            "org.freedesktop.login1.User", "State", "Linger", NULL);
        if (r < 0) return r;
    }
    for (i = 0; i < dl_manager_seat_count(manager); ++i) {
        const dl_seat *seat = dl_manager_seat_at(manager, i);
        dl_event event = {0};
        (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s",
                       dl_seat_id(seat));
        r = emit_seat_active_changed(dbus, &event);
        if (r < 0) return r;
    }
    return 0;
}

static int process_core_events(dl_dbus *dbus)
{
    dl_event event;
    dl_result result;
    int r;
    for (;;) {
        result = dl_manager_next_event(dbus->manager, dbus->event_cursor, &event);
        if (result == DL_ERR_NOT_FOUND) return 0;
        if (result == DL_ERR_STATE && event.type == DL_EVENT_OVERFLOW) {
            r = emit_resnapshot_properties(dbus, dbus->manager);
            if (r >= 0) dbus->event_cursor = event.generation;
            return r;
        }
        if (result != DL_OK) return -EIO;
        switch (event.type) {
        case DL_EVENT_USER_ADDED: {
            bool linger = false;
            /* Rehydrate the persistent policy when the user first appears
             * after a daemon restart. Missing/unsafe storage is fail-closed. */
            if (dl_runtime_get_linger(
                    &(dl_runtime_paths){ .runtime_base = "/run/user",
                        .linger_directory = "/var/lib/dinit-logind/linger",
                        .trusted_owner = 0 }, event.uid, &linger) == DL_OK && linger)
                (void)dl_user_set_linger(dbus->manager, event.uid, true);
            r = emit_manager_object_signal(dbus, "UserNew", "uo", NULL,
                                           event.uid, "user");
            break;
        }
        case DL_EVENT_SEAT_ADDED:
            r = emit_manager_object_signal(dbus, "SeatNew", "so",
                                           event.seat_id, 0, "seat");
            break;
        case DL_EVENT_SESSION_ADDED:
            r = emit_manager_object_signal(dbus, "SessionNew", "so",
                                           event.session_id, 0, "session");
            if (r >= 0) r = emit_user_state_changed(dbus, event.uid);
            break;
        case DL_EVENT_SESSION_REMOVED:
            r = emit_manager_object_signal(dbus, "SessionRemoved", "so",
                                           event.session_id, 0, "session");
            if (r >= 0) r = emit_user_state_changed(dbus, event.uid);
            break;
        case DL_EVENT_SESSION_STATE_CHANGED:
            r = emit_session_state_changed(dbus, &event);
            break;
        case DL_EVENT_SEAT_ACTIVE_SESSION_CHANGED:
            r = emit_seat_active_changed(dbus, &event);
            break;
        case DL_EVENT_USER_LINGER_CHANGED:
            r = emit_user_linger_changed(dbus, event.uid);
            break;
        case DL_EVENT_NONE:
        case DL_EVENT_OVERFLOW:
        default:
            r = 0;
            break;
        }
        if (r < 0) return r;
        dbus->event_cursor = event.generation;
    }
}

int dl_dbus_open(dl_dbus *dbus, dl_manager *manager)
{
    return dl_dbus_open_internal(dbus, manager, NULL);
}

int dl_dbus_open_address(dl_dbus *dbus, dl_manager *manager,
                         const char *address)
{
    if (!address || address[0] == '\0') return -EINVAL;
    return dl_dbus_open_internal(dbus, manager, address);
}

int dl_dbus_get_fd(const dl_dbus *dbus)
{
    if (!dbus || !dbus->bus) return -EINVAL;
    return sd_bus_get_fd(dbus->bus);
}

int dl_dbus_get_events(const dl_dbus *dbus)
{
    if (!dbus || !dbus->bus) return -EINVAL;
    return sd_bus_get_events(dbus->bus);
}

int dl_dbus_set_terminate_timeout(dl_dbus *dbus,
                                  uint32_t timeout_sec)
{
    struct dbus_context *ctx;
    if (!dbus || !dbus->manager_slot || timeout_sec < 1 ||
        timeout_sec > 86400)
        return -EINVAL;
    ctx = sd_bus_slot_get_userdata(dbus->manager_slot);
    if (!ctx) return -EINVAL;
    ctx->terminate_timeout_sec = timeout_sec;
    ctx->terminations.timeout_sec = timeout_sec;
    return 0;
}

int dl_dbus_process(dl_dbus *dbus)
{
    struct dbus_context *ctx;
    int r;
    if (!dbus || !dbus->bus) return -EINVAL;
    do {
        r = sd_bus_process(dbus->bus, NULL);
    } while (r > 0);
    if (r < 0) return r;
    ctx = dbus->manager_slot ?
          sd_bus_slot_get_userdata(dbus->manager_slot) : NULL;
    inhibitors_reap(ctx);
    r = process_core_events(dbus);
    if (r < 0) return r;
    return ctx ? dl_termination_queue_process(&ctx->terminations) : 0;
}

void dl_dbus_close(dl_dbus *dbus)
{
    struct dbus_context *ctx = NULL;
    if (!dbus) return;
    if (dbus->manager_slot) ctx = sd_bus_slot_get_userdata(dbus->manager_slot);
    if (ctx) dl_termination_queue_finish(&ctx->terminations);
    pending_authorizations_cancel(ctx);
    inhibitors_finish(ctx);
    if (ctx && ctx->termination_store_open) {
        dl_termination_store_close(&ctx->termination_store);
        ctx->termination_store_open = false;
    }
    sd_bus_slot_unref(dbus->seat_slot);
    sd_bus_slot_unref(dbus->user_slot);
    sd_bus_slot_unref(dbus->session_slot);
    sd_bus_slot_unref(dbus->manager_slot);
    sd_bus_unref(dbus->bus);
    free(ctx);
    memset(dbus, 0, sizeof(*dbus));
}
