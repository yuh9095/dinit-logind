/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "../../src/dbus/dbus.h"
#include "../../src/platform/linux/process_identity.h"
#include "../../src/platform/linux/cgroup_v2.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LOGIN1_NAME "org.freedesktop.login1"
#define LOGIN1_PATH "/org/freedesktop/login1"
#define MANAGER_IFACE "org.freedesktop.login1.Manager"
#define SESSION_IFACE "org.freedesktop.login1.Session"

struct server_state {
    dl_dbus *dbus;
    pthread_mutex_t lock;
    atomic_bool stop;
    atomic_bool failed;
};

struct authority_state {
    sd_bus *bus;
    atomic_bool stop;
    atomic_bool failed;
};

static int session_new_count;
static int session_removed_count;
static int properties_changed_count;
static int lock_signal_count;
static int unlock_signal_count;

static atomic_int fake_polkit_allow = 1;
static atomic_int fake_polkit_challenge = 0;
static atomic_int fake_polkit_suppress_reply = 0;
static atomic_uint fake_polkit_calls;

static int fake_polkit_check(sd_bus_message *message, void *userdata,
                             sd_bus_error *error)
{
    sd_bus_message *reply = NULL;
    int r;
    (void)userdata;
    (void)error;
    atomic_fetch_add(&fake_polkit_calls, 1);
    r = sd_bus_message_new_method_return(message, &reply);
    if (r >= 0) r = sd_bus_message_append(reply, "bb",
        atomic_load(&fake_polkit_allow), atomic_load(&fake_polkit_challenge));
    if (r >= 0) r = sd_bus_message_open_container(reply, 'a', "{ss}");
    if (r >= 0) r = sd_bus_message_close_container(reply);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(message), reply, NULL);
    sd_bus_message_unref(reply);
    return r;
}

static const sd_bus_vtable fake_polkit_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CheckAuthorization", "(sa{sv})sa{ss}us", "bba{ss}",
                  fake_polkit_check, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static int signal_counter(sd_bus_message *message, void *userdata,
                          sd_bus_error *error)
{
    const char *member = sd_bus_message_get_member(message);
    int *counter = userdata;
    (void)error;
    if (member && strcmp(member, "SessionNew") == 0) ++session_new_count;
    else if (member && strcmp(member, "SessionRemoved") == 0) ++session_removed_count;
    else if (member && strcmp(member, "PropertiesChanged") == 0)
        ++properties_changed_count;
    else if (member && strcmp(member, "Lock") == 0)
        ++lock_signal_count;
    else if (member && strcmp(member, "Unlock") == 0)
        ++unlock_signal_count;
    ++*counter;
    return 0;
}

static void *server_thread(void *userdata)
{
    struct server_state *state = userdata;
    struct pollfd pfd;
    while (!atomic_load(&state->stop)) {
        int r;
        pthread_mutex_lock(&state->lock);
        r = dl_dbus_process(state->dbus);
        pthread_mutex_unlock(&state->lock);
        if (r < 0) {
            atomic_store(&state->failed, true);
            break;
        }
        pfd.fd = dl_dbus_get_fd(state->dbus);
        pfd.events = (short)dl_dbus_get_events(state->dbus);
        pfd.revents = 0;
        if (pfd.fd < 0 || pfd.events < 0) {
            state->failed = 1;
            break;
        }
        (void)poll(&pfd, 1, 10);
    }
    return NULL;
}

static void *authority_thread_main(void *userdata)
{
    struct authority_state *state = userdata;
    struct pollfd pfd;
    while (!atomic_load(&state->stop)) {
        int r = sd_bus_process(state->bus, NULL);
        if (r < 0) {
            atomic_store(&state->failed, true);
            break;
        }
        if (r > 0) continue;
        pfd.fd = sd_bus_get_fd(state->bus);
        pfd.events = (short)sd_bus_get_events(state->bus);
        pfd.revents = 0;
        if (pfd.fd < 0 || pfd.events < 0) {
            atomic_store(&state->failed, true);
            break;
        }
        (void)poll(&pfd, 1, 10);
    }
    return NULL;
}

static int pump_until(sd_bus *bus, volatile int *value, int expected)
{
    unsigned int i;
    for (i = 0; i < 200; ++i) {
        int r;
        do {
            r = sd_bus_process(bus, NULL);
        } while (r > 0);
        if (r < 0) return r;
        if (*value >= expected) return 0;
        r = sd_bus_wait(bus, 10000);
        if (r < 0) return r;
    }
    return -ETIMEDOUT;
}

static int open_client(sd_bus **ret, const char *address)
{
    int r = sd_bus_new(ret);
    if (r >= 0) r = sd_bus_set_address(*ret, address);
    if (r >= 0) r = sd_bus_set_bus_client(*ret, 1);
    if (r >= 0) r = sd_bus_start(*ret);
    if (r < 0) {
        sd_bus_unref(*ret);
        *ret = NULL;
    }
    return r;
}

int main(void)
{
    const char *address = getenv("DBUS_SESSION_BUS_ADDRESS");
    dl_manager *manager = NULL;
    dl_dbus dbus = {0};
    dl_session_spec spec = {0};
    dl_session *session = NULL;
    struct server_state server = {0};
    struct authority_state authority = {0};
    pthread_t thread, authority_thread;
    int authority_started = 0;
    sd_bus *client = NULL;
    sd_bus_slot *new_slot = NULL, *removed_slot = NULL, *changed_slot = NULL;
    sd_bus_slot *lock_slot = NULL, *unlock_slot = NULL;
    sd_bus_slot *polkit_slot = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char object_path[256], user_path[256], seat_path[256];
    const char *returned_path = NULL;
    int callback_count = 0, r, result = 1, stage = 0;
    int server_started = 0;
    int active = 1;
    pid_t child_pid = -1;
    int child_status;
    dl_session_spec child_spec;
    dl_session *child_session = NULL;
    char child_path[256];
    char *session_state = NULL;

    if (!address) {
        fprintf(stderr, "DBUS_SESSION_BUS_ADDRESS is not set\n");
        return 1;
    }
    stage = 1;
    manager = dl_manager_new();
    if (!manager) goto finish;
    r = dl_dbus_open_address(&dbus, manager, address);
    if (r < 0) {
        fprintf(stderr, "cannot open test bus: %s\n", strerror(-r));
        goto finish;
    }
    /* Keep the real cgroup termination integration test short. */
    if (dl_dbus_set_terminate_timeout(&dbus, 1) < 0) goto finish;
    stage = 2;
    if (open_client(&client, address) < 0) goto finish;
    /* The authority uses its own connection so it can answer while the test
     * client is synchronously waiting for login1 method replies. */
    if (open_client(&authority.bus, address) < 0) goto finish;
    r = sd_bus_add_object_vtable(authority.bus, &polkit_slot,
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", fake_polkit_vtable, NULL);
    if (r < 0) goto finish;
    r = sd_bus_request_name(authority.bus, "org.freedesktop.PolicyKit1", 0);
    if (r < 0) goto finish;
    if (pthread_create(&authority_thread, NULL, authority_thread_main,
                       &authority) != 0) goto finish;
    authority_started = 1;

    stage = 3;
    r = sd_bus_add_match(client, &new_slot,
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='SessionNew'",
        signal_counter, &callback_count);
    if (r < 0) goto finish;
    r = sd_bus_add_match(client, &removed_slot,
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='SessionRemoved'",
        signal_counter, &callback_count);
    if (r < 0) goto finish;
    r = sd_bus_add_match(client, &changed_slot,
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
        signal_counter, &callback_count);
    if (r < 0) goto finish;
    r = sd_bus_add_match(client, &lock_slot,
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Lock'",
        signal_counter, &callback_count);
    if (r < 0) goto finish;
    r = sd_bus_add_match(client, &unlock_slot,
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Unlock'",
        signal_counter, &callback_count);
    if (r < 0) goto finish;

    server.dbus = &dbus;
    if (pthread_mutex_init(&server.lock, NULL) != 0) goto finish;
    if (pthread_create(&thread, NULL, server_thread, &server) != 0) {
        pthread_mutex_destroy(&server.lock);
        goto finish;
    }
    server_started = 1;

    spec.uid = (uint32_t)getuid();
    if (dl_linux_process_identity_read((uint32_t)getpid(), &spec.leader) != DL_OK)
        goto stop_server;
    spec.seat = "seat0";
    spec.tty = "tty-test";
    spec.service = "test-login";
    spec.type = "tty";
    spec.session_class = "user";

    stage = 4;
    pthread_mutex_lock(&server.lock);
    r = dl_session_create(manager, &spec, &session);
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    stage = 5;
    if (pump_until(client, &session_new_count, 1) < 0 || session_new_count != 1)
        goto stop_server;

    stage = 6;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSession", &error, &reply, "s", dl_session_id(session));
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
        goto stop_server;
    (void)snprintf(object_path, sizeof(object_path), "%s", returned_path);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 7;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSessionByPID", &error, &reply, "u",
                           (uint32_t)getpid());
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0 ||
        strcmp(returned_path, object_path) != 0)
        goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 8;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSessionByPID", &error, &reply, "u", 0);
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0 ||
        strcmp(returned_path, object_path) != 0)
        goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;


    stage = 7;
    r = sd_bus_get_property_trivial(client, LOGIN1_NAME, object_path,
        SESSION_IFACE, "Active", &error, 'b', &active);
    if (r < 0 || active != 0) goto stop_server;

    stage = 8;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path,
        "org.freedesktop.DBus.Properties", "GetAll", &error, &reply,
        "s", SESSION_IFACE);
    if (r < 0 || !reply) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 9;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetUser", &error, &reply, "u", spec.uid);
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
        goto stop_server;
    (void)snprintf(user_path, sizeof(user_path), "%s", returned_path);
    if (strncmp(user_path, LOGIN1_PATH "/user/_", strlen(LOGIN1_PATH "/user/_")) != 0)
        goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 10;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetUserByPID", &error, &reply, "u",
                           (uint32_t)getpid());
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0 ||
        strcmp(returned_path, user_path) != 0)
        goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 11;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSessionByPID", &error, &reply, "u", UINT32_MAX);
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.login1.NoSessionForPID"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 12;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetUserByPID", &error, &reply, "u", UINT32_MAX);
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.login1.NoUserForPID"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 10;
    r = sd_bus_call_method(client, LOGIN1_NAME, user_path,
        "org.freedesktop.DBus.Properties", "GetAll", &error, &reply,
        "s", "org.freedesktop.login1.User");
    if (r < 0 || !reply) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    stage = 11;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSeat", &error, &reply, "s", "seat0");
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
        goto stop_server;
    (void)snprintf(seat_path, sizeof(seat_path), "%s", returned_path);
    sd_bus_message_unref(reply);
    reply = NULL;
    stage = 12;
    r = sd_bus_call_method(client, LOGIN1_NAME, seat_path,
        "org.freedesktop.DBus.Properties", "GetAll", &error, &reply,
        "s", "org.freedesktop.login1.Seat");
    if (r < 0 || !reply) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 13;
    atomic_store(&fake_polkit_allow, 0);
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Activate", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.AccessDenied"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;
    atomic_store(&fake_polkit_challenge, 1);
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Activate", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.AccessDenied"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;
    atomic_store(&fake_polkit_challenge, 0);
    atomic_store(&fake_polkit_suppress_reply, 1);
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Activate", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.AccessDenied"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;
    atomic_store(&fake_polkit_suppress_reply, 0);
    atomic_store(&fake_polkit_allow, 1);
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Activate", &error, &reply, "");
    if (r < 0) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    stage = 14;
    if (pump_until(client, &properties_changed_count, 3) < 0) goto stop_server;
    active = 0;
    r = sd_bus_get_property_trivial(client, LOGIN1_NAME, object_path,
        SESSION_IFACE, "Active", &error, 'b', &active);
    if (r < 0 || active != 1) goto stop_server;


    stage = 15;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Lock", &error, &reply, "");
    if (r < 0) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    if (pump_until(client, &lock_signal_count, 1) < 0 || lock_signal_count != 1)
        goto stop_server;

    stage = 16;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Unlock", &error, &reply, "");
    if (r < 0) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    if (pump_until(client, &unlock_signal_count, 1) < 0 || unlock_signal_count != 1)
        goto stop_server;

    /* Terminate must never degrade to signaling only the Leader.
     * This synthetic session has no daemon-owned cgroup, so fail closed. */
    stage = 169;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Terminate", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.NotSupported"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 17;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Kill", &error, &reply, "si", "all", SIGTERM);
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.NotSupported"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    /* SIGKILL for the whole session must also fail closed when this test
     * session has no dinit-logind-owned cgroup. */
    stage = 171;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Kill", &error, &reply, "si", "all", SIGKILL);
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.NotSupported"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 18;
    child_pid = fork();
    if (child_pid < 0) goto stop_server;
    if (child_pid == 0) {
        for (;;) pause();
    }
    memset(&child_spec, 0, sizeof(child_spec));
    child_spec.uid = (uint32_t)getuid();
    if (dl_linux_process_identity_read((uint32_t)child_pid, &child_spec.leader) != DL_OK)
        goto stop_server;
    child_spec.service = "test-kill";
    child_spec.type = "tty";
    child_spec.session_class = "user";
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetUserByPID", &error, &reply, "u",
                           (uint32_t)child_pid);
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0 ||
        strcmp(returned_path, user_path) != 0)
        goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    pthread_mutex_lock(&server.lock);
    r = dl_session_create(manager, &child_spec, &child_session);
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSession", &error, &reply, "s", dl_session_id(child_session));
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
        goto stop_server;
    (void)snprintf(child_path, sizeof(child_path), "%s", returned_path);
    sd_bus_message_unref(reply);
    reply = NULL;
    r = sd_bus_call_method(client, LOGIN1_NAME, child_path, SESSION_IFACE,
                           "Kill", &error, &reply, "si", "leader", SIGTERM);
    if (r < 0) goto stop_server;
    sd_bus_message_unref(reply);
    reply = NULL;
    if (waitpid(child_pid, &child_status, 0) != child_pid ||
        !WIFSIGNALED(child_status) || WTERMSIG(child_status) != SIGTERM)
        goto stop_server;
    child_pid = -1;
    pthread_mutex_lock(&server.lock);
    r = dl_session_close(manager, dl_session_id(child_session));
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;

    stage = 19;
    child_pid = fork();
    if (child_pid < 0) goto stop_server;
    if (child_pid == 0) {
        for (;;) pause();
    }
    memset(&child_spec, 0, sizeof(child_spec));
    child_spec.uid = (uint32_t)getuid();
    if (dl_linux_process_identity_read((uint32_t)child_pid, &child_spec.leader) != DL_OK)
        goto stop_server;
    child_spec.service = "test-terminate";
    child_spec.type = "tty";
    child_spec.session_class = "user";
    pthread_mutex_lock(&server.lock);
    r = dl_session_create(manager, &child_spec, &child_session);
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSession", &error, &reply, "s", dl_session_id(child_session));
    if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
        goto stop_server;
    (void)snprintf(child_path, sizeof(child_path), "%s", returned_path);
    sd_bus_message_unref(reply);
    reply = NULL;
    /* Synthetic sessions created outside the PAM ingress have no
     * daemon-owned cgroup. Terminate must fail closed rather than silently
     * degrading to signaling only the Leader. */
    r = sd_bus_call_method(client, LOGIN1_NAME, child_path, SESSION_IFACE,
                           "Terminate", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.NotSupported"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;
    if (kill(child_pid, 0) != 0) goto stop_server;
    if (kill(child_pid, SIGKILL) != 0 ||
        waitpid(child_pid, &child_status, 0) != child_pid ||
        !WIFSIGNALED(child_status) || WTERMSIG(child_status) != SIGKILL)
        goto stop_server;
    child_pid = -1;
    pthread_mutex_lock(&server.lock);
    r = dl_session_close(manager, dl_session_id(child_session));
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;

    /*
     * Positive asynchronous Terminate coverage. This only runs when the
     * host delegates a writable cgroup-v2 subtree with cgroup.kill.
     */
    {
        dl_linux_cgroup_v2 parent = {-1, {0}};
        dl_linux_cgroup_v2_session cgroup_session = {-1, -1, {0}};
        struct timespec deadline, pause_time = {0, 10000000L};
        int cr;

        stage = 191;
        child_pid = fork();
        if (child_pid < 0) goto stop_server;
        if (child_pid == 0) {
            (void)signal(SIGTERM, SIG_IGN);
            (void)signal(SIGHUP, SIG_IGN);
            for (;;) pause();
        }
        memset(&child_spec, 0, sizeof(child_spec));
        child_spec.uid = (uint32_t)getuid();
        if (dl_linux_process_identity_read((uint32_t)child_pid,
                                           &child_spec.leader) != DL_OK)
            goto stop_server;
        child_spec.service = "test-terminate-async";
        child_spec.type = "tty";
        child_spec.session_class = "user";
        pthread_mutex_lock(&server.lock);
        r = dl_session_create(manager, &child_spec, &child_session);
        pthread_mutex_unlock(&server.lock);
        if (r != DL_OK) goto stop_server;

        cr = dl_linux_cgroup_v2_open_current(&parent);
        if (cr == 0)
            cr = dl_linux_cgroup_v2_session_create(
                &parent, dl_session_id(child_session),
                &child_spec.leader, &cgroup_session);
        if (cr == 0)
            cr = dl_linux_cgroup_v2_session_kill_all_available(&cgroup_session);
        if (cr == 0) {
            r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH,
                MANAGER_IFACE, "GetSession", &error, &reply, "s",
                dl_session_id(child_session));
            if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
                goto stop_server;
            (void)snprintf(child_path, sizeof(child_path), "%s", returned_path);
            sd_bus_message_unref(reply);
            reply = NULL;

            r = sd_bus_call_method(client, LOGIN1_NAME, child_path,
                SESSION_IFACE, "Terminate", &error, &reply, "");
            if (r < 0) goto stop_server;
            sd_bus_message_unref(reply);
            reply = NULL;

            /* The accepted stop transition is externally visible before
             * PAM teardown removes the Session object. */
            r = sd_bus_get_property_string(client, LOGIN1_NAME, child_path,
                SESSION_IFACE, "State", &error, &session_state);
            if (r < 0 || !session_state ||
                strcmp(session_state, "closing") != 0)
                goto stop_server;
            free(session_state);
            session_state = NULL;

            /* Repeating Terminate while the first grace-period operation is
             * pending is idempotent: it must not enqueue a second cgroup kill
             * or reject the already accepted operation. */
            r = sd_bus_call_method(client, LOGIN1_NAME, child_path,
                SESSION_IFACE, "Terminate", &error, &reply, "");
            if (r < 0) goto stop_server;
            sd_bus_message_unref(reply);
            reply = NULL;

            /* The pending operation must survive core Session teardown. */
            pthread_mutex_lock(&server.lock);
            r = dl_session_close(manager, dl_session_id(child_session));
            pthread_mutex_unlock(&server.lock);
            if (r != DL_OK) goto stop_server;
            child_session = NULL;

            if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
                goto stop_server;
            deadline.tv_sec += 5;
            for (;;) {
                pid_t waited = waitpid(child_pid, &child_status, WNOHANG);
                if (waited == child_pid) break;
                if (waited < 0 && errno != EINTR) goto stop_server;
                {
                    struct timespec now;
                    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
                        goto stop_server;
                    if (now.tv_sec > deadline.tv_sec ||
                        (now.tv_sec == deadline.tv_sec &&
                         now.tv_nsec >= deadline.tv_nsec))
                        goto stop_server;
                }
                (void)nanosleep(&pause_time, NULL);
            }
            if (!WIFSIGNALED(child_status) || WTERMSIG(child_status) != SIGKILL)
                goto stop_server;
            child_pid = -1;

            /* Once the Core Session is closed, its D-Bus object must no
             * longer be callable. Idempotence applies only while it exists. */
            r = sd_bus_call_method(client, LOGIN1_NAME, child_path,
                SESSION_IFACE, "Terminate", &error, &reply, "");
            if (r >= 0 || !sd_bus_error_has_name(&error,
                    "org.freedesktop.DBus.Error.UnknownObject"))
                goto stop_server;
            sd_bus_error_free(&error);
            sd_bus_message_unref(reply);
            reply = NULL;
        } else {
            fprintf(stderr,
                "Skipping positive Terminate integration: writable delegated "
                "cgroup.kill unavailable (%d)\n", cr);
            (void)kill(child_pid, SIGKILL);
            (void)waitpid(child_pid, &child_status, 0);
            child_pid = -1;
            pthread_mutex_lock(&server.lock);
            r = dl_session_close(manager, dl_session_id(child_session));
            pthread_mutex_unlock(&server.lock);
            if (r != DL_OK) goto stop_server;
            child_session = NULL;
        }
        if (cgroup_session.fd >= 0) {
            if (dl_linux_cgroup_v2_session_close(&cgroup_session) != 0)
                dl_linux_cgroup_v2_session_release(&cgroup_session);
        }
        dl_linux_cgroup_v2_close(&parent);
    }

    /* A vanished authority must fail closed rather than falling back to
     * session-owner or root checks. */
    atomic_store(&authority.stop, true);
    pthread_join(authority_thread, NULL);
    authority_started = 0;
    (void)sd_bus_release_name(authority.bus, "org.freedesktop.PolicyKit1");
    stage = 19;
    r = sd_bus_call_method(client, LOGIN1_NAME, object_path, SESSION_IFACE,
                           "Lock", &error, &reply, "");
    if (r >= 0 || !sd_bus_error_has_name(&error,
            "org.freedesktop.DBus.Error.AccessDenied"))
        goto stop_server;
    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    reply = NULL;

    stage = 20;
    pthread_mutex_lock(&server.lock);
    r = dl_session_close(manager, dl_session_id(session));
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    stage = 16;
    if (pump_until(client, &session_removed_count, 3) < 0 || session_removed_count != 3)
        goto stop_server;

    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSession", &error, &reply, "s", dl_session_id(session));
    if (r >= 0) goto stop_server;

    /*
     * D-Bus daemon shutdown must synchronously attempt pending session
     * SIGKILLs. The scheduler unit test covers callback semantics; this
     * exercises the real D-Bus close path with a daemon-owned cgroup.
     */
    {
        dl_linux_cgroup_v2 parent = {-1, {0}};
        dl_linux_cgroup_v2_session cgroup_session = {-1, -1, {0}};
        int cr = -1;
        int shutdown_test_supported = 0;

        stage = 21;
        child_pid = fork();
        if (child_pid < 0) goto stop_server;
        if (child_pid == 0) {
            (void)signal(SIGTERM, SIG_IGN);
            (void)signal(SIGHUP, SIG_IGN);
            for (;;) pause();
        }
        memset(&child_spec, 0, sizeof(child_spec));
        child_spec.uid = (uint32_t)getuid();
        if (dl_linux_process_identity_read((uint32_t)child_pid,
                                           &child_spec.leader) != DL_OK)
            goto stop_server;
        child_spec.service = "test-terminate-shutdown";
        child_spec.type = "tty";
        child_spec.session_class = "user";
        pthread_mutex_lock(&server.lock);
        r = dl_session_create(manager, &child_spec, &child_session);
        pthread_mutex_unlock(&server.lock);
        if (r != DL_OK) goto stop_server;

        cr = dl_linux_cgroup_v2_open_current(&parent);
        if (cr == 0)
            cr = dl_linux_cgroup_v2_session_create(
                &parent, dl_session_id(child_session),
                &child_spec.leader, &cgroup_session);
        if (cr == 0)
            cr = dl_linux_cgroup_v2_session_kill_all_available(&cgroup_session);
        if (cr == 0) {
            r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH,
                MANAGER_IFACE, "GetSession", &error, &reply, "s",
                dl_session_id(child_session));
            if (r < 0 || sd_bus_message_read(reply, "o", &returned_path) < 0)
                goto stop_server;
            (void)snprintf(child_path, sizeof(child_path), "%s", returned_path);
            sd_bus_message_unref(reply);
            reply = NULL;

            r = sd_bus_call_method(client, LOGIN1_NAME, child_path,
                SESSION_IFACE, "Terminate", &error, &reply, "");
            if (r < 0) goto stop_server;
            sd_bus_message_unref(reply);
            reply = NULL;

            pthread_mutex_lock(&server.lock);
            r = dl_session_close(manager, dl_session_id(child_session));
            pthread_mutex_unlock(&server.lock);
            if (r != DL_OK) goto stop_server;
            child_session = NULL;
            shutdown_test_supported = 1;
        } else {
            fprintf(stderr,
                "Skipping D-Bus shutdown Terminate integration: delegated "
                "cgroup.kill unavailable (%d)\n", cr);
            (void)kill(child_pid, SIGKILL);
            (void)waitpid(child_pid, &child_status, 0);
            child_pid = -1;
            pthread_mutex_lock(&server.lock);
            r = dl_session_close(manager, dl_session_id(child_session));
            pthread_mutex_unlock(&server.lock);
            if (r != DL_OK) goto stop_server;
            child_session = NULL;
        }

        if (shutdown_test_supported) {
            /* Stop the event loop before close: finish() must not rely on a
             * future tick and must kill immediately, before the grace period. */
            atomic_store(&server.stop, true);
            pthread_join(thread, NULL);
            server_started = 0;
            if (atomic_load(&server.failed)) goto stop_server;
            dl_dbus_close(&dbus);

            /* Bound the wait: if shutdown kill fails, report a test failure
             * instead of hanging CI; stop_server will reap the child. */
            {
                struct timespec deadline, pause_time = {0, 10000000L};
                if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
                    goto stop_server;
                deadline.tv_sec += 5;
                for (;;) {
                    pid_t waited = waitpid(child_pid, &child_status, WNOHANG);
                    if (waited == child_pid) break;
                    if (waited < 0 && errno != EINTR) goto stop_server;
                    {
                        struct timespec now;
                        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
                            goto stop_server;
                        if (now.tv_sec > deadline.tv_sec ||
                            (now.tv_sec == deadline.tv_sec &&
                             now.tv_nsec >= deadline.tv_nsec))
                            goto stop_server;
                    }
                    (void)nanosleep(&pause_time, NULL);
                }
            }
            if (!WIFSIGNALED(child_status) || WTERMSIG(child_status) != SIGKILL)
                goto stop_server;
            child_pid = -1;
        }

        if (cgroup_session.fd >= 0) {
            if (dl_linux_cgroup_v2_session_close(&cgroup_session) != 0)
                dl_linux_cgroup_v2_session_release(&cgroup_session);
        }
        dl_linux_cgroup_v2_close(&parent);
    }

    result = 0;

stop_server:
    if (child_pid > 0) {
        (void)kill(child_pid, SIGKILL);
        (void)waitpid(child_pid, NULL, 0);
    }
    if (result != 0)
        fprintf(stderr, "D-Bus integration failed at stage %d (r=%d, error=%s: %s)\n",
                stage, r, error.name ? error.name : "-",
                error.message ? error.message : "-");
    if (server_started) {
        atomic_store(&server.stop, true);
        pthread_join(thread, NULL);
        server_started = 0;
    }
    if (atomic_load(&server.failed)) result = 1;
    pthread_mutex_destroy(&server.lock);

finish:
    if (authority_started) {
        atomic_store(&authority.stop, true);
        pthread_join(authority_thread, NULL);
        if (atomic_load(&authority.failed)) result = 1;
    }
    sd_bus_slot_unref(polkit_slot);
    sd_bus_unref(authority.bus);
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_slot_unref(changed_slot);
    sd_bus_slot_unref(lock_slot);
    sd_bus_slot_unref(unlock_slot);
    sd_bus_slot_unref(removed_slot);
    sd_bus_slot_unref(new_slot);
    sd_bus_unref(client);
    dl_dbus_close(&dbus);
    dl_manager_destroy(manager);
    if (result != 0) fprintf(stderr, "D-Bus integration test failed\n");
    return result;
}
