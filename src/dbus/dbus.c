/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "dbus.h"
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DL_LOGIN1_NAME "org.freedesktop.login1"
#define DL_LOGIN1_PATH "/org/freedesktop/login1"
#define DL_LOGIN1_IFACE "org.freedesktop.login1.Manager"

struct dbus_context {
    dl_manager *manager;
};

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

static int method_get_user(sd_bus_message *m, void *userdata,
                           sd_bus_error *ret_error)
{
    struct dbus_context *ctx = userdata;
    uint32_t uid;
    char id[32], path[256];
    if (sd_bus_message_read(m, "u", &uid) < 0) return -EINVAL;
    if (!dl_user_find(ctx->manager, uid))
        return sd_bus_error_setf(ret_error,
            "org.freedesktop.login1.NoSuchUser", "No user with UID %u", uid);
    (void)snprintf(id, sizeof(id), "%u", (unsigned int)uid);
    if (make_object_path("user", id, path, sizeof(path)) < 0)
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
        char username[256], id[32], path[256];
        (void)snprintf(id, sizeof(id), "%u", (unsigned int)uid);
        if (uid_to_name(uid, username, sizeof(username)) < 0 ||
            make_object_path("user", id, path, sizeof(path)) < 0) {
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
            dl_user_linger_enabled(user) ? "lingering" : "offline";
        return sd_bus_message_append(reply, "s", state);
    }
    if (strcmp(property, "Display") == 0)
        return sd_bus_message_append(reply, "(so)", "", "/");
    if (strcmp(property, "Linger") == 0)
        return sd_bus_message_append(reply, "b", dl_user_linger_enabled(user));
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

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetSession", "s", "o", method_get_session, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetUser", "u", "o", method_get_user, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetSeat", "s", "o", method_get_seat, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSessions", "", "a(susso)", method_list_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListUsers", "", "a(uso)", method_list_users, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSeats", "", "a(so)", method_list_seats, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("SessionNew", "so", 0),
    SD_BUS_SIGNAL("SessionRemoved", "so", 0),
    SD_BUS_SIGNAL("UserNew", "uo", 0),
    SD_BUS_SIGNAL("UserRemoved", "uo", 0),
    SD_BUS_SIGNAL("SeatNew", "so", 0),
    SD_BUS_SIGNAL("SeatRemoved", "so", 0),
    SD_BUS_VTABLE_END
};

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
    r = sd_bus_request_name(dbus->bus, DL_LOGIN1_NAME, 0);
    if (r < 0) {
        sd_bus_slot_unref(dbus->seat_slot);
        sd_bus_slot_unref(dbus->user_slot);
        sd_bus_slot_unref(dbus->session_slot);
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus);
        dbus->bus = NULL;
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
        case DL_EVENT_USER_ADDED:
            r = emit_manager_object_signal(dbus, "UserNew", "uo", NULL,
                                           event.uid, "user");
            break;
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

int dl_dbus_process(dl_dbus *dbus)
{
    int r;
    if (!dbus || !dbus->bus) return -EINVAL;
    do {
        r = sd_bus_process(dbus->bus, NULL);
    } while (r > 0);
    if (r < 0) return r;
    return process_core_events(dbus);
}

void dl_dbus_close(dl_dbus *dbus)
{
    struct dbus_context *ctx = NULL;
    if (!dbus) return;
    if (dbus->manager_slot) ctx = sd_bus_slot_get_userdata(dbus->manager_slot);
    sd_bus_slot_unref(dbus->seat_slot);
    sd_bus_slot_unref(dbus->user_slot);
    sd_bus_slot_unref(dbus->session_slot);
    sd_bus_slot_unref(dbus->manager_slot);
    sd_bus_unref(dbus->bus);
    free(ctx);
    memset(dbus, 0, sizeof(*dbus));
}
