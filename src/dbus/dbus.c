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
            (*p >= '0' && *p <= '9') || *p == '_') {
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
    if (!dl_session_find(ctx->manager, id))
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

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetSession", "s", "o", method_get_session, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetUser", "u", "o", method_get_user, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("GetSeat", "s", "o", method_get_seat, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSessions", "", "a(susso)", method_list_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListUsers", "", "a(uso)", method_list_users, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("ListSeats", "", "a(so)", method_list_seats, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

int dl_dbus_open(dl_dbus *dbus, dl_manager *manager)
{
    struct dbus_context *ctx;
    int r;
    if (!dbus || !manager) return -EINVAL;
    memset(dbus, 0, sizeof(*dbus));
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -ENOMEM;
    ctx->manager = manager;
    r = sd_bus_open_system(&dbus->bus);
    if (r < 0) { free(ctx); return r; }
    r = sd_bus_add_object_vtable(dbus->bus, &dbus->manager_slot,
                                 DL_LOGIN1_PATH, DL_LOGIN1_IFACE,
                                 manager_vtable, ctx);
    if (r < 0) { sd_bus_unref(dbus->bus); dbus->bus = NULL; free(ctx); return r; }
    r = sd_bus_request_name(dbus->bus, DL_LOGIN1_NAME, 0);
    if (r < 0) {
        sd_bus_slot_unref(dbus->manager_slot);
        sd_bus_unref(dbus->bus);
        dbus->bus = NULL;
        free(ctx);
        return r;
    }
    return 0;
}

int dl_dbus_process(dl_dbus *dbus)
{
    int r;
    if (!dbus || !dbus->bus) return -EINVAL;
    do {
        r = sd_bus_process(dbus->bus, NULL);
    } while (r > 0);
    return r < 0 ? r : 0;
}

void dl_dbus_close(dl_dbus *dbus)
{
    struct dbus_context *ctx = NULL;
    if (!dbus) return;
    if (dbus->manager_slot) {
        ctx = sd_bus_slot_get_userdata(dbus->manager_slot);
        sd_bus_slot_unref(dbus->manager_slot);
    }
    sd_bus_unref(dbus->bus);
    free(ctx);
    memset(dbus, 0, sizeof(*dbus));
}
