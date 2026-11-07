/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "../../src/dbus/dbus.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static int session_new_count;
static int session_removed_count;
static int properties_changed_count;

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
    pthread_t thread;
    sd_bus *client = NULL;
    sd_bus_slot *new_slot = NULL, *removed_slot = NULL, *changed_slot = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char object_path[256], user_path[256], seat_path[256];
    const char *returned_path = NULL;
    int callback_count = 0, r, result = 1, stage = 0;
    int active = 1;

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
    stage = 2;
    if (open_client(&client, address) < 0) goto finish;

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

    server.dbus = &dbus;
    if (pthread_mutex_init(&server.lock, NULL) != 0) goto finish;
    if (pthread_create(&thread, NULL, server_thread, &server) != 0) {
        pthread_mutex_destroy(&server.lock);
        goto finish;
    }

    spec.uid = (uint32_t)getuid();
    spec.leader.pid = (uint32_t)getpid();
    spec.leader.pid_namespace_inode = 1;
    spec.leader.process_start_time = 1;
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
    pthread_mutex_lock(&server.lock);
    r = dl_session_activate(manager, dl_session_id(session));
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    stage = 14;
    if (pump_until(client, &properties_changed_count, 3) < 0) goto stop_server;
    active = 0;
    r = sd_bus_get_property_trivial(client, LOGIN1_NAME, object_path,
        SESSION_IFACE, "Active", &error, 'b', &active);
    if (r < 0 || active != 1) goto stop_server;

    stage = 15;
    pthread_mutex_lock(&server.lock);
    r = dl_session_close(manager, dl_session_id(session));
    pthread_mutex_unlock(&server.lock);
    if (r != DL_OK) goto stop_server;
    stage = 16;
    if (pump_until(client, &session_removed_count, 1) < 0 || session_removed_count != 1)
        goto stop_server;

    r = sd_bus_call_method(client, LOGIN1_NAME, LOGIN1_PATH, MANAGER_IFACE,
                           "GetSession", &error, &reply, "s", dl_session_id(session));
    if (r >= 0) goto stop_server;

    result = 0;

stop_server:
    if (result != 0)
        fprintf(stderr, "D-Bus integration failed at stage %d (r=%d, error=%s: %s)\n",
                stage, r, error.name ? error.name : "-",
                error.message ? error.message : "-");
    atomic_store(&server.stop, true);
    pthread_join(thread, NULL);
    if (atomic_load(&server.failed)) result = 1;
    pthread_mutex_destroy(&server.lock);

finish:
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_slot_unref(changed_slot);
    sd_bus_slot_unref(removed_slot);
    sd_bus_slot_unref(new_slot);
    sd_bus_unref(client);
    dl_dbus_close(&dbus);
    dl_manager_destroy(manager);
    if (result != 0) fprintf(stderr, "D-Bus integration test failed\n");
    return result;
}
