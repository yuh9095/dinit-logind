/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "config.h"
#include "runtime_socket.h"
#include "../dbus/dbus.h"
#include "../platform/linux/pam_ingress.h"
#include "../platform/linux/cgroup_v2.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DL_DEFAULT_CONFIG "/etc/dinit-logind.conf"
#define DL_MAX_CLIENTS 128u
#define DL_POLL_INTERVAL_MS 100
#define DL_PENDING_TIMEOUT_SECONDS 10

struct client {
    dl_pam_ingress *ingress;
    struct timespec accepted_at;
    struct client *next;
};

static volatile sig_atomic_t stopping;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0) return -1;
    if (sigaction(SIGINT, &action, NULL) != 0) return -1;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) return -1;
    return 0;
}

static void usage(FILE *stream, const char *program)
{
    (void)fprintf(stream,
        "Usage: %s [--config PATH] [--help] [--version]\n"
        "Runs dinit-logind in the foreground under Dinit.\n", program);
}

static int parse_arguments(int argc, char **argv, const char **config_path)
{
    int i;
    *config_path = DL_DEFAULT_CONFIG;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 1;
        }
        if (strcmp(argv[i], "--version") == 0) {
            (void)puts("dinit-logind 0.1.0");
            return 1;
        }
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            *config_path = argv[++i];
            continue;
        }
        usage(stderr, argv[0]);
        return -1;
    }
    return 0;
}

static void remove_client(struct client **head, struct client *client)
{
    struct client **cursor = head;
    while (*cursor != NULL && *cursor != client) cursor = &(*cursor)->next;
    if (*cursor == client) *cursor = client->next;
    dl_pam_ingress_destroy(client->ingress);
    free(client);
}

static void destroy_clients(struct client *clients)
{
    while (clients != NULL) {
        struct client *next = clients->next;
        dl_pam_ingress_destroy(clients->ingress);
        free(clients);
        clients = next;
    }
}

static size_t client_count(const struct client *clients)
{
    size_t count = 0;
    while (clients != NULL) { ++count; clients = clients->next; }
    return count;
}

static bool pending_timed_out(const struct client *client)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return true;
    return now.tv_sec - client->accepted_at.tv_sec >=
           DL_PENDING_TIMEOUT_SECONDS;
}

static int run_event_loop(dl_manager *manager, dl_dbus *dbus, int listener,
                          uint32_t allowed_peer_uid)
{
    struct client *clients = NULL;
    struct pollfd descriptors[2];
    int exit_status = 0;

    while (!stopping) {
        int ready;
        if (dl_dbus_process(dbus) < 0) { exit_status = 1; break; }
        dl_linux_cgroup_v2_registry_reap();
        struct client *client, *next;

        descriptors[0].fd = listener;
        descriptors[0].events = client_count(clients) < DL_MAX_CLIENTS ? POLLIN : 0;
        descriptors[0].revents = 0;
        descriptors[1].fd = dl_dbus_get_fd(dbus);
        descriptors[1].events = (short)dl_dbus_get_events(dbus);
        descriptors[1].revents = 0;
        if (descriptors[1].fd < 0 || descriptors[1].events < 0) {
            exit_status = 1;
            break;
        }
        do {
            ready = poll(descriptors, 2, DL_POLL_INTERVAL_MS);
        } while (ready < 0 && errno == EINTR && !stopping);
        if (ready < 0 && errno == EINTR && stopping) break;
        if (ready < 0) { exit_status = 1; break; }

        if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            exit_status = 1;
            break;
        }
        if ((descriptors[0].revents & POLLIN) != 0 &&
            client_count(clients) < DL_MAX_CLIENTS) {
            struct client *entry = calloc(1, sizeof(*entry));
            if (entry == NULL) { exit_status = 1; break; }
            {
                dl_result accepted = dl_pam_ingress_accept(
                    manager, listener, allowed_peer_uid, &entry->ingress);
                if (accepted == DL_OK) {
                    if (clock_gettime(CLOCK_MONOTONIC, &entry->accepted_at) == 0) {
                        entry->next = clients;
                        clients = entry;
                    } else {
                        dl_pam_ingress_destroy(entry->ingress);
                        free(entry);
                    }
                } else {
                    free(entry);
                }
            }
        }

        for (client = clients; client != NULL; client = next) {
            bool complete = false, closed = false;
            dl_result result;
            next = client->next;

            if (dl_pam_ingress_session_id(client->ingress) == NULL &&
                pending_timed_out(client)) {
                remove_client(&clients, client);
                continue;
            }
            result = dl_pam_ingress_step(client->ingress, &complete);
            if (result != DL_OK) {
                remove_client(&clients, client);
                continue;
            }
            if (dl_pam_ingress_session_id(client->ingress) != NULL) {
                result = dl_pam_ingress_peer_closed(client->ingress, &closed);
                if (result != DL_OK || closed)
                    remove_client(&clients, client);
            }
        }
    }

    destroy_clients(clients);
    return exit_status;
}

int main(int argc, char **argv)
{
    const char *config_path;
    dl_daemon_config config;
    dl_runtime_socket runtime;
    dl_dbus dbus;
    dl_manager *manager;
    int args, result;

    args = parse_arguments(argc, argv, &config_path);
    if (args > 0) return 0;
    if (args < 0) return 2;
    if (geteuid() != 0) {
        (void)fprintf(stderr, "dinit-logind: must run as root\n");
        return 1;
    }

    dl_daemon_config_defaults(&config);
    if (dl_daemon_config_load(config_path, &config) != 0 &&
        errno != ENOENT) {
        (void)fprintf(stderr, "dinit-logind: cannot load %s: %s\n",
                      config_path, strerror(errno));
        return 1;
    }
    if (dl_runtime_socket_open(&runtime) != 0) {
        (void)fprintf(stderr, "dinit-logind: cannot create PAM socket: %s\n",
                      strerror(errno));
        return 1;
    }
    manager = dl_manager_new();
    if (manager == NULL) {
        (void)fprintf(stderr, "dinit-logind: cannot allocate manager\n");
        dl_runtime_socket_close(&runtime);
        return 1;
    }
    if (dl_dbus_open(&dbus, manager) < 0) {
        (void)fprintf(stderr, "dinit-logind: cannot connect to system D-Bus or own org.freedesktop.login1\n");
        dl_manager_destroy(manager);
        dl_runtime_socket_close(&runtime);
        return 1;
    }
    if (dl_dbus_set_terminate_timeout(
            &dbus, config.session_terminate_timeout_sec) != 0) {
        (void)fprintf(stderr, "dinit-logind: invalid session termination timeout\n");
        dl_dbus_close(&dbus);
        dl_manager_destroy(manager);
        dl_runtime_socket_close(&runtime);
        return 1;
    }
    if (install_signal_handlers() != 0) {
        (void)fprintf(stderr, "dinit-logind: cannot install signal handlers: %s\n",
                      strerror(errno));
        dl_dbus_close(&dbus);
        dl_manager_destroy(manager);
        dl_runtime_socket_close(&runtime);
        return 1;
    }

    (void)fprintf(stderr, "dinit-logind: listening on %s/pam.sock\n",
                  "/run/dinit-logind");
    result = run_event_loop(manager, &dbus, runtime.fd, config.allowed_peer_uid);

    dl_dbus_close(&dbus);
    dl_manager_destroy(manager);
    dl_runtime_socket_close(&runtime);
    return result;
}
