/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "pam_ingress.h"
#include "pam_protocol.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int make_connection(int *client_fd)
{
    static const char name[] = "dinit-logind-test";
    struct sockaddr_un address;
    socklen_t length;
    int listener;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path + 1, name, sizeof(name) - 1);
    length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(name) - 1);
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listener >= 0);
    assert(bind(listener, (struct sockaddr *)&address, length) == 0);
    assert(listen(listener, 4) == 0);
    *client_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(*client_fd >= 0);
    assert(connect(*client_fd, (struct sockaddr *)&address, length) == 0);
    return listener;
}

static void fill_request(dl_pam_open_request *r)
{
    memset(r, 0, sizeof(*r));
    r->magic = DL_PAM_PROTOCOL_MAGIC;
    r->version = DL_PAM_PROTOCOL_VERSION;
    r->size = (uint16_t)sizeof(*r);
    r->uid = (uint32_t)getuid();
    memcpy(r->service, "login", 6);
    memcpy(r->tty, "/dev/tty7", 10);
    r->vtnr = 7;
    memcpy(r->type, "tty", 4);
    memcpy(r->session_class, "user", 5);
}

static void send_request(int client, const dl_pam_open_request *request)
{
    assert(write(client, request, sizeof(*request)) == (ssize_t)sizeof(*request));
}

static void test_valid_lifecycle_and_seat(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    dl_pam_open_response response;
    dl_event event;
    bool complete = false, closed = false;
    const dl_user *user;
    const dl_seat *seat;
    const dl_session *session;
    uint64_t cursor = 0;
    bool saw_added = false, saw_removed = false;

    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    send_request(client, &request);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_OK && complete);
    assert(dl_pam_ingress_session_id(ingress) != NULL);
    assert(recv(client, &response, sizeof(response), MSG_WAITALL) ==
           (ssize_t)sizeof(response));
    assert(response.magic == DL_PAM_RESPONSE_MAGIC);
    assert(response.status == 0 && response.session_id[0] != '\0');

    user = dl_user_find(manager, request.uid);
    assert(user != NULL && dl_user_session_count(user) == 1);
    assert(dl_manager_session_count(manager) == 1);
    session = dl_manager_session_at(manager, 0);
    assert(session != NULL);
    assert(strcmp(dl_session_id(session), response.session_id) == 0);
    assert(dl_session_vtnr(session) == 7);
    assert(strcmp(dl_session_seat(session), "seat0") == 0);
    seat = dl_seat_find(manager, "seat0");
    assert(seat != NULL && dl_seat_session_count(seat) == 1);
    assert(dl_seat_active_session_id(seat) == NULL);

    (void)close(client);
    assert(dl_pam_ingress_peer_closed(ingress, &closed) == DL_OK && closed);
    assert(dl_user_session_count(user) == 0);
    assert(dl_manager_session_count(manager) == 0);
    assert(dl_seat_session_count(seat) == 0);

    while (dl_manager_next_event(manager, cursor, &event) == DL_OK) {
        if (event.type == DL_EVENT_SESSION_ADDED &&
            strcmp(event.session_id, response.session_id) == 0)
            saw_added = true;
        if (event.type == DL_EVENT_SESSION_REMOVED &&
            strcmp(event.session_id, response.session_id) == 0)
            saw_removed = true;
        cursor = event.generation;
    }
    assert(saw_added && saw_removed);

    dl_pam_ingress_destroy(ingress);
    (void)close(listener);
    dl_manager_destroy(manager);
}

static void test_remote_session_has_no_local_seat(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    dl_pam_open_response response;
    bool complete = false;
    const dl_session *session;

    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    request.remote = 1;
    memcpy(request.rhost, "remote.example", 15);
    send_request(client, &request);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_OK && complete);
    assert(recv(client, &response, sizeof(response), MSG_WAITALL) ==
           (ssize_t)sizeof(response));
    session = dl_manager_session_at(manager, 0);
    assert(session != NULL && dl_session_is_remote(session));
    assert(dl_session_seat(session) == NULL);
    assert(dl_session_vtnr(session) == 7);
    dl_pam_ingress_destroy(ingress);
    (void)close(client);
    (void)close(listener);
    dl_manager_destroy(manager);
}

static void test_bad_request(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false;
    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    request.magic = 0;
    send_request(client, &request);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_ERR_INVALID);
    assert(!complete);
    dl_pam_ingress_destroy(ingress);
    (void)close(listener); (void)close(client);
    dl_manager_destroy(manager);
}

static void test_peer_uid_policy(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid() + 1,
                                 &ingress) == DL_ERR_INVALID);
    assert(ingress == NULL);
    (void)close(listener); (void)close(client);
    dl_manager_destroy(manager);
}

static void test_truncated_request(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false;
    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    assert(write(client, &request, sizeof(request) / 2) ==
           (ssize_t)(sizeof(request) / 2));
    (void)shutdown(client, SHUT_WR);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_ERR_INVALID);
    dl_pam_ingress_destroy(ingress);
    (void)close(listener); (void)close(client);
    dl_manager_destroy(manager);
}

static void test_vtnr_mismatch_rejected(void)
{
    int listener, client;
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false;
    assert(manager != NULL);
    listener = make_connection(&client);
    assert(dl_pam_ingress_accept(manager, listener, (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    request.vtnr = 8;
    send_request(client, &request);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_ERR_INVALID);
    assert(dl_manager_session_count(manager) == 0);
    dl_pam_ingress_destroy(ingress);
    (void)close(listener); (void)close(client);
    dl_manager_destroy(manager);
}

int main(void)
{
    test_valid_lifecycle_and_seat();
    test_remote_session_has_no_local_seat();
    test_bad_request();
    test_peer_uid_policy();
    test_truncated_request();
    test_vtnr_mismatch_rejected();
    puts("PAM ingress protocol, seat mapping and lifecycle tests: ok");
    return 0;
}
