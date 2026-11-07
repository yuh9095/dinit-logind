/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "pam_ingress.h"
#include "pam_protocol.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void fill_request(dl_pam_open_request *r)
{
    memset(r, 0, sizeof(*r));
    r->magic = DL_PAM_PROTOCOL_MAGIC;
    r->version = DL_PAM_PROTOCOL_VERSION;
    r->size = (uint16_t)sizeof(*r);
    r->uid = (uint32_t)getuid();
    memcpy(r->service, "login", 6);
    memcpy(r->type, "tty", 4);
    memcpy(r->session_class, "user", 5);
}

static int make_listener(int peer[2])
{
    int listener[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, listener) == 0);
    peer[0] = listener[0];
    peer[1] = listener[1];
    return listener[0];
}

static void test_valid_lifecycle(void)
{
    int pair[2], accepted_pair[2];
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false, closed = false;
    const dl_user *user;
    char id[DL_SESSION_ID_MAX];

    assert(manager != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    assert(dl_pam_ingress_accept(manager, pair[0], (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    assert(write(pair[1], &request, sizeof(request)) == (ssize_t)sizeof(request));
    assert(dl_pam_ingress_step(ingress, &complete) == DL_OK && complete);
    assert(dl_pam_ingress_session_id(ingress) != NULL);
    (void)snprintf(id, sizeof(id), "%s", dl_pam_ingress_session_id(ingress));
    user = dl_user_find(manager, request.uid);
    assert(user != NULL && dl_user_active_session_count(user) == 1);
    (void)close(pair[1]);
    assert(dl_pam_ingress_peer_closed(ingress, &closed) == DL_OK && closed);
    assert(dl_user_active_session_count(user) == 0);
    dl_pam_ingress_destroy(ingress);
    (void)close(pair[0]);
    dl_manager_destroy(manager);
    (void)accepted_pair;
}

static void test_bad_request(void)
{
    int pair[2];
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false;
    assert(manager != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    assert(dl_pam_ingress_accept(manager, pair[0], (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    request.magic = 0;
    assert(write(pair[1], &request, sizeof(request)) == (ssize_t)sizeof(request));
    assert(dl_pam_ingress_step(ingress, &complete) == DL_ERR_INVALID);
    assert(!complete);
    dl_pam_ingress_destroy(ingress);
    (void)close(pair[0]); (void)close(pair[1]);
    dl_manager_destroy(manager);
}

static void test_peer_uid_policy(void)
{
    int pair[2];
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    assert(manager != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    assert(dl_pam_ingress_accept(manager, pair[0], (uint32_t)getuid() + 1,
                                 &ingress) == DL_ERR_INVALID);
    assert(ingress == NULL);
    (void)close(pair[0]); (void)close(pair[1]);
    dl_manager_destroy(manager);
}

static void test_truncated_request(void)
{
    int pair[2];
    dl_manager *manager = dl_manager_new();
    dl_pam_ingress *ingress = NULL;
    dl_pam_open_request request;
    bool complete = false;
    assert(manager != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    assert(dl_pam_ingress_accept(manager, pair[0], (uint32_t)getuid(),
                                 &ingress) == DL_OK);
    fill_request(&request);
    assert(write(pair[1], &request, sizeof(request) / 2) ==
           (ssize_t)(sizeof(request) / 2));
    (void)shutdown(pair[1], SHUT_WR);
    assert(dl_pam_ingress_step(ingress, &complete) == DL_ERR_INVALID);
    dl_pam_ingress_destroy(ingress);
    (void)close(pair[0]); (void)close(pair[1]);
    dl_manager_destroy(manager);
}

int main(void)
{
    test_valid_lifecycle();
    test_bad_request();
    test_peer_uid_policy();
    test_truncated_request();
    puts("PAM ingress protocol and lifecycle tests: ok");
    return 0;
}
