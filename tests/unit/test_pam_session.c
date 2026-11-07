/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "pam_session.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int sockets[2] = {-1, -1};
    dl_manager *manager = dl_manager_new();
    dl_pam_session *session = NULL;
    dl_session_spec spec;
    const dl_linux_peer_credentials *peer;
    const dl_user *user;
    bool closed = false;
    const char *id;

    assert(manager != NULL);
    memset(&spec, 0, sizeof(spec));
    spec.uid = (uint32_t)getuid();
    spec.service = "login";
    spec.type = "tty";
    spec.session_class = "user";
    spec.leader.pid = UINT32_MAX; /* Must be overwritten by SO_PEERCRED. */

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(dl_pam_session_begin(manager, sockets[0], &spec, &session) == DL_OK);
    assert(session != NULL);
    id = dl_pam_session_id(session);
    assert(id != NULL);
    peer = dl_pam_session_peer(session);
    assert(peer != NULL);
    assert(peer->process.pid == (uint32_t)getpid());
    assert(peer->uid == (uint32_t)getuid());
    assert(peer->process.pid_namespace_inode != 0);

    user = dl_user_find(manager, spec.uid);
    assert(user != NULL);
    assert(dl_user_active_session_count(user) == 1);

    assert(dl_pam_session_peer_closed(session, &closed) == DL_OK);
    assert(!closed);

    (void)close(sockets[1]);
    assert(dl_pam_session_peer_closed(session, &closed) == DL_OK);
    assert(closed);
    assert(dl_session_get_state(dl_session_find(manager, id)) == DL_SESSION_CLOSED);
    assert(dl_user_active_session_count(user) == 0);

    assert(dl_pam_session_close(session) == DL_OK);
    assert(dl_pam_session_peer_closed(session, &closed) == DL_OK);
    assert(closed);
    dl_pam_session_destroy(session);
    (void)close(sockets[0]);
    dl_manager_destroy(manager);

    puts("PAM session lifetime tests: ok");
    return 0;
}
