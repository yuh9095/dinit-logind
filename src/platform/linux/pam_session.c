/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "pam_session.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif

struct dl_pam_session {
    dl_manager *manager;
    dl_session *core_session;
    int socket_fd;
    bool closed;
    dl_linux_peer_credentials peer;
};

dl_result dl_pam_session_begin(dl_manager *manager, int socket_fd,
                               const dl_session_spec *spec,
                               dl_pam_session **out_session)
{
    dl_pam_session *session;
    dl_session_spec authenticated_spec;
    dl_result result;

    if (out_session != NULL) *out_session = NULL;
    if (manager == NULL || socket_fd < 0 || spec == NULL ||
        out_session == NULL) return DL_ERR_INVALID;

    session = calloc(1, sizeof(*session));
    if (session == NULL) return DL_ERR_NOMEM;
    session->socket_fd = -1;

    session->socket_fd = fcntl(socket_fd, F_DUPFD_CLOEXEC, 0);
    if (session->socket_fd < 0) {
        free(session);
        return errno == EBADF ? DL_ERR_INVALID : DL_ERR_STATE;
    }

    result = dl_linux_peer_credentials_read(session->socket_fd, &session->peer);
    if (result != DL_OK) {
        (void)close(session->socket_fd);
        free(session);
        return result;
    }

    authenticated_spec = *spec;
    authenticated_spec.leader = session->peer.process;
    result = dl_session_create(manager, &authenticated_spec, &session->core_session);
    if (result != DL_OK) {
        (void)close(session->socket_fd);
        free(session);
        return result;
    }

    session->manager = manager;
    *out_session = session;
    return DL_OK;
}

dl_result dl_pam_session_peer_closed(dl_pam_session *session, bool *closed)
{
    struct pollfd descriptor;
    int result;

    if (closed != NULL) *closed = false;
    if (session == NULL || closed == NULL) return DL_ERR_INVALID;
    if (session->closed) {
        *closed = true;
        return DL_OK;
    }

    descriptor.fd = session->socket_fd;
    descriptor.events = POLLHUP | POLLRDHUP | POLLERR;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);

    if (result < 0) return DL_ERR_STATE;
    if (result == 0) return DL_OK;
    if ((descriptor.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) != 0) {
        *closed = true;
        return dl_pam_session_close(session);
    }
    return DL_OK;
}

dl_result dl_pam_session_close(dl_pam_session *session)
{
    dl_result result = DL_OK;

    if (session == NULL) return DL_ERR_INVALID;
    if (session->closed) return DL_OK;

    session->closed = true;
    if (session->core_session != NULL) {
        result = dl_session_close(session->manager,
                                  dl_session_id(session->core_session));
    }
    if (session->socket_fd >= 0) {
        (void)close(session->socket_fd);
        session->socket_fd = -1;
    }
    return result;
}

void dl_pam_session_destroy(dl_pam_session *session)
{
    if (session == NULL) return;
    (void)dl_pam_session_close(session);
    free(session);
}

const char *dl_pam_session_id(const dl_pam_session *session)
{
    return session == NULL ? NULL : dl_session_id(session->core_session);
}

const dl_linux_peer_credentials *dl_pam_session_peer(
    const dl_pam_session *session)
{
    return session == NULL ? NULL : &session->peer;
}
