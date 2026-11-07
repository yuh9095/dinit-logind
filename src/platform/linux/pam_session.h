/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_PAM_SESSION_H
#define DINIT_LOGIND_LINUX_PAM_SESSION_H

#include <stdbool.h>
#include "../../core/core.h"
#include "peer_credentials.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dl_pam_session dl_pam_session;

/*
 * Bind a connected AF_UNIX stream socket to a core Session.
 * spec->uid and metadata must come from the trusted PAM ingress; the leader
 * identity is always replaced with the kernel-authenticated socket peer.
 * The socket peer UID is deliberately not equated with the login UID:
 * privileged PAM stacks commonly serve another account.
 */
dl_result dl_pam_session_begin(dl_manager *manager, int socket_fd,
                               const dl_session_spec *spec,
                               dl_pam_session **out_session);

/* Non-blocking disconnect check for the daemon's owner event loop. */
dl_result dl_pam_session_peer_closed(dl_pam_session *session, bool *closed);

/* Idempotently close the core Session and release the retained socket. */
dl_result dl_pam_session_close(dl_pam_session *session);
void dl_pam_session_destroy(dl_pam_session *session);

const char *dl_pam_session_id(const dl_pam_session *session);
const dl_linux_peer_credentials *dl_pam_session_peer(
    const dl_pam_session *session);

#ifdef __cplusplus
}
#endif
#endif
