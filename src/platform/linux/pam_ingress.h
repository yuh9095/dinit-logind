/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_PAM_INGRESS_H
#define DINIT_LOGIND_LINUX_PAM_INGRESS_H

#include <stdbool.h>
#include <stdint.h>
#include "../../core/core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dl_pam_ingress dl_pam_ingress;

/*
 * Accept one already-listening AF_UNIX stream connection. The kernel peer
 * UID must equal allowed_peer_uid; the target login UID is separately
 * checked against NSS and is intentionally not compared with the peer UID.
 */
dl_result dl_pam_ingress_accept(dl_manager *manager, int listen_fd,
                                uint32_t allowed_peer_uid,
                                dl_pam_ingress **out_ingress);

/*
 * Consume available request bytes without blocking. complete is true once
 * the request has been validated and its Core Session created. Incomplete
 * input returns DL_OK with complete=false; malformed or truncated input
 * returns an error and the caller must destroy the ingress object.
 */
dl_result dl_pam_ingress_step(dl_pam_ingress *ingress, bool *complete);

/* Poll for peer disconnect after successful request processing. */
dl_result dl_pam_ingress_peer_closed(dl_pam_ingress *ingress, bool *closed);
const char *dl_pam_ingress_session_id(const dl_pam_ingress *ingress);
void dl_pam_ingress_destroy(dl_pam_ingress *ingress);

#ifdef __cplusplus
}
#endif
#endif
