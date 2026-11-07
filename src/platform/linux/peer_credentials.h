/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_PEER_CREDENTIALS_H
#define DINIT_LOGIND_LINUX_PEER_CREDENTIALS_H

#include <stdint.h>
#include "../../core/core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t uid;
    uint32_t gid;
    dl_process_identity process;
} dl_linux_peer_credentials;

/*
 * Read kernel-supplied credentials from a connected AF_UNIX socket and bind
 * the peer PID to a procfs process identity. The caller must still apply
 * authorization policy; peer credentials are authentication metadata, not
 * permission to perform privileged operations.
 */
dl_result dl_linux_peer_credentials_read(int socket_fd,
                                         dl_linux_peer_credentials *credentials);

#ifdef __cplusplus
}
#endif
#endif
