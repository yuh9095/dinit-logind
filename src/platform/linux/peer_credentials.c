/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "peer_credentials.h"

#include "process_identity.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

dl_result dl_linux_peer_credentials_read(
    int socket_fd, dl_linux_peer_credentials *credentials)
{
    struct ucred peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    dl_linux_peer_credentials result;
    dl_result status;

    if (credentials != NULL) memset(credentials, 0, sizeof(*credentials));
    if (socket_fd < 0 || credentials == NULL) return DL_ERR_INVALID;

    memset(&peer, 0, sizeof(peer));
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED,
                   &peer, &peer_length) != 0) {
        return (errno == EBADF || errno == ENOTSOCK ||
                errno == ENOPROTOOPT || errno == EOPNOTSUPP)
                   ? DL_ERR_INVALID : DL_ERR_STATE;
    }
    if (peer_length != (socklen_t)sizeof(peer) || peer.pid <= 0 ||
        (uintmax_t)peer.uid > UINT32_MAX ||
        (uintmax_t)peer.gid > UINT32_MAX) {
        return DL_ERR_STATE;
    }

    memset(&result, 0, sizeof(result));
    status = dl_linux_process_identity_read((uint32_t)peer.pid,
                                            &result.process);
    if (status != DL_OK) return status;
    if (result.process.pid != (uint32_t)peer.pid) return DL_ERR_STATE;

    result.uid = (uint32_t)peer.uid;
    result.gid = (uint32_t)peer.gid;
    *credentials = result;
    return DL_OK;
}
