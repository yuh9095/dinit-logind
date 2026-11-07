/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "peer_credentials.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    int sockets[2] = {-1, -1};
    dl_linux_peer_credentials credentials;
    dl_linux_peer_credentials invalid;

    memset(&credentials, 0, sizeof(credentials));
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(dl_linux_peer_credentials_read(sockets[0], &credentials) == DL_OK);
    assert(credentials.process.pid == (uint32_t)getpid());
    assert(credentials.process.pid_namespace_inode != 0);
    assert(credentials.process.process_start_time != 0);
    assert(credentials.uid == (uint32_t)getuid());
    assert(credentials.gid == (uint32_t)getgid());

    memset(&invalid, 0xA5, sizeof(invalid));
    assert(dl_linux_peer_credentials_read(-1, &invalid) == DL_ERR_INVALID);
    assert(invalid.process.pid == 0);
    assert(invalid.uid == 0);
    assert(invalid.gid == 0);

    memset(&invalid, 0xA5, sizeof(invalid));
    assert(dl_linux_peer_credentials_read(STDIN_FILENO, &invalid) == DL_ERR_INVALID);
    assert(invalid.process.pid == 0);
    assert(invalid.uid == 0);
    assert(invalid.gid == 0);

    assert(dl_linux_peer_credentials_read(sockets[0], NULL) == DL_ERR_INVALID);
    (void)close(sockets[0]);
    (void)close(sockets[1]);

    puts("peer credential tests: ok");
    return 0;
}
