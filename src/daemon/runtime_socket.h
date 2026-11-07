/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_RUNTIME_SOCKET_H
#define DINIT_LOGIND_RUNTIME_SOCKET_H

#include <sys/stat.h>

typedef struct {
    int fd;
    int directory_fd;
    int lock_fd;
    dev_t socket_device;
    ino_t socket_inode;
    int owns_socket;
} dl_runtime_socket;

int dl_runtime_socket_open(dl_runtime_socket *runtime);
void dl_runtime_socket_close(dl_runtime_socket *runtime);

#endif
