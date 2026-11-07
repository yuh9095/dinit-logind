/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "runtime_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define DL_RUNTIME_PARENT "/run"
#define DL_RUNTIME_DIRECTORY "dinit-logind"
#define DL_RUNTIME_SOCKET "pam.sock"
#define DL_RUNTIME_SOCKET_PATH DL_RUNTIME_PARENT "/" DL_RUNTIME_DIRECTORY "/" DL_RUNTIME_SOCKET

static int verify_root_directory(int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int prepare_directory(void)
{
    int parent_fd, directory_fd;
    parent_fd = open(DL_RUNTIME_PARENT, O_RDONLY | O_DIRECTORY |
                     O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0) return -1;
    if (verify_root_directory(parent_fd) != 0) {
        (void)close(parent_fd);
        return -1;
    }
    if (mkdirat(parent_fd, DL_RUNTIME_DIRECTORY, 0755) != 0 &&
        errno != EEXIST) {
        (void)close(parent_fd);
        return -1;
    }
    directory_fd = openat(parent_fd, DL_RUNTIME_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    (void)close(parent_fd);
    if (directory_fd < 0) return -1;
    if (verify_root_directory(directory_fd) != 0) {
        (void)close(directory_fd);
        return -1;
    }
    return directory_fd;
}

static int acquire_daemon_lock(int directory_fd)
{
    struct stat st;
    int fd = openat(directory_fd, "daemon.lock",
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || (st.st_mode & 0077) != 0) {
        (void)close(fd);
        errno = EPERM;
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int remove_stale_socket(int directory_fd)
{
    struct sockaddr_un address;
    struct stat before, after;
    int probe, connect_error;

    if (fstatat(directory_fd, DL_RUNTIME_SOCKET, &before,
                AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(before.st_mode) || before.st_uid != 0) {
        errno = EPERM;
        return -1;
    }

    probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (probe < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, DL_RUNTIME_SOCKET_PATH,
           sizeof(DL_RUNTIME_SOCKET_PATH));
    if (connect(probe, (struct sockaddr *)&address, sizeof(address)) == 0) {
        (void)close(probe);
        errno = EADDRINUSE;
        return -1;
    }
    connect_error = errno;
    (void)close(probe);
    if (connect_error != ECONNREFUSED && connect_error != ENOENT) {
        errno = connect_error;
        return -1;
    }

    if (fstatat(directory_fd, DL_RUNTIME_SOCKET, &after,
                AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(after.st_mode) || after.st_uid != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino) {
        errno = EAGAIN;
        return -1;
    }
    return unlinkat(directory_fd, DL_RUNTIME_SOCKET, 0);
}

int dl_runtime_socket_open(dl_runtime_socket *runtime)
{
    struct sockaddr_un address;
    struct stat st;
    mode_t old_mask;
    int fd, directory_fd;

    if (runtime == NULL || geteuid() != 0) { errno = EPERM; return -1; }
    memset(runtime, 0, sizeof(*runtime));
    runtime->fd = -1;
    runtime->directory_fd = -1;
    runtime->lock_fd = -1;

    directory_fd = prepare_directory();
    if (directory_fd < 0) return -1;
    runtime->lock_fd = acquire_daemon_lock(directory_fd);
    if (runtime->lock_fd < 0) {
        (void)close(directory_fd);
        return -1;
    }
    if (remove_stale_socket(directory_fd) != 0) {
        int saved = errno;
        (void)close(runtime->lock_fd);
        runtime->lock_fd = -1;
        (void)close(directory_fd);
        errno = saved;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { (void)close(runtime->lock_fd); runtime->lock_fd = -1; (void)close(directory_fd); return -1; }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (sizeof(DL_RUNTIME_SOCKET_PATH) > sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        goto fail;
    }
    memcpy(address.sun_path, DL_RUNTIME_SOCKET_PATH,
           sizeof(DL_RUNTIME_SOCKET_PATH));

    old_mask = umask(0117);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        (void)umask(old_mask);
        errno = saved;
        goto fail;
    }
    (void)umask(old_mask);

    if (fstatat(directory_fd, DL_RUNTIME_SOCKET, &st,
                AT_SYMLINK_NOFOLLOW) != 0) goto fail_bound;
    if (!S_ISSOCK(st.st_mode) || st.st_uid != 0) {
        errno = EPERM;
        goto fail_bound;
    }
    if (fchmodat(directory_fd, DL_RUNTIME_SOCKET, 0660, 0) != 0)
        goto fail_bound;
    if (listen(fd, 64) != 0) goto fail_bound;

    runtime->fd = fd;
    runtime->directory_fd = directory_fd;
    runtime->socket_device = st.st_dev;
    runtime->socket_inode = st.st_ino;
    runtime->owns_socket = 1;
    return 0;

fail_bound:
    (void)unlinkat(directory_fd, DL_RUNTIME_SOCKET, 0);
fail:
    {
        int saved = errno;
        (void)close(fd);
        (void)close(directory_fd);
        if (runtime->lock_fd >= 0) (void)close(runtime->lock_fd);
        runtime->lock_fd = -1;
        errno = saved;
    }
    return -1;
}

void dl_runtime_socket_close(dl_runtime_socket *runtime)
{
    struct stat st;
    if (runtime == NULL) return;
    if (runtime->fd >= 0) (void)close(runtime->fd);
    if (runtime->owns_socket && runtime->directory_fd >= 0 &&
        fstatat(runtime->directory_fd, DL_RUNTIME_SOCKET, &st,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISSOCK(st.st_mode) && st.st_uid == 0 &&
        st.st_dev == runtime->socket_device &&
        st.st_ino == runtime->socket_inode) {
        (void)unlinkat(runtime->directory_fd, DL_RUNTIME_SOCKET, 0);
    }
    if (runtime->directory_fd >= 0) (void)close(runtime->directory_fd);
    if (runtime->lock_fd >= 0) (void)close(runtime->lock_fd);
    runtime->fd = -1;
    runtime->directory_fd = -1;
    runtime->lock_fd = -1;
    runtime->owns_socket = 0;
}
