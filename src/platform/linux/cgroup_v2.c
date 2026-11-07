/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "cgroup_v2.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define DL_CGROUP_PROC_FILE "/proc/self/cgroup"
#define DL_CGROUP_MOUNT "/sys/fs/cgroup"
#define DL_CGROUP_TEXT_MAX 16384

static bool valid_cgroup_path(const char *path)
{
    const char *cursor;
    if (path == NULL || path[0] != '/' || path[1] == '\0') return false;
    cursor = path + 1;
    while (*cursor != '\0') {
        const char *start = cursor;
        size_t length;
        while (*cursor != '\0' && *cursor != '/') {
            unsigned char ch = (unsigned char)*cursor;
            if (!(ch >= 'a' && ch <= 'z') &&
                !(ch >= 'A' && ch <= 'Z') &&
                !(ch >= '0' && ch <= '9') && ch != '_' && ch != '-' &&
                ch != '.') return false;
            ++cursor;
        }
        length = (size_t)(cursor - start);
        if (length == 0 || (length == 1 && start[0] == '.') ||
            (length == 2 && start[0] == '.' && start[1] == '.'))
            return false;
        if (*cursor == '/') {
            ++cursor;
            if (*cursor == '\0') return false;
        }
    }
    return true;
}

int dl_linux_cgroup_v2_parse_self_cgroup(const char *contents,
                                         char *path, size_t path_size)
{
    const char *line;
    bool found = false;
    size_t length;
    if (path != NULL && path_size != 0) path[0] = '\0';
    if (contents == NULL || path == NULL || path_size == 0) return -EINVAL;

    line = contents;
    while (*line != '\0') {
        const char *end = strchr(line, '\n');
        const char *first, *second, *entry_path;
        size_t line_length;
        if (end == NULL) end = line + strlen(line);
        line_length = (size_t)(end - line);
        first = memchr(line, ':', line_length);
        second = first == NULL ? NULL :
                 memchr(first + 1, ':', (size_t)(end - first - 1));
        if (first == NULL || second == NULL) { path[0] = '\0'; return -EINVAL; }
        if (first - line == 1 && line[0] == '0' && second == first + 1) {
            if (found) { path[0] = '\0'; return -EINVAL; }
            entry_path = second + 1;
            length = (size_t)(end - entry_path);
            if (length == 0 || length >= path_size) { path[0] = '\0'; return -ENAMETOOLONG; }
            memcpy(path, entry_path, length);
            path[length] = '\0';
            if (!valid_cgroup_path(path)) {
                path[0] = '\0';
                return -EINVAL;
            }
            found = true;
        }
        line = *end == '\0' ? end : end + 1;
    }
    return found ? 0 : -ENOTSUP;
}

static int verify_cgroup2_fd(int fd)
{
    struct statfs fs;
    if (fd < 0) return -EBADF;
    if (fstatfs(fd, &fs) != 0) return -errno;
    return (unsigned long)fs.f_type == (unsigned long)CGROUP2_SUPER_MAGIC
               ? 0 : -ENODEV;
}

static int read_self_cgroup(char *buffer, size_t capacity)
{
    int fd;
    size_t used = 0;
    fd = open(DL_CGROUP_PROC_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    while (used + 1 < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used - 1);
        if (count < 0) {
            if (errno == EINTR) continue;
            {
                int saved = errno;
                (void)close(fd);
                return -saved;
            }
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used + 1 == capacity) {
        (void)close(fd);
        return -EOVERFLOW;
    }
    (void)close(fd);
    buffer[used] = '\0';
    return 0;
}

int dl_linux_cgroup_v2_open_current(dl_linux_cgroup_v2 *cgroup)
{
    char contents[DL_CGROUP_TEXT_MAX];
    int root_fd = -1, current_fd = -1, result;
    char path[sizeof(cgroup->path)];
    char walk_path[sizeof(cgroup->path)];
    char *component, *saveptr = NULL;

    if (cgroup == NULL) return -EINVAL;
    cgroup->fd = -1;
    cgroup->path[0] = '\0';
    result = read_self_cgroup(contents, sizeof(contents));
    if (result != 0) return result;
    result = dl_linux_cgroup_v2_parse_self_cgroup(contents, path, sizeof(path));
    if (result != 0) return result;
    (void)snprintf(cgroup->path, sizeof(cgroup->path), "%s", path);
    (void)snprintf(walk_path, sizeof(walk_path), "%s", path);

    root_fd = open(DL_CGROUP_MOUNT,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) { result = -errno; goto out; }
    result = verify_cgroup2_fd(root_fd);
    if (result != 0) goto out;

    current_fd = root_fd;
    root_fd = -1;
    for (component = strtok_r(walk_path + 1, "/", &saveptr);
         component != NULL;
         component = strtok_r(NULL, "/", &saveptr)) {
        int next_fd = openat(current_fd, component,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            result = -errno;
            goto out;
        }
        (void)close(current_fd);
        current_fd = next_fd;
    }
    result = verify_cgroup2_fd(current_fd);
    if (result != 0) goto out;
    cgroup->fd = current_fd;
    current_fd = -1;
    result = 0;
out:
    if (current_fd >= 0) (void)close(current_fd);
    if (root_fd >= 0) (void)close(root_fd);
    if (result != 0) cgroup->path[0] = '\0';
    return result;
}

void dl_linux_cgroup_v2_close(dl_linux_cgroup_v2 *cgroup)
{
    if (cgroup == NULL) return;
    if (cgroup->fd >= 0) (void)close(cgroup->fd);
    cgroup->fd = -1;
    cgroup->path[0] = '\0';
}

static bool valid_session_id(const char *session_id)
{
    const unsigned char *p;
    size_t length;
    if (session_id == NULL) return false;
    length = strlen(session_id);
    if (length == 0 || length >= 64) return false;
    for (p = (const unsigned char *)session_id; *p != '\0'; ++p)
        if (!( (*p >= 'a' && *p <= 'z') ||
               (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
            return false;
    return true;
}


static int make_session_name(const char *session_id,
                             const dl_process_identity *leader,
                             char *name, size_t name_size)
{
    int length;
    if (!valid_session_id(session_id) || leader == NULL ||
        leader->pid == 0 || leader->pid_namespace_inode == 0)
        return -EINVAL;
    length = snprintf(name, name_size, "login-%s-%u-%llu", session_id,
                      leader->pid,
                      (unsigned long long)leader->process_start_time);
    return length < 0 ? -EINVAL :
           (size_t)length >= name_size ? -ENAMETOOLONG : 0;
}

static bool same_process(const dl_process_identity *a,
                         const dl_process_identity *b)
{
    return a->pid == b->pid &&
           a->pid_namespace_inode == b->pid_namespace_inode &&
           a->process_start_time == b->process_start_time;
}

int dl_linux_cgroup_v2_session_create(
    const dl_linux_cgroup_v2 *parent, const char *session_id,
    const dl_process_identity *leader, dl_linux_cgroup_v2_session *session)
{
#if defined(SYS_pidfd_open)
    dl_process_identity current;
    char pid_text[32];
    int pidfd = -1, parent_copy = -1, child_fd = -1, procs_fd = -1;
    int result = -EINVAL;
    bool created = false;

    if (session != NULL) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    if (parent == NULL || parent->fd < 0 || !valid_session_id(session_id) ||
        leader == NULL || leader->pid == 0 ||
        leader->pid > (uint32_t)INT_MAX || leader->pid_namespace_inode == 0 ||
        session == NULL) return -EINVAL;
    result = verify_cgroup2_fd(parent->fd);
    if (result != 0) return result;

    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)leader->pid, 0);
    if (pidfd < 0) return errno == ENOSYS ? -ENOTSUP : -errno;
    if (dl_linux_process_identity_read(leader->pid, &current) != DL_OK ||
        !same_process(leader, &current)) {
        result = -ESRCH;
        goto out;
    }

    parent_copy = fcntl(parent->fd, F_DUPFD_CLOEXEC, 0);
    if (parent_copy < 0) { result = -errno; goto out; }

    result = make_session_name(session_id, leader, session->name,
                               sizeof(session->name));
    if (result != 0) goto out;
    if (mkdirat(parent->fd, session->name, 0755) != 0) {
        result = -errno;
        goto out;
    }
    created = true;
    child_fd = openat(parent->fd, session->name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (child_fd < 0) { result = -errno; goto out; }
    result = verify_cgroup2_fd(child_fd);
    if (result != 0) goto out;

    procs_fd = openat(child_fd, "cgroup.procs", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (procs_fd < 0) { result = -errno; goto out; }
    if (snprintf(pid_text, sizeof(pid_text), "%u\n", leader->pid) >=
        (int)sizeof(pid_text)) {
        result = -EINVAL;
        goto out;
    }
    {
        size_t length = strlen(pid_text);
        ssize_t written;
        do {
            written = write(procs_fd, pid_text, length);
        } while (written < 0 && errno == EINTR);
        if (written < 0) { result = -errno; goto out; }
        if ((size_t)written != length) { result = -EIO; goto out; }
    }

    /* pidfd keeps this numeric PID reserved while we verify the move. */
    if (dl_linux_process_identity_read(leader->pid, &current) != DL_OK ||
        !same_process(leader, &current)) {
        result = -ESRCH;
        goto out;
    }

    session->parent_fd = parent_copy;
    session->fd = child_fd;
                   parent->path, session->name);
    parent_copy = -1;
    child_fd = -1;
    result = 0;
out:
    if (procs_fd >= 0) (void)close(procs_fd);
    if (child_fd >= 0) (void)close(child_fd);
    if (created && result != 0)
        (void)unlinkat(parent->fd, session->name, AT_REMOVEDIR);
    if (parent_copy >= 0) (void)close(parent_copy);
    if (pidfd >= 0) (void)close(pidfd);
    if (result != 0) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    return result;
#else
    (void)parent;
    (void)session_id;
    (void)leader;
    if (session != NULL) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    return -ENOTSUP;
#endif
}


int dl_linux_cgroup_v2_session_open(
    const dl_linux_cgroup_v2 *parent, const char *session_id,
    const dl_process_identity *leader, dl_linux_cgroup_v2_session *session)
{
    int result, parent_copy = -1, child_fd = -1;
    if (session != NULL) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    if (parent == NULL || parent->fd < 0 || session == NULL)
        return -EINVAL;
    result = verify_cgroup2_fd(parent->fd);
    if (result != 0) return result;
    result = make_session_name(session_id, leader, session->name,
                               sizeof(session->name));
    if (result != 0) return result;
    parent_copy = fcntl(parent->fd, F_DUPFD_CLOEXEC, 0);
    if (parent_copy < 0) return -errno;
    child_fd = openat(parent->fd, session->name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (child_fd < 0) {
        result = -errno;
        (void)close(parent_copy);
        session->name[0] = '\0';
        return result;
    }
    result = verify_cgroup2_fd(child_fd);
    if (result != 0) {
        (void)close(child_fd);
        (void)close(parent_copy);
        session->name[0] = '\0';
        return result;
    }
    session->parent_fd = parent_copy;
    session->fd = child_fd;
                   parent->path, session->name);
    return 0;
}

void dl_linux_cgroup_v2_session_release(dl_linux_cgroup_v2_session *session)
{
    if (session == NULL) return;
    if (session->fd >= 0) (void)close(session->fd);
    if (session->parent_fd >= 0) (void)close(session->parent_fd);
    session->fd = -1;
    session->parent_fd = -1;
    session->name[0] = '\0';
}

int dl_linux_cgroup_v2_session_kill_all(
    const dl_linux_cgroup_v2_session *session)
{
    int fd, result = 0;
    if (session == NULL || session->fd < 0) return -EINVAL;
    fd = openat(session->fd, "cgroup.kill",
                O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? -ENOTSUP : -errno;
    for (;;) {
        ssize_t written = write(fd, "1", 1);
        if (written == 1) break;
        if (written < 0 && errno == EINTR) continue;
        result = written < 0 ? -errno : -EIO;
        break;
    }
    (void)close(fd);
    return result;
}

int dl_linux_cgroup_v2_session_close(dl_linux_cgroup_v2_session *session)
{
    if (session == NULL || session->parent_fd < 0 || session->fd < 0)
        return -EINVAL;
    if (unlinkat(session->parent_fd, session->name, AT_REMOVEDIR) != 0) {
        if (errno == ENOTEMPTY || errno == EBUSY) return -EBUSY;
        if (errno != ENOENT) return -errno;
    }
    (void)close(session->fd);
    (void)close(session->parent_fd);
    session->fd = -1;
    session->parent_fd = -1;
    session->name[0] = '\0';
    return 0;
}
