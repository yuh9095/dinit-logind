/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "cgroup_v2.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
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

struct cgroup_session_registry_entry {
    char name[96];
    int parent_fd;
    int fd;
    struct cgroup_session_registry_entry *next;
};

/* All registry operations run on the daemon's single event-loop thread. */
static struct cgroup_session_registry_entry *session_registry;

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
    struct cgroup_session_registry_entry *entry = NULL;
    char pid_text[32];
    int pidfd = -1, parent_copy = -1, child_fd = -1;
    int session_parent_fd = -1, session_fd = -1, procs_fd = -1;
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

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) return -ENOMEM;
    entry->parent_fd = -1;
    entry->fd = -1;

    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)leader->pid, 0);
    if (pidfd < 0) {
        result = errno == ENOSYS ? -ENOTSUP : -errno;
        goto out;
    }
    if (dl_linux_process_identity_read(leader->pid, &current) != DL_OK ||
        !same_process(leader, &current)) {
        result = -ESRCH;
        goto out;
    }

    parent_copy = fcntl(parent->fd, F_DUPFD_CLOEXEC, 0);
    if (parent_copy < 0) { result = -errno; goto out; }

    result = make_session_name(session_id, leader, entry->name,
                               sizeof(entry->name));
    if (result != 0) goto out;
    if (mkdirat(parent->fd, entry->name, 0755) != 0) {
        result = -errno;
        goto out;
    }
    created = true;
    child_fd = openat(parent->fd, entry->name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (child_fd < 0) { result = -errno; goto out; }
    result = verify_cgroup2_fd(child_fd);
    if (result != 0) goto out;

    /* Allocate every handle and registry object before moving the process. */
    session_parent_fd = fcntl(parent_copy, F_DUPFD_CLOEXEC, 0);
    if (session_parent_fd < 0) { result = -errno; goto out; }
    session_fd = fcntl(child_fd, F_DUPFD_CLOEXEC, 0);
    if (session_fd < 0) { result = -errno; goto out; }

    procs_fd = openat(child_fd, "cgroup.procs",
                      O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
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

    entry->parent_fd = parent_copy;
    entry->fd = child_fd;
    entry->next = session_registry;
    session_registry = entry;
    parent_copy = -1;
    child_fd = -1;
    session->parent_fd = session_parent_fd;
    session->fd = session_fd;
    (void)snprintf(session->name, sizeof(session->name), "%s", entry->name);
    session_parent_fd = -1;
    session_fd = -1;
    entry = NULL;
    result = 0;
out:
    if (procs_fd >= 0) (void)close(procs_fd);
    if (session_fd >= 0) (void)close(session_fd);
    if (session_parent_fd >= 0) (void)close(session_parent_fd);
    if (child_fd >= 0) (void)close(child_fd);
    if (created && result != 0)
        (void)unlinkat(parent->fd, entry->name, AT_REMOVEDIR);
    if (parent_copy >= 0) (void)close(parent_copy);
    if (pidfd >= 0) (void)close(pidfd);
    free(entry);
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
    struct cgroup_session_registry_entry *entry;
    struct stat expected_parent, registered_parent;
    char name[96];
    int result, parent_copy, child_copy;

    if (session != NULL) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    if (parent == NULL || parent->fd < 0 || session == NULL)
        return -EINVAL;
    result = verify_cgroup2_fd(parent->fd);
    if (result != 0) return result;
    result = make_session_name(session_id, leader, name, sizeof(name));
    if (result != 0) return result;
    if (fstat(parent->fd, &expected_parent) != 0) return -errno;

    for (entry = session_registry; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) != 0) continue;
        if (fstat(entry->parent_fd, &registered_parent) != 0)
            return -errno;
        if (expected_parent.st_dev != registered_parent.st_dev ||
            expected_parent.st_ino != registered_parent.st_ino)
            return -EXDEV;
        parent_copy = fcntl(entry->parent_fd, F_DUPFD_CLOEXEC, 0);
        if (parent_copy < 0) return -errno;
        child_copy = fcntl(entry->fd, F_DUPFD_CLOEXEC, 0);
        if (child_copy < 0) {
            result = -errno;
            (void)close(parent_copy);
            return result;
        }
        session->parent_fd = parent_copy;
        session->fd = child_copy;
        (void)snprintf(session->name, sizeof(session->name), "%s", name);
        return 0;
    }
    return -ENOENT;
}

int dl_linux_cgroup_v2_session_open_recovery(
    const dl_linux_cgroup_v2 *parent, const char *name,
    uint64_t expected_parent_dev, uint64_t expected_parent_ino,
    uint64_t expected_child_dev, uint64_t expected_child_ino,
    dl_linux_cgroup_v2_session *session)
{
    struct stat parent_st, child_st;
    size_t i, length;
    int parent_fd = -1, child_fd = -1, kill_fd = -1, result = -EINVAL;

    if (session) {
        session->parent_fd = -1;
        session->fd = -1;
        session->name[0] = '\0';
    }
    if (!parent || parent->fd < 0 || !name || !session)
        return -EINVAL;
    length = strnlen(name, sizeof(session->name));
    if (length == 0 || length >= sizeof(session->name) ||
        (length == 1 && name[0] == '.') ||
        (length == 2 && name[0] == '.' && name[1] == '.'))
        return -EINVAL;
    for (i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)name[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '-'))
            return -EINVAL;
    }
    result = verify_cgroup2_fd(parent->fd);
    if (result != 0) return result;
    if (fstat(parent->fd, &parent_st) != 0) return -errno;
    if ((uint64_t)parent_st.st_dev != expected_parent_dev ||
        (uint64_t)parent_st.st_ino != expected_parent_ino)
        return -EXDEV;

    child_fd = openat(parent->fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (child_fd < 0) return -errno;
    result = verify_cgroup2_fd(child_fd);
    if (result != 0) goto fail;
    if (fstat(child_fd, &child_st) != 0) {
        result = -errno;
        goto fail;
    }
    if ((uint64_t)child_st.st_dev != expected_child_dev ||
        (uint64_t)child_st.st_ino != expected_child_ino) {
        result = -ESTALE;
        goto fail;
    }
    kill_fd = openat(child_fd, "cgroup.kill",
                     O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (kill_fd < 0) {
        result = errno == ENOENT ? -ENOTSUP : -errno;
        goto fail;
    }
    if (close(kill_fd) != 0) {
        result = -errno;
        kill_fd = -1;
        goto fail;
    }
    kill_fd = -1;
    parent_fd = fcntl(parent->fd, F_DUPFD_CLOEXEC, 0);
    if (parent_fd < 0) {
        result = -errno;
        goto fail;
    }
    session->parent_fd = parent_fd;
    session->fd = child_fd;
    memcpy(session->name, name, length + 1);
    return 0;

fail:
    if (kill_fd >= 0) (void)close(kill_fd);
    if (parent_fd >= 0) (void)close(parent_fd);
    if (child_fd >= 0) (void)close(child_fd);
    return result;
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

static int default_kill_open(int dirfd, int flags, void *userdata)
{
    (void)userdata;
    return openat(dirfd, "cgroup.kill", flags);
}

static ssize_t default_kill_write(int fd, const void *buffer, size_t size,
                                  void *userdata)
{
    (void)userdata;
    return write(fd, buffer, size);
}

static int default_kill_close(int fd, void *userdata)
{
    (void)userdata;
    return close(fd);
}

static const dl_linux_cgroup_v2_kill_io default_kill_io = {
    default_kill_open, default_kill_write, default_kill_close, NULL
};

int dl_linux_cgroup_v2_session_kill_all_available(
    const dl_linux_cgroup_v2_session *session)
{
    int fd;
    if (session == NULL || session->fd < 0) return -EINVAL;
    fd = default_kill_io.open_kill(session->fd,
        O_WRONLY | O_CLOEXEC | O_NOFOLLOW, NULL);
    if (fd < 0) return errno == ENOENT ? -ENOTSUP : -errno;
    (void)default_kill_io.close_fd(fd, NULL);
    return 0;
}

int dl_linux_cgroup_v2_session_kill_all_with_io(
    const dl_linux_cgroup_v2_session *session,
    const dl_linux_cgroup_v2_kill_io *io)
{
    int fd, result = 0;
    if (session == NULL || session->fd < 0 || io == NULL ||
        io->open_kill == NULL || io->write_kill == NULL ||
        io->close_fd == NULL)
        return -EINVAL;
    fd = io->open_kill(session->fd,
        O_WRONLY | O_CLOEXEC | O_NOFOLLOW, io->userdata);
    if (fd < 0) return errno == ENOENT ? -ENOTSUP : -errno;
    for (;;) {
        ssize_t written = io->write_kill(fd, "1", 1, io->userdata);
        if (written == 1) break;
        if (written < 0 && errno == EINTR) continue;
        result = written < 0 ? -errno : -EIO;
        break;
    }
    (void)io->close_fd(fd, io->userdata);
    return result;
}

int dl_linux_cgroup_v2_session_kill_all(
    const dl_linux_cgroup_v2_session *session)
{
    return dl_linux_cgroup_v2_session_kill_all_with_io(session, &default_kill_io);
}



#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
#define DL_CGROUP_SIGNAL_MAX_DEPTH 64u
#define DL_CGROUP_SIGNAL_MAX_PROCESSES 65536u

static int cgroup_v2_read_procs_fd(int cgroup_fd, char *buffer,
                                   size_t capacity)
{
    int fd;
    size_t used = 0;
    if (capacity < 2) return -EINVAL;
    fd = openat(cgroup_fd, "cgroup.procs",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    while (used + 1 < capacity) {
        ssize_t n = read(fd, buffer + used, capacity - used - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            {
                int saved = errno;
                (void)close(fd);
                return -saved;
            }
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    (void)close(fd);
    if (used + 1 == capacity) return -EOVERFLOW;
    buffer[used] = '\0';
    return 0;
}

static int cgroup_v2_contains_pid_fd(int cgroup_fd, pid_t wanted,
                                     bool *contains)
{
    char buffer[65536];
    char *line, *saveptr = NULL;
    int r;
    *contains = false;
    r = cgroup_v2_read_procs_fd(cgroup_fd, buffer, sizeof(buffer));
    if (r < 0) return r;
    for (line = strtok_r(buffer, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *end = NULL;
        long value;
        errno = 0;
        value = strtol(line, &end, 10);
        if (errno != 0 || end == line || *end != '\0' ||
            value <= 0 || value > INT_MAX)
            return -EIO;
        if ((pid_t)value == wanted) {
            *contains = true;
            return 0;
        }
    }
    return 0;
}

static int cgroup_v2_signal_one(int cgroup_fd, pid_t pid,
                                int signal_number)
{
    int pidfd, r, saved_errno;
    bool still_member = false;
    dl_process_identity identity;

    /* Pin the PID before reading process metadata. A reused PID can never
     * redirect pidfd_send_signal to a different task after this point. */
    pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) {
        if (errno == ESRCH) return 0;
        return errno == ENOSYS ? -ENOTSUP : -errno;
    }
    if (dl_linux_process_identity_read((uint32_t)pid, &identity) != DL_OK) {
        (void)close(pidfd);
        return 0;
    }
    r = cgroup_v2_contains_pid_fd(cgroup_fd, pid, &still_member);
    if (r < 0 || !still_member) {
        (void)close(pidfd);
        return r;
    }
    r = (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0);
    saved_errno = errno;
    (void)close(pidfd);
    if (r < 0 && saved_errno != ESRCH)
        return saved_errno == ENOSYS ? -ENOTSUP : -saved_errno;
    return 0;
}

static int cgroup_v2_signal_tree(int cgroup_fd, int signal_number,
                                 unsigned int depth, size_t *process_count)
{
    char buffer[65536];
    char *line, *saveptr = NULL;
    DIR *directory = NULL;
    struct dirent *entry;
    int duplicate_fd, r;

    if (depth > DL_CGROUP_SIGNAL_MAX_DEPTH) return -ELOOP;
    r = verify_cgroup2_fd(cgroup_fd);
    if (r < 0) return r;

    r = cgroup_v2_read_procs_fd(cgroup_fd, buffer, sizeof(buffer));
    if (r < 0) return r;
    for (line = strtok_r(buffer, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *end = NULL;
        long value;
        errno = 0;
        value = strtol(line, &end, 10);
        if (errno != 0 || end == line || *end != '\0' ||
            value <= 0 || value > INT_MAX)
            return -EIO;
        if (++(*process_count) > DL_CGROUP_SIGNAL_MAX_PROCESSES)
            return -E2BIG;
        r = cgroup_v2_signal_one(cgroup_fd, (pid_t)value, signal_number);
        if (r < 0) return r;
    }

    duplicate_fd = fcntl(cgroup_fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate_fd < 0) return -errno;
    directory = fdopendir(duplicate_fd);
    if (directory == NULL) {
        r = -errno;
        (void)close(duplicate_fd);
        return r;
    }
    for (;;) {
        int child_fd;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            r = errno == 0 ? 0 : -errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        child_fd = openat(cgroup_fd, entry->d_name,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0) {
            if (errno == ENOTDIR) continue;
            r = -errno;
            break;
        }
        r = cgroup_v2_signal_tree(child_fd, signal_number,
                                  depth + 1, process_count);
        (void)close(child_fd);
        if (r < 0) break;
    }
    if (r < 0) {
        (void)closedir(directory);
        return r;
    }
    (void)closedir(directory);
    return r;
}
#endif

int dl_linux_cgroup_v2_session_signal_all(
    const dl_linux_cgroup_v2_session *session, int signal_number)
{
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    size_t process_count = 0;
    if (session == NULL || session->fd < 0 || signal_number <= 0 ||
        signal_number == SIGKILL)
        return -EINVAL;
    return cgroup_v2_signal_tree(session->fd, signal_number, 0,
                                 &process_count);
#else
    (void)session;
    (void)signal_number;
    return -ENOTSUP;
#endif
}


void dl_linux_cgroup_v2_registry_reap(void)
{
    struct cgroup_session_registry_entry **link = &session_registry;
    while (*link != NULL) {
        struct cgroup_session_registry_entry *entry = *link;
        if (unlinkat(entry->parent_fd, entry->name, AT_REMOVEDIR) == 0 ||
            errno == ENOENT) {
            *link = entry->next;
            (void)close(entry->fd);
            (void)close(entry->parent_fd);
            free(entry);
            continue;
        }
        link = &entry->next;
    }
}

int dl_linux_cgroup_v2_session_close(dl_linux_cgroup_v2_session *session)
{
    struct cgroup_session_registry_entry **link;
    if (session == NULL || session->parent_fd < 0 || session->fd < 0)
        return -EINVAL;
    if (unlinkat(session->parent_fd, session->name, AT_REMOVEDIR) != 0) {
        if (errno == ENOTEMPTY || errno == EBUSY) return -EBUSY;
        if (errno != ENOENT) return -errno;
    }
    for (link = &session_registry; *link != NULL; link = &(*link)->next) {
        struct cgroup_session_registry_entry *entry = *link;
        if (strcmp(entry->name, session->name) != 0) continue;
        *link = entry->next;
        (void)close(entry->fd);
        (void)close(entry->parent_fd);
        free(entry);
        break;
    }
    (void)close(session->fd);
    (void)close(session->parent_fd);
    session->fd = -1;
    session->parent_fd = -1;
    session->name[0] = '\0';
    return 0;
}
