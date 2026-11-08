/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "termination_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STORE_MAGIC UINT64_C(0x444c5445524d3031)
#define STORE_VERSION 1u
#define STORE_FILE_SUFFIX ".term"

struct disk_record {
    uint64_t magic;
    uint32_t version;
    uint32_t reserved;
    dl_termination_record record;
    uint64_t checksum;
};

static bool valid_component(const char *s, size_t cap)
{
    size_t i, n;
    if (!s) return false;
    n = strnlen(s, cap);
    if (n == 0 || n >= cap) return false;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static uint64_t checksum_bytes(const void *data, size_t size)
{
    const unsigned char *p = data;
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < size; ++i) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static int record_valid(const dl_termination_record *r)
{
    if (!r || !valid_component(r->session_id, sizeof(r->session_id)) ||
        !valid_component(r->cgroup_name, sizeof(r->cgroup_name)) ||
        strnlen(r->boot_id, sizeof(r->boot_id)) != 36 ||
        r->deadline_nsec >= 1000000000u ||
        r->parent_ino == 0 || r->cgroup_ino == 0 ||
        r->leader_pid == 0 || r->leader_start_time == 0 ||
        r->pid_namespace_inode == 0)
        return -EINVAL;
    return 0;
}

static int record_filename(const char *id, char *out, size_t size)
{
    int n;
    if (!valid_component(id, DL_TERMINATION_STORE_SESSION_MAX))
        return -EINVAL;
    n = snprintf(out, size, "%s%s", id, STORE_FILE_SUFFIX);
    return n < 0 ? -EINVAL : (size_t)n >= size ? -ENAMETOOLONG : 0;
}

int dl_termination_store_open(dl_termination_store *store,
                              const char *path, int create)
{
    struct stat st;
    int fd;
    if (!store || !path || path[0] != '/' || strlen(path) >= sizeof(store->path))
        return -EINVAL;
    store->dir_fd = -1;
    store->path[0] = '\0';
    if (create && mkdir(path, 0700) != 0 && errno != EEXIST)
        return -errno;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    if (fstat(fd, &st) != 0) {
        int e = errno; close(fd); return -e;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0077) != 0) {
        close(fd);
        return -EPERM;
    }
    store->dir_fd = fd;
    memcpy(store->path, path, strlen(path) + 1);
    return 0;
}

void dl_termination_store_close(dl_termination_store *store)
{
    if (!store) return;
    if (store->dir_fd >= 0) close(store->dir_fd);
    store->dir_fd = -1;
    store->path[0] = '\0';
}

int dl_termination_store_put(dl_termination_store *store,
                             const dl_termination_record *record)
{
    struct disk_record disk;
    char name[DL_TERMINATION_STORE_SESSION_MAX + sizeof(STORE_FILE_SUFFIX)];
    char temp[DL_TERMINATION_STORE_SESSION_MAX + 48];
    int fd = -1, r, n;
    if (!store || store->dir_fd < 0) return -EINVAL;
    r = record_valid(record);
    if (r < 0) return r;
    r = record_filename(record->session_id, name, sizeof(name));
    if (r < 0) return r;
    memset(&disk, 0, sizeof(disk));
    disk.magic = STORE_MAGIC;
    disk.version = STORE_VERSION;
    disk.record = *record;
    disk.checksum = checksum_bytes(&disk, offsetof(struct disk_record, checksum));
    n = snprintf(temp, sizeof(temp), ".tmp-%ld-%s", (long)getpid(),
                 record->session_id);
    if (n < 0 || (size_t)n >= sizeof(temp)) return -ENAMETOOLONG;
    fd = openat(store->dir_fd, temp,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -errno;
    {
        const unsigned char *p = (const unsigned char *)&disk;
        size_t left = sizeof(disk);
        while (left) {
            ssize_t w = write(fd, p, left);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { r = w < 0 ? -errno : -EIO; goto fail; }
            p += (size_t)w;
            left -= (size_t)w;
        }
    }
    if (fsync(fd) != 0) { r = -errno; goto fail; }
    if (close(fd) != 0) { fd = -1; r = -errno; goto fail; }
    fd = -1;
    if (renameat(store->dir_fd, temp, store->dir_fd, name) != 0) {
        r = -errno; goto fail;
    }
    if (fsync(store->dir_fd) != 0) return -errno;
    return 0;
fail:
    if (fd >= 0) close(fd);
    unlinkat(store->dir_fd, temp, 0);
    return r;
}

int dl_termination_store_remove(dl_termination_store *store,
                                const char *session_id)
{
    char name[DL_TERMINATION_STORE_SESSION_MAX + sizeof(STORE_FILE_SUFFIX)];
    int r;
    if (!store || store->dir_fd < 0) return -EINVAL;
    r = record_filename(session_id, name, sizeof(name));
    if (r < 0) return r;
    if (unlinkat(store->dir_fd, name, 0) != 0 && errno != ENOENT)
        return -errno;
    return fsync(store->dir_fd) == 0 ? 0 : -errno;
}

int dl_termination_store_foreach(dl_termination_store *store,
                                 dl_termination_store_visit_fn visit,
                                 void *userdata)
{
    DIR *dir;
    struct dirent *de;
    int dupfd, result = 0;
    if (!store || store->dir_fd < 0 || !visit) return -EINVAL;
    dupfd = fcntl(store->dir_fd, F_DUPFD_CLOEXEC, 0);
    if (dupfd < 0) return -errno;
    dir = fdopendir(dupfd);
    if (!dir) { result = -errno; close(dupfd); return result; }
    errno = 0;
    while ((de = readdir(dir)) != NULL) {
        struct disk_record disk;
        struct stat st;
        int fd;
        size_t suffix = sizeof(STORE_FILE_SUFFIX) - 1;
        if (de->d_name[0] == '.') continue;
        if (strlen(de->d_name) <= suffix ||
            strcmp(de->d_name + strlen(de->d_name) - suffix,
                   STORE_FILE_SUFFIX) != 0) continue;
        fd = openat(store->dir_fd, de->d_name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) { result = -errno; break; }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != 0 || (st.st_mode & 0077) != 0 ||
            st.st_size != (off_t)sizeof(disk)) {
            close(fd); result = -EPERM; break;
        }
        {
            unsigned char *p = (unsigned char *)&disk;
            size_t left = sizeof(disk);
            while (left) {
                ssize_t n = read(fd, p, left);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { result = n < 0 ? -errno : -EIO; break; }
                p += (size_t)n; left -= (size_t)n;
            }
        }
        close(fd);
        if (result < 0) break;
        if (disk.magic != STORE_MAGIC || disk.version != STORE_VERSION ||
            disk.checksum != checksum_bytes(&disk,
                offsetof(struct disk_record, checksum)) ||
            record_valid(&disk.record) < 0) {
            result = -EBADMSG; break;
        }
        {
            char expected[DL_TERMINATION_STORE_SESSION_MAX +
                          sizeof(STORE_FILE_SUFFIX)];
            if (record_filename(disk.record.session_id, expected,
                                sizeof(expected)) < 0 ||
                strcmp(expected, de->d_name) != 0) {
                result = -EBADMSG; break;
            }
        }
        result = visit(&disk.record, userdata);
        if (result != 0) break;
        errno = 0;
    }
    if (result == 0 && errno != 0) result = -errno;
    closedir(dir);
    return result;
}

int dl_termination_store_read_boot_id(char boot_id[DL_TERMINATION_BOOT_ID_MAX])
{
    int fd;
    size_t used = 0;
    if (!boot_id) return -EINVAL;
    fd = open("/proc/sys/kernel/random/boot_id",
              O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    while (used < DL_TERMINATION_BOOT_ID_MAX - 1) {
        ssize_t n = read(fd, boot_id + used,
                         DL_TERMINATION_BOOT_ID_MAX - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { int e = errno; close(fd); return -e; }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    while (used && (boot_id[used - 1] == '\n' ||
                    boot_id[used - 1] == '\r')) --used;
    boot_id[used] = '\0';
    return used == 36 ? 0 : -EBADMSG;
}
