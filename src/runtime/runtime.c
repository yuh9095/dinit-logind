/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static dl_result open_trusted_dir(const char *path, uid_t owner, int *out)
{
    struct stat st;
    int fd;
    if (out) *out = -1;
    if (!path || path[0] != '/' || !out) return DL_ERR_INVALID;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? DL_ERR_NOT_FOUND : DL_ERR_STATE;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & 0022) != 0) {
        close(fd);
        return DL_ERR_INVALID;
    }
    *out = fd;
    return DL_OK;
}

static bool uid_name(uint32_t uid, char name[32])
{
    int n = snprintf(name, 32, "%u", (unsigned int)uid);
    return n > 0 && n < 32;
}

dl_result dl_runtime_prepare_user(const dl_runtime_paths *paths,
                                  uint32_t uid, uint32_t gid,
                                  char *out_path, size_t out_size)
{
    int base = -1, user = -1, n;
    char name[32];
    struct stat st;
    dl_result result;
    if (!paths || !paths->runtime_base || !out_path || !out_size ||
        !uid_name(uid, name)) return DL_ERR_INVALID;
    out_path[0] = '\0';
    result = open_trusted_dir(paths->runtime_base, paths->trusted_owner, &base);
    if (result != DL_OK) return result;

    if (mkdirat(base, name, 0700) == 0) {
        user = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (user < 0 || fchown(user, (uid_t)uid, (gid_t)gid) ||
            fchmod(user, 0700) || fstat(user, &st) ||
            !S_ISDIR(st.st_mode) || st.st_uid != (uid_t)uid ||
            st.st_gid != (gid_t)gid || (st.st_mode & 0777) != 0700) {
            if (user >= 0) close(user);
            (void)unlinkat(base, name, AT_REMOVEDIR);
            close(base);
            return DL_ERR_INVALID;
        }
    } else if (errno == EEXIST) {
        user = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (user < 0 || fstat(user, &st) || !S_ISDIR(st.st_mode) ||
            st.st_uid != (uid_t)uid || st.st_gid != (gid_t)gid ||
            (st.st_mode & 0777) != 0700) {
            if (user >= 0) close(user);
            close(base);
            return DL_ERR_INVALID;
        }
    } else {
        close(base);
        return DL_ERR_STATE;
    }
    n = snprintf(out_path, out_size, "%s/%s", paths->runtime_base, name);
    close(user);
    close(base);
    if (n < 0 || (size_t)n >= out_size) {
        out_path[0] = '\0';
        return DL_ERR_INVALID;
    }
    return DL_OK;
}

dl_result dl_runtime_cleanup_user(const dl_runtime_paths *paths, uint32_t uid)
{
    int base = -1, user = -1;
    char name[32];
    struct stat st;
    dl_result result;
    if (!paths || !paths->runtime_base || !uid_name(uid, name))
        return DL_ERR_INVALID;
    result = open_trusted_dir(paths->runtime_base, paths->trusted_owner, &base);
    if (result != DL_OK) return result;
    user = openat(base, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (user < 0) {
        close(base);
        return errno == ENOENT ? DL_OK : DL_ERR_STATE;
    }
    if (fstat(user, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != (uid_t)uid || (st.st_mode & 0777) != 0700) {
        close(user);
        close(base);
        return DL_ERR_INVALID;
    }
    close(user);
    if (unlinkat(base, name, AT_REMOVEDIR) != 0) {
        result = (errno == ENOTEMPTY || errno == EEXIST)
                     ? DL_ERR_CONFLICT : DL_ERR_STATE;
        close(base);
        return result;
    }
    close(base);
    return DL_OK;
}

static dl_result check_marker(int dirfd, const char *name, uid_t owner,
                              uint32_t uid)
{
    char expected[64], actual[64];
    struct stat st;
    ssize_t n;
    int fd, length = snprintf(expected, sizeof(expected),
                              "dinit-logind-linger-v1\nuid=%u\n",
                              (unsigned int)uid);
    if (length < 0 || (size_t)length >= sizeof(expected)) return DL_ERR_INVALID;
    fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? DL_ERR_NOT_FOUND : DL_ERR_STATE;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & 0077) != 0 || st.st_nlink != 1) {
        close(fd);
        return DL_ERR_INVALID;
    }
    n = read(fd, actual, sizeof(actual));
    close(fd);
    return n == length && memcmp(actual, expected, (size_t)length) == 0
               ? DL_OK : DL_ERR_INVALID;
}

dl_result dl_runtime_get_linger(const dl_runtime_paths *paths,
                                uint32_t uid, bool *enabled)
{
    int dirfd = -1;
    char name[32];
    dl_result result;
    if (enabled) *enabled = false;
    if (!paths || !paths->linger_directory || !enabled || !uid_name(uid, name))
        return DL_ERR_INVALID;
    result = open_trusted_dir(paths->linger_directory, paths->trusted_owner, &dirfd);
    if (result != DL_OK) return result;
    result = check_marker(dirfd, name, paths->trusted_owner, uid);
    close(dirfd);
    if (result == DL_OK) *enabled = true;
    else if (result == DL_ERR_NOT_FOUND) result = DL_OK;
    return result;
}

dl_result dl_runtime_set_linger(const dl_runtime_paths *paths,
                                uint32_t uid, bool enabled)
{
    int dirfd = -1, fd = -1, length;
    char name[32], temporary[64], contents[64];
    struct timespec now;
    dl_result result;
    if (!paths || !paths->linger_directory || !uid_name(uid, name))
        return DL_ERR_INVALID;
    result = open_trusted_dir(paths->linger_directory, paths->trusted_owner, &dirfd);
    if (result != DL_OK) return result;
    result = check_marker(dirfd, name, paths->trusted_owner, uid);
    if (!enabled) {
        if (result == DL_ERR_NOT_FOUND) { close(dirfd); return DL_OK; }
        if (result != DL_OK) { close(dirfd); return result; }
        if (unlinkat(dirfd, name, 0) || fsync(dirfd)) {
            close(dirfd);
            return DL_ERR_STATE;
        }
        close(dirfd);
        return DL_OK;
    }
    if (result == DL_OK) { close(dirfd); return DL_OK; }
    if (result != DL_ERR_NOT_FOUND) { close(dirfd); return result; }
    if (clock_gettime(CLOCK_MONOTONIC, &now)) { close(dirfd); return DL_ERR_STATE; }
    length = snprintf(temporary, sizeof(temporary), ".%s.%ld.%ld",
                      name, (long)getpid(), now.tv_nsec);
    if (length < 0 || (size_t)length >= sizeof(temporary)) {
        close(dirfd);
        return DL_ERR_INVALID;
    }
    fd = openat(dirfd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { close(dirfd); return DL_ERR_STATE; }
    length = snprintf(contents, sizeof(contents),
                      "dinit-logind-linger-v1\nuid=%u\n", (unsigned int)uid);
    if (length < 0 || (size_t)length >= sizeof(contents) ||
        write(fd, contents, (size_t)length) != length || fsync(fd)) {
        close(fd);
        unlinkat(dirfd, temporary, 0);
        close(dirfd);
        return DL_ERR_STATE;
    }
    if (close(fd)) {
        unlinkat(dirfd, temporary, 0);
        close(dirfd);
        return DL_ERR_STATE;
    }
    if (renameat(dirfd, temporary, dirfd, name) || fsync(dirfd)) {
        unlinkat(dirfd, temporary, 0);
        close(dirfd);
        return DL_ERR_STATE;
    }
    close(dirfd);
    return DL_OK;
}
