/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "process_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROC_STAT_BUFFER_SIZE 4096

static bool read_all(int fd, char *buffer, size_t capacity, size_t *length)
{
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used - 1);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used + 1 == capacity) return false;
    buffer[used] = '\0';
    *length = used;
    return used != 0;
}

/* comm may contain spaces and ')' characters; the final ')' delimits field 2. */
static bool parse_start_time(const char *line, uint64_t *start_time)
{
    const char *cursor;
    char *end = NULL;
    unsigned long long value;
    unsigned int field = 3;
    if (line == NULL || start_time == NULL) return false;
    cursor = strrchr(line, ')');
    if (cursor == NULL || cursor[1] != ' ') return false;
    cursor += 2;
    while (field < 22) {
        while (*cursor == ' ') ++cursor;
        if (*cursor == '\0') return false;
        while (*cursor != '\0' && *cursor != ' ') ++cursor;
        if (*cursor == '\0') return false;
        ++field;
    }
    while (*cursor == ' ') ++cursor;
    if (*cursor == '\0' || *cursor == '-' || *cursor == '+') return false;
    errno = 0;
    value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor ||
        (*end != ' ' && *end != '\n' && *end != '\0')) return false;
    *start_time = (uint64_t)value;
    return true;
}

static bool read_start_time_at(int process_fd, uint64_t *start_time)
{
    char buffer[PROC_STAT_BUFFER_SIZE];
    size_t length = 0;
    int fd = openat(process_fd, "stat", O_RDONLY | O_CLOEXEC);
    bool ok;
    if (fd < 0) return false;
    ok = read_all(fd, buffer, sizeof(buffer), &length);
    (void)close(fd);
    return ok && length != 0 && parse_start_time(buffer, start_time);
}

dl_result dl_linux_process_identity_read(uint32_t pid, dl_process_identity *identity)
{
    char pid_text[32];
    int proc_fd = -1, process_fd = -1, namespace_fd = -1;
    struct stat namespace_stat;
    uint64_t start_before = 0, start_after = 0;
    dl_result result = DL_ERR_INVALID;

    if (identity != NULL) memset(identity, 0, sizeof(*identity));
    if (identity == NULL || pid == 0 || pid > (uint32_t)INT_MAX) return DL_ERR_INVALID;
    if (snprintf(pid_text, sizeof(pid_text), "%u", pid) >= (int)sizeof(pid_text))
        return DL_ERR_INVALID;

    proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) {
        result = DL_ERR_NOT_FOUND;
        goto out;
    }
    process_fd = openat(proc_fd, pid_text, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (process_fd < 0) {
        result = (errno == ENOENT || errno == ESRCH) ? DL_ERR_NOT_FOUND : DL_ERR_STATE;
        goto out;
    }
    namespace_fd = openat(process_fd, "ns/pid", O_RDONLY | O_CLOEXEC);
    if (namespace_fd < 0 || fstat(namespace_fd, &namespace_stat) != 0 ||
        namespace_stat.st_ino == 0) {
        result = DL_ERR_STATE;
        goto out;
    }
    if (!read_start_time_at(process_fd, &start_before) ||
        !read_start_time_at(process_fd, &start_after) ||
        start_before != start_after) {
        result = DL_ERR_STATE;
        goto out;
    }
    identity->pid = pid;
    identity->pid_namespace_inode = (uint64_t)namespace_stat.st_ino;
    identity->process_start_time = start_after;
    result = DL_OK;
out:
    if (namespace_fd >= 0) (void)close(namespace_fd);
    if (process_fd >= 0) (void)close(process_fd);
    if (proc_fd >= 0) (void)close(proc_fd);
    if (result != DL_OK && identity != NULL) memset(identity, 0, sizeof(*identity));
    return result;
}
