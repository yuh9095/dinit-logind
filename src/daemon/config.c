/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void dl_daemon_config_defaults(dl_daemon_config *config)
{
    if (config != NULL) config->allowed_peer_uid = 0;
}

static char *trim(char *value)
{
    char *end;
    while (isspace((unsigned char)*value)) ++value;
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

int dl_daemon_config_load(const char *path, dl_daemon_config *config)
{
    struct stat st;
    char line[512];
    unsigned int seen = 0;
    int fd, result = -1;
    FILE *file;

    if (path == NULL || config == NULL) { errno = EINVAL; return -1; }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022) != 0) {
        errno = EPERM;
        (void)close(fd);
        return -1;
    }
    file = fdopen(fd, "r");
    if (file == NULL) { (void)close(fd); return -1; }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *entry;
        char *equals;
        char *key, *value, *end;
        unsigned long parsed;

        if (strchr(line, '\n') == NULL && !feof(file)) {
            errno = EOVERFLOW;
            goto out;
        }
        entry = trim(line);
        if (*entry == '\0' || *entry == '#') continue;
        equals = strchr(entry, '=');
        if (equals == NULL) { errno = EINVAL; goto out; }
        *equals = '\0';
        key = trim(entry);
        value = trim(equals + 1);
        if (strcmp(key, "allowed_peer_uid") != 0 || seen != 0 ||
            *value == '\0' || *value == '-') {
            errno = EINVAL;
            goto out;
        }
        errno = 0;
        parsed = strtoul(value, &end, 10);
        if (errno != 0 || *trim(end) != '\0' || parsed > UINT32_MAX) {
            errno = EINVAL;
            goto out;
        }
        config->allowed_peer_uid = (uint32_t)parsed;
        seen = 1;
    }
    if (ferror(file)) goto out;
    result = 0;
out:
    {
        int saved = errno;
        (void)fclose(file);
        errno = saved;
    }
    return result;
}
