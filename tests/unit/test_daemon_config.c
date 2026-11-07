/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_all(int fd, const char *text)
{
    size_t offset = 0, length = strlen(text);
    while (offset < length) {
        ssize_t n = write(fd, text + offset, length - offset);
        assert(n > 0);
        offset += (size_t)n;
    }
}

static void test_root_owned_config_policy(void)
{
    char path[] = "/tmp/dinit-logind-config-XXXXXX";
    int fd = mkstemp(path);
    dl_daemon_config config;
    assert(fd >= 0);
    assert(fchmod(fd, 0600) == 0);
    write_all(fd, "allowed_peer_uid = 0\n");
    assert(close(fd) == 0);

    dl_daemon_config_defaults(&config);
    if (geteuid() == 0) {
        assert(dl_daemon_config_load(path, &config) == 0);
        assert(config.allowed_peer_uid == 0);
    } else {
        errno = 0;
        assert(dl_daemon_config_load(path, &config) == -1);
        assert(errno == EPERM);
        assert(config.allowed_peer_uid == 0);
    }
    assert(unlink(path) == 0);
}

static void test_symlink_rejected(void)
{
    char target[] = "/tmp/dinit-logind-config-target-XXXXXX";
    char linkpath[] = "/tmp/dinit-logind-config-link-XXXXXX";
    int fd = mkstemp(target);
    dl_daemon_config config;
    assert(fd >= 0);
    assert(close(fd) == 0);
    fd = mkstemp(linkpath);
    assert(fd >= 0);
    assert(close(fd) == 0);
    assert(unlink(linkpath) == 0);
    assert(symlink(target, linkpath) == 0);
    dl_daemon_config_defaults(&config);
    errno = 0;
    assert(dl_daemon_config_load(linkpath, &config) == -1);
    assert(errno == ELOOP);
    assert(unlink(linkpath) == 0);
    assert(unlink(target) == 0);
}

int main(void)
{
    test_root_owned_config_policy();
    test_symlink_rejected();
    puts("daemon configuration tests: ok");
    return 0;
}
