/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "../../src/runtime/runtime.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void join_path(char *out, size_t size, const char *a, const char *b)
{
    int n = snprintf(out, size, "%s/%s", a, b);
    assert(n > 0 && (size_t)n < size);
}

int main(void)
{
    char temporary[] = "/tmp/dinit-logind-runtime-XXXXXX";
    char runtime_base[256], linger_dir[256], runtime_path[512], file_path[512];
    struct stat st;
    dl_runtime_paths paths;
    bool enabled = false;
    uint32_t uid = (uint32_t)getuid(), gid = (uint32_t)getgid();
    int fd;

    assert(mkdtemp(temporary) != NULL);
    join_path(runtime_base, sizeof(runtime_base), temporary, "run-user");
    join_path(linger_dir, sizeof(linger_dir), temporary, "linger");
    assert(mkdir(runtime_base, 0755) == 0);
    assert(mkdir(linger_dir, 0700) == 0);
    paths.runtime_base = runtime_base;
    paths.linger_directory = linger_dir;
    paths.trusted_owner = geteuid();

    assert(dl_runtime_prepare_user(&paths, uid, gid,
                                   runtime_path, sizeof(runtime_path)) == DL_OK);
    assert(stat(runtime_path, &st) == 0);
    assert(st.st_uid == (uid_t)uid && st.st_gid == (gid_t)gid);
    assert((st.st_mode & 0777) == 0700);
    assert(dl_runtime_get_linger(&paths, uid, &enabled) == DL_OK && !enabled);
    assert(dl_runtime_set_linger(&paths, uid, true) == DL_OK);
    assert(dl_runtime_get_linger(&paths, uid, &enabled) == DL_OK && enabled);
    assert(dl_runtime_set_linger(&paths, uid, true) == DL_OK);
    assert(dl_runtime_set_linger(&paths, uid, false) == DL_OK);
    assert(dl_runtime_get_linger(&paths, uid, &enabled) == DL_OK && !enabled);

    join_path(file_path, sizeof(file_path), runtime_path, "keep");
    fd = open(file_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, "x", 1) == 1);
    assert(close(fd) == 0);
    assert(dl_runtime_cleanup_user(&paths, uid) == DL_ERR_CONFLICT);
    assert(access(file_path, F_OK) == 0);
    assert(unlink(file_path) == 0);
    assert(dl_runtime_cleanup_user(&paths, uid) == DL_OK);
    assert(access(runtime_path, F_OK) != 0 && errno == ENOENT);
    assert(rmdir(runtime_base) == 0);
    assert(rmdir(linger_dir) == 0);
    assert(rmdir(temporary) == 0);
    return 0;
}
