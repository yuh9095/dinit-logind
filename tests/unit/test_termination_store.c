/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "../../src/session/termination_store.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct seen { int count; dl_termination_record record; };
static int visit(const dl_termination_record *r, void *p)
{
    struct seen *s = p;
    ++s->count;
    s->record = *r;
    return 0;
}

static dl_termination_record sample(void)
{
    dl_termination_record r;
    memset(&r, 0, sizeof(r));
    strcpy(r.session_id, "c1");
    strcpy(r.boot_id, "01234567-89ab-cdef-0123-456789abcdef");
    strcpy(r.cgroup_name, "login-c1-42-123456");
    r.deadline_sec = 900;
    r.deadline_nsec = 123;
    r.parent_dev = 1; r.parent_ino = 2;
    r.cgroup_dev = 1; r.cgroup_ino = 3;
    r.leader_pid = 42; r.leader_start_time = 123456;
    r.pid_namespace_inode = 77;
    return r;
}

static void test_roundtrip_and_remove(void)
{
    char path[] = "/tmp/dl-term-store-XXXXXX";
    char *dir = mkdtemp(path);
    dl_termination_store store;
    dl_termination_record record = sample();
    struct seen seen = {0};
    assert(dir);
    assert(chmod(dir, 0700) == 0);
    if (geteuid() != 0) { rmdir(dir); return; }
    assert(dl_termination_store_open(&store, dir, 0) == 0);
    assert(dl_termination_store_put(&store, &record) == 0);
    assert(dl_termination_store_foreach(&store, visit, &seen) == 0);
    assert(seen.count == 1);
    assert(strcmp(seen.record.session_id, record.session_id) == 0);
    assert(seen.record.deadline_sec == record.deadline_sec);
    assert(seen.record.cgroup_ino == record.cgroup_ino);
    assert(dl_termination_store_remove(&store, "c1") == 0);
    seen.count = 0;
    assert(dl_termination_store_foreach(&store, visit, &seen) == 0);
    assert(seen.count == 0);
    dl_termination_store_close(&store);
    assert(rmdir(dir) == 0);
}

static void test_corruption_fails_closed(void)
{
    char path[] = "/tmp/dl-term-corrupt-XXXXXX";
    char *dir = mkdtemp(path);
    dl_termination_store store;
    dl_termination_record record = sample();
    struct seen seen = {0};
    int fd;
    char file[256];
    assert(dir);
    assert(chmod(dir, 0700) == 0);
    if (geteuid() != 0) { rmdir(dir); return; }
    assert(dl_termination_store_open(&store, dir, 0) == 0);
    assert(dl_termination_store_put(&store, &record) == 0);
    assert(snprintf(file, sizeof(file), "%s/c1.term", dir) > 0);
    fd = open(file, O_WRONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(pwrite(fd, "X", 1, 0) == 1);
    close(fd);
    assert(dl_termination_store_foreach(&store, visit, &seen) == -EBADMSG);
    dl_termination_store_close(&store);
    unlink(file);
    assert(rmdir(dir) == 0);
}

static void test_invalid_record_rejected(void)
{
    char path[] = "/tmp/dl-term-invalid-XXXXXX";
    char *dir = mkdtemp(path);
    dl_termination_store store;
    dl_termination_record record = sample();
    assert(dir);
    assert(chmod(dir, 0700) == 0);
    if (geteuid() != 0) { rmdir(dir); return; }
    assert(dl_termination_store_open(&store, dir, 0) == 0);
    record.cgroup_name[0] = '.';
    assert(dl_termination_store_put(&store, &record) == -EINVAL);
    dl_termination_store_close(&store);
    assert(rmdir(dir) == 0);
}

static void test_malformed_boot_id_rejected(void)
{
    char path[] = "/tmp/dl-term-bootid-XXXXXX";
    char *dir = mkdtemp(path);
    dl_termination_store store;
    dl_termination_record record = sample();
    assert(dir);
    assert(chmod(dir, 0700) == 0);
    if (geteuid() != 0) { rmdir(dir); return; }
    assert(dl_termination_store_open(&store, dir, 0) == 0);
    record.boot_id[8] = 'x';
    assert(dl_termination_store_put(&store, &record) == -EINVAL);
    dl_termination_store_close(&store);
    assert(rmdir(dir) == 0);
}

int main(void)
{
    test_roundtrip_and_remove();
    test_corruption_fails_closed();
    test_invalid_record_rejected();
    test_malformed_boot_id_rejected();
    return 0;
}
