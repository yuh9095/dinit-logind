/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_TERMINATION_STORE_H
#define DINIT_LOGIND_TERMINATION_STORE_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define DL_TERMINATION_BOOT_ID_MAX 37
#define DL_TERMINATION_CGROUP_NAME_MAX 96
#define DL_TERMINATION_STORE_SESSION_MAX 64

typedef struct {
    char session_id[DL_TERMINATION_STORE_SESSION_MAX];
    char boot_id[DL_TERMINATION_BOOT_ID_MAX];
    char cgroup_name[DL_TERMINATION_CGROUP_NAME_MAX];
    uint64_t deadline_sec;
    uint32_t deadline_nsec;
    uint64_t parent_dev;
    uint64_t parent_ino;
    uint64_t cgroup_dev;
    uint64_t cgroup_ino;
    uint32_t leader_pid;
    uint64_t leader_start_time;
    uint64_t pid_namespace_inode;
} dl_termination_record;

typedef struct {
    int dir_fd;
    char path[4096];
} dl_termination_store;

typedef int (*dl_termination_store_visit_fn)(
    const dl_termination_record *record, void *userdata);

/* Opens or creates a root-owned, mode-0700 state directory. */
int dl_termination_store_open(dl_termination_store *store,
                              const char *path, int create);
void dl_termination_store_close(dl_termination_store *store);
/* Atomically writes and fsyncs one validated record before returning. */
int dl_termination_store_put(dl_termination_store *store,
                             const dl_termination_record *record);
/* Removes a record and fsyncs the directory. Missing records are harmless. */
int dl_termination_store_remove(dl_termination_store *store,
                                const char *session_id);
/* Visits validated records. Corrupt or unsafe records fail the scan closed. */
int dl_termination_store_foreach(dl_termination_store *store,
                                 dl_termination_store_visit_fn visit,
                                 void *userdata);
int dl_termination_store_read_boot_id(char boot_id[DL_TERMINATION_BOOT_ID_MAX]);

#endif
