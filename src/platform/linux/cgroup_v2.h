/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_CGROUP_V2_H
#define DINIT_LOGIND_LINUX_CGROUP_V2_H

#include <stddef.h>
#include "process_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int fd;
    char path[4096];
} dl_linux_cgroup_v2;

typedef struct {
    int parent_fd;
    int fd;
    char name[96];
} dl_linux_cgroup_v2_session;

/* Parse the unified 0:: entry from /proc/self/cgroup. Root and unsafe paths
 * are rejected because sessions must live below a dedicated service cgroup. */
int dl_linux_cgroup_v2_parse_self_cgroup(const char *contents,
                                         char *path, size_t path_size);

/* Open the current process's cgroup below the cgroup-v2 mount. This fails
 * closed for hybrid/v1, namespace-root, read-only, or inaccessible layouts. */
int dl_linux_cgroup_v2_open_current(dl_linux_cgroup_v2 *cgroup);
void dl_linux_cgroup_v2_close(dl_linux_cgroup_v2 *cgroup);

/* Create a child cgroup and attach only the authenticated leader. A pidfd is
 * held across identity revalidation and cgroup.procs write to prevent PID
 * reuse from redirecting the move. No kill(2) fallback is used. */
int dl_linux_cgroup_v2_session_create(
    const dl_linux_cgroup_v2 *parent, const char *session_id,
    const dl_process_identity *leader, dl_linux_cgroup_v2_session *session);

/* cgroup.kill is required; missing support returns -ENOTSUP. */
int dl_linux_cgroup_v2_session_kill_all(
    const dl_linux_cgroup_v2_session *session);

/* Removes only the exact child created by session_create. If it is still
 * populated, returns -EBUSY and retains the handles for a later retry. */
int dl_linux_cgroup_v2_session_close(dl_linux_cgroup_v2_session *session);

#ifdef __cplusplus
}
#endif
#endif
