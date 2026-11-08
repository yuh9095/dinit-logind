/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_CGROUP_V2_H
#define DINIT_LOGIND_LINUX_CGROUP_V2_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
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

/* Narrow I/O seam for deterministic cgroup.kill error and retry tests. */
typedef struct {
    int (*open_kill)(int dirfd, int flags, void *userdata);
    ssize_t (*write_kill)(int fd, const void *buffer, size_t size, void *userdata);
    int (*close_fd)(int fd, void *userdata);
    void *userdata;
} dl_linux_cgroup_v2_kill_io;

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

/* Open an existing session cgroup by its generated ID/leader-derived name. */
int dl_linux_cgroup_v2_session_open(
    const dl_linux_cgroup_v2 *parent, const char *session_id,
    const dl_process_identity *leader, dl_linux_cgroup_v2_session *session);

/* Reopen a journaled child only when both parent and child filesystem
 * identities still match. The child name is treated as one safe component. */
int dl_linux_cgroup_v2_session_open_recovery(
    const dl_linux_cgroup_v2 *parent, const char *name,
    uint64_t expected_parent_dev, uint64_t expected_parent_ino,
    uint64_t expected_child_dev, uint64_t expected_child_ino,
    dl_linux_cgroup_v2_session *session);

/* Close handles without removing the cgroup (used when still populated). */
void dl_linux_cgroup_v2_session_release(dl_linux_cgroup_v2_session *session);

/* Reap empty cgroups previously created by this daemon instance. */
void dl_linux_cgroup_v2_registry_reap(void);

/* Best-effort non-SIGKILL signaling of processes observed in this
 * daemon-owned session cgroup subtree. pidfds prevent PID-reuse redirection;
 * membership is rechecked immediately before signaling, but cgroup migration
 * can still race between that check and pidfd_send_signal(). This operation
 * is not an atomic whole-session operation. Requires pidfd support and never
 * falls back to numeric-PID kill(2). Use session_kill_all() for atomic,
 * migration-safe SIGKILL semantics when cgroup.kill is available. */
int dl_linux_cgroup_v2_session_signal_all(
    const dl_linux_cgroup_v2_session *session, int signal_number);

/* Check that cgroup.kill is present and writable before accepting Terminate. */
int dl_linux_cgroup_v2_session_kill_all_available(
    const dl_linux_cgroup_v2_session *session);

/* cgroup.kill is required; missing support returns -ENOTSUP. */
int dl_linux_cgroup_v2_session_kill_all(
    const dl_linux_cgroup_v2_session *session);
int dl_linux_cgroup_v2_session_kill_all_with_io(
    const dl_linux_cgroup_v2_session *session,
    const dl_linux_cgroup_v2_kill_io *io);

/* Removes only the exact child created by session_create. If it is still
 * populated, returns -EBUSY and retains the handles for a later retry. */
int dl_linux_cgroup_v2_session_close(dl_linux_cgroup_v2_session *session);

#ifdef __cplusplus
}
#endif
#endif
