/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "cgroup_v2.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static void expect_parse_error(const char *contents, int expected)
{
    char path[256];
    assert(dl_linux_cgroup_v2_parse_self_cgroup(contents, path,
                                                 sizeof(path)) == expected);
    assert(path[0] == '\0');
}


static pid_t spawn_waiter(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) pause();
    }
    return pid;
}

static void stop_and_reap(pid_t pid)
{
    int status;
    if (pid <= 0) return;
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

static void test_session_signal_tree(void)
{
    dl_linux_cgroup_v2 parent = {-1, {0}};
    dl_linux_cgroup_v2_session session = {-1, -1, {0}};
    dl_process_identity first_identity, second_identity;
    pid_t first = -1, second = -1;
    int result, status;
    bool nested_created = false;

    if (dl_linux_cgroup_v2_open_current(&parent) < 0) return;
    first = spawn_waiter();
    second = spawn_waiter();
    if (first <= 0 || second <= 0) goto out;
    if (dl_linux_process_identity_read((uint32_t)first, &first_identity) != DL_OK)
        goto out;
    if (dl_linux_process_identity_read((uint32_t)second, &second_identity) != DL_OK)
        goto out;

    result = dl_linux_cgroup_v2_session_create(
        &parent, "test-session-signal-tree", &first_identity, &session);
    /* CI hosts commonly expose cgroup v2 without delegating a writable
     * subtree. That is an expected skip, not a test failure. */
    if (result < 0) goto out;

    if (mkdirat(session.fd, "nested", 0755) == 0) {
        int nested_fd = openat(session.fd, "nested",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nested_fd >= 0) {
            int procs_fd = openat(nested_fd, "cgroup.procs",
                O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
            if (procs_fd >= 0) {
                char pid_text[32];
                int n = snprintf(pid_text, sizeof(pid_text), "%ld",
                                 (long)second);
                if (n > 0 && (size_t)n < sizeof(pid_text) &&
                    write(procs_fd, pid_text, (size_t)n) == n)
                    nested_created = true;
                (void)close(procs_fd);
            }
            (void)close(nested_fd);
        }
    }

    result = dl_linux_cgroup_v2_session_signal_all(&session, SIGTERM);
    assert(result == 0);
    assert(waitpid(first, &status, 0) == first);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    first = -1;

    if (nested_created) {
        assert(waitpid(second, &status, 0) == second);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
        second = -1;
        assert(unlinkat(session.fd, "nested", AT_REMOVEDIR) == 0);
    } else {
        /* If the host disallows nested cgroups, still exercise signaling
         * of a process in the session's direct cgroup. */
        char pid_text[32];
        int fd = openat(session.fd, "cgroup.procs",
                        O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            int n = snprintf(pid_text, sizeof(pid_text), "%ld", (long)second);
            if (n > 0 && (size_t)n < sizeof(pid_text))
                (void)write(fd, pid_text, (size_t)n);
            (void)close(fd);
            result = dl_linux_cgroup_v2_session_signal_all(&session, SIGTERM);
            if (result == 0) {
                assert(waitpid(second, &status, 0) == second);
                assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
                second = -1;
            }
        }
    }
    (void)dl_linux_cgroup_v2_session_close(&session);
out:
    stop_and_reap(first);
    stop_and_reap(second);
    if (session.fd >= 0) dl_linux_cgroup_v2_session_release(&session);
    dl_linux_cgroup_v2_close(&parent);
}

int main(void)
{
    char path[256];
    dl_linux_cgroup_v2 current = {-1, {0}};

    assert(dl_linux_cgroup_v2_parse_self_cgroup(
        "2:cpu:/legacy\n0::/dinit/logind\n",
        path, sizeof(path)) == 0);
    assert(strcmp(path, "/dinit/logind") == 0);

    expect_parse_error("2:cpu:/legacy\n", -ENOTSUP);
    expect_parse_error("0::/\n", -EINVAL);
    expect_parse_error("0::/../../outside\n", -EINVAL);
    expect_parse_error("0::/safe//empty\n", -EINVAL);
    expect_parse_error("0::/safe/\n", -EINVAL);
    expect_parse_error("0::/safe\n0::/other\n", -EINVAL);
    expect_parse_error("0:cpu:/not-unified\n", -ENOTSUP);

    /* The host/container may expose cgroup v1, a read-only cgroup2 mount, or
     * no delegated service subtree. All are valid fail-closed outcomes. */
    {
        int result = dl_linux_cgroup_v2_open_current(&current);
        if (result == 0) {
            assert(current.fd >= 0);
            assert(current.path[0] == '/');
            assert(strcmp(current.path, "/") != 0);
            dl_linux_cgroup_v2_close(&current);
        } else {
            assert(result < 0);
            assert(current.fd == -1);
            assert(current.path[0] == '\0');
        }
    }

    test_session_signal_tree();
    puts("Linux cgroup v2 path, session signal tree, and fail-closed tests: ok");
    return 0;
}
