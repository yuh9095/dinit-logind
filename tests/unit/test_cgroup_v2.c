/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "cgroup_v2.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void expect_parse_error(const char *contents, int expected)
{
    char path[256];
    assert(dl_linux_cgroup_v2_parse_self_cgroup(contents, path,
                                                 sizeof(path)) == expected);
    assert(path[0] == '\0');
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

    puts("Linux cgroup v2 path and fail-closed tests: ok");
    return 0;
}
