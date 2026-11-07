/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "process_identity.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void)
{
    dl_process_identity identity = {0, 0, 0};
    dl_process_identity invalid = {1, 1, 1};
    char original_name[16] = {0};

    assert(prctl(PR_GET_NAME, original_name, 0, 0, 0) == 0);
    assert(dl_linux_process_identity_read((uint32_t)getpid(), &identity) == DL_OK);
    assert(identity.pid == (uint32_t)getpid());
    assert(identity.pid_namespace_inode != 0);
    assert(identity.process_start_time != 0);

    /*
     * Linux task comm is allowed to contain spaces and closing parentheses.
     * This exercises the /proc/PID/stat field-2 delimiter handling.
     */
    assert(prctl(PR_SET_NAME, "dl ) stat test", 0, 0, 0) == 0);
    assert(dl_linux_process_identity_read((uint32_t)getpid(), &identity) == DL_OK);
    assert(identity.pid == (uint32_t)getpid());
    assert(identity.pid_namespace_inode != 0);
    assert(identity.process_start_time != 0);
    assert(prctl(PR_SET_NAME, original_name, 0, 0, 0) == 0);

    assert(dl_linux_process_identity_read(0, &invalid) == DL_ERR_INVALID);
    assert(invalid.pid == 0);
    assert(dl_linux_process_identity_read(UINT32_MAX, &invalid) == DL_ERR_INVALID);
    assert(invalid.pid == 0);
    assert(dl_linux_process_identity_read((uint32_t)INT_MAX, &invalid) == DL_ERR_NOT_FOUND);
    assert(invalid.pid == 0);
    assert(dl_linux_process_identity_read((uint32_t)getpid(), NULL) == DL_ERR_INVALID);

    puts("process identity tests: ok");
    return 0;
}
