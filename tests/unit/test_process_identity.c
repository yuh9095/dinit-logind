/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "process_identity.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
int main(void)
{
    dl_process_identity identity = {0, 0, 0};
    dl_process_identity invalid = {1, 1, 1};
    assert(dl_linux_process_identity_read((uint32_t)getpid(), &identity) == DL_OK);
    assert(identity.pid == (uint32_t)getpid());
    assert(identity.pid_namespace_inode != 0);
    assert(dl_linux_process_identity_read(0, &invalid) == DL_ERR_INVALID);
    assert(invalid.pid == 0);
    assert(dl_linux_process_identity_read(UINT32_MAX, &invalid) == DL_ERR_INVALID);
    assert(invalid.pid == 0);
    assert(dl_linux_process_identity_read((uint32_t)getpid(), NULL) == DL_ERR_INVALID);
    puts("process identity tests: ok");
    return 0;
}
