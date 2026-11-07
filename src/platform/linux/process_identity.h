/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_LINUX_PROCESS_IDENTITY_H
#define DINIT_LOGIND_LINUX_PROCESS_IDENTITY_H
#include <stdint.h>
#include "../../core/core.h"
#ifdef __cplusplus
extern "C" {
#endif
/* PID must come from authenticated transport credentials such as SO_PEERCRED. */
dl_result dl_linux_process_identity_read(uint32_t pid, dl_process_identity *identity);
#ifdef __cplusplus
}
#endif
#endif
