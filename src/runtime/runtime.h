/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_RUNTIME_H
#define DINIT_LOGIND_RUNTIME_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "../core/core.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    const char *runtime_base;
    const char *linger_directory;
    uid_t trusted_owner;
} dl_runtime_paths;
dl_result dl_runtime_prepare_user(const dl_runtime_paths *paths,
                                  uint32_t uid, uint32_t gid,
                                  char *out_path, size_t out_path_size);
/* Removes only an empty, correctly-owned runtime directory. */
dl_result dl_runtime_cleanup_user(const dl_runtime_paths *paths, uint32_t uid);
dl_result dl_runtime_set_linger(const dl_runtime_paths *paths,
                                uint32_t uid, bool enabled);
dl_result dl_runtime_get_linger(const dl_runtime_paths *paths,
                                uint32_t uid, bool *enabled);
#ifdef __cplusplus
}
#endif
#endif
