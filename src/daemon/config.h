/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_DAEMON_CONFIG_H
#define DINIT_LOGIND_DAEMON_CONFIG_H

#include <stdint.h>

typedef struct {
    uint32_t allowed_peer_uid;
    uint32_t session_terminate_timeout_sec;
} dl_daemon_config;

void dl_daemon_config_defaults(dl_daemon_config *config);
int dl_daemon_config_load(const char *path, dl_daemon_config *config);

#endif
