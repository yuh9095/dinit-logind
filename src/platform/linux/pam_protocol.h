/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_PAM_PROTOCOL_H
#define DINIT_LOGIND_PAM_PROTOCOL_H

#include <stdint.h>

#define DL_PAM_PROTOCOL_MAGIC 0x444c5041u
#define DL_PAM_RESPONSE_MAGIC 0x444c5052u
#define DL_PAM_PROTOCOL_VERSION 1u
#define DL_PAM_SOCKET_DEFAULT "/run/dinit-logind/pam.sock"
#define DL_PAM_FIELD_MAX 128u
#define DL_PAM_SESSION_ID_MAX 32u

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t uid;
    uint32_t vtnr;
    uint8_t remote;
    uint8_t reserved[7];
    char service[DL_PAM_FIELD_MAX];
    char tty[DL_PAM_FIELD_MAX];
    char ruser[DL_PAM_FIELD_MAX];
    char rhost[DL_PAM_FIELD_MAX];
    char display[DL_PAM_FIELD_MAX];
    char type[DL_PAM_FIELD_MAX];
    char session_class[DL_PAM_FIELD_MAX];
} dl_pam_open_request;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t status;
    char session_id[DL_PAM_SESSION_ID_MAX];
} dl_pam_open_response;

#endif
