/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_CORE_H
#define DINIT_LOGIND_CORE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DL_SESSION_ID_MAX 32
#define DL_METADATA_MAX 128

typedef struct dl_manager dl_manager;
typedef struct dl_user dl_user;
typedef struct dl_session dl_session;

typedef enum {
    DL_OK = 0,
    DL_ERR_INVALID,
    DL_ERR_NOT_FOUND,
    DL_ERR_NOMEM,
    DL_ERR_CONFLICT,
    DL_ERR_STATE
} dl_result;

typedef enum {
    DL_SESSION_OPEN = 0,
    DL_SESSION_ACTIVE,
    DL_SESSION_CLOSED
} dl_session_state;

/* Must be populated from authenticated peer credentials and verified by the
 * Linux adapter. PID alone is deliberately insufficient. */
typedef struct {
    uint32_t pid;
    uint64_t pid_namespace_inode;
    uint64_t process_start_time;
} dl_process_identity;

typedef struct {
    uint32_t uid;
    dl_process_identity leader;
    const char *seat;
    uint32_t vtnr;
    const char *tty;
    const char *display;
    const char *service;
    const char *type;
    const char *session_class;
    bool remote;
    const char *remote_user;
    const char *remote_host;
} dl_session_spec;

/* All returned object pointers are borrowed from manager and remain valid
 * until dl_manager_destroy(). Calls must be serialized on one owner thread. */
dl_manager *dl_manager_new(void);
void dl_manager_destroy(dl_manager *manager);

dl_result dl_session_create(dl_manager *manager, const dl_session_spec *spec,
                            dl_session **out_session);
dl_result dl_session_close(dl_manager *manager, const char *session_id);
dl_result dl_session_activate(dl_manager *manager, const char *session_id);

dl_session *dl_session_find(dl_manager *manager, const char *session_id);
dl_session *dl_session_find_by_identity(dl_manager *manager,
                                        const dl_process_identity *identity);

const char *dl_session_id(const dl_session *session);
uint32_t dl_session_uid(const dl_session *session);
dl_process_identity dl_session_leader(const dl_session *session);
dl_session_state dl_session_get_state(const dl_session *session);
const char *dl_session_seat(const dl_session *session);
uint32_t dl_session_vtnr(const dl_session *session);
const char *dl_session_tty(const dl_session *session);
const char *dl_session_display(const dl_session *session);
const char *dl_session_service(const dl_session *session);
const char *dl_session_type(const dl_session *session);
const char *dl_session_class(const dl_session *session);
bool dl_session_is_remote(const dl_session *session);
const char *dl_session_remote_user(const dl_session *session);
const char *dl_session_remote_host(const dl_session *session);

dl_result dl_user_set_linger(dl_manager *manager, uint32_t uid, bool enabled);
const dl_user *dl_user_find(const dl_manager *manager, uint32_t uid);
bool dl_user_linger_enabled(const dl_user *user);
uint32_t dl_user_active_session_count(const dl_user *user);

#ifdef __cplusplus
}
#endif

#endif
