/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_CORE_H
#define DINIT_LOGIND_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DL_SESSION_ID_MAX 32
#define DL_METADATA_MAX 128
#define DL_EVENT_HISTORY_MAX 256

typedef struct dl_manager dl_manager;
typedef struct dl_user dl_user;
typedef struct dl_session dl_session;
typedef struct dl_seat dl_seat;

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

typedef enum {
    DL_EVENT_NONE = 0,
    DL_EVENT_OVERFLOW,
    DL_EVENT_USER_ADDED,
    DL_EVENT_SEAT_ADDED,
    DL_EVENT_SESSION_ADDED,
    DL_EVENT_SESSION_STATE_CHANGED,
    DL_EVENT_SESSION_REMOVED,
    DL_EVENT_SEAT_ACTIVE_SESSION_CHANGED,
    DL_EVENT_USER_LINGER_CHANGED
} dl_event_type;

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

typedef struct {
    uint64_t generation;
    dl_event_type type;
    uint32_t uid;
    dl_session_state old_state;
    dl_session_state new_state;
    char session_id[DL_SESSION_ID_MAX];
    char seat_id[DL_METADATA_MAX];
    char active_session_id[DL_SESSION_ID_MAX];
} dl_event;

dl_manager *dl_manager_new(void);
void dl_manager_destroy(dl_manager *manager);

dl_result dl_session_create(dl_manager *manager, const dl_session_spec *spec,
                            dl_session **out_session);
dl_result dl_session_close(dl_manager *manager, const char *session_id);
dl_result dl_session_activate(dl_manager *manager, const char *session_id);
dl_result dl_session_deactivate(dl_manager *manager, const char *session_id);
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

/* Enumeration is stable only until the next manager mutation. */
size_t dl_manager_user_count(const dl_manager *manager);
const dl_user *dl_manager_user_at(const dl_manager *manager, size_t index);
size_t dl_manager_seat_count(const dl_manager *manager);
const dl_seat *dl_manager_seat_at(const dl_manager *manager, size_t index);
size_t dl_manager_session_count(const dl_manager *manager);
const dl_session *dl_manager_session_at(const dl_manager *manager, size_t index);

const dl_seat *dl_seat_find(const dl_manager *manager, const char *seat_id);
const char *dl_seat_id(const dl_seat *seat);
const char *dl_seat_active_session_id(const dl_seat *seat);
uint32_t dl_seat_session_count(const dl_seat *seat);

dl_result dl_user_set_linger(dl_manager *manager, uint32_t uid, bool enabled);
const dl_user *dl_user_find(const dl_manager *manager, uint32_t uid);
uint32_t dl_user_uid(const dl_user *user);
bool dl_user_linger_enabled(const dl_user *user);
uint32_t dl_user_session_count(const dl_user *user);
uint32_t dl_user_active_session_count(const dl_user *user);

/* Bounded, non-destructive event journal. Each subscriber keeps a cursor.
 * DL_ERR_NOT_FOUND means no new event. DL_ERR_STATE with OVERFLOW means the
 * cursor fell behind retained history; resnapshot and resume at generation. */
uint64_t dl_manager_event_generation(const dl_manager *manager);
dl_result dl_manager_next_event(const dl_manager *manager,
                                uint64_t after_generation,
                                dl_event *out_event);

#ifdef __cplusplus
}
#endif
#endif
