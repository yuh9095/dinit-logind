/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dl_user {
    uint32_t uid;
    bool linger;
    uint32_t active_sessions;
    struct dl_user *next;
};

struct dl_session {
    char id[DL_SESSION_ID_MAX];
    uint32_t uid;
    dl_process_identity leader;
    dl_session_state state;
    char seat[DL_METADATA_MAX];
    uint32_t vtnr;
    char tty[DL_METADATA_MAX];
    char display[DL_METADATA_MAX];
    char service[DL_METADATA_MAX];
    char type[DL_METADATA_MAX];
    char session_class[DL_METADATA_MAX];
    bool remote;
    char remote_user[DL_METADATA_MAX];
    char remote_host[DL_METADATA_MAX];
    struct dl_user *user;
    struct dl_session *next;
};

struct dl_manager {
    struct dl_user *users;
    struct dl_session *sessions;
    uint64_t next_session_number;
};

static struct dl_user *find_user_mut(dl_manager *manager, uint32_t uid)
{
    struct dl_user *user;
    for (user = manager->users; user != NULL; user = user->next) {
        if (user->uid == uid) return user;
    }
    return NULL;
}

static struct dl_user *get_or_create_user(dl_manager *manager, uint32_t uid)
{
    struct dl_user *user = find_user_mut(manager, uid);
    if (user != NULL) return user;
    user = calloc(1, sizeof(*user));
    if (user == NULL) return NULL;
    user->uid = uid;
    user->next = manager->users;
    manager->users = user;
    return user;
}

static bool valid_text(const char *value)
{
    const unsigned char *p;
    size_t length;
    if (value == NULL) return true;
    length = strlen(value);
    if (length >= DL_METADATA_MAX) return false;
    for (p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (*p < 0x20 || *p == 0x7f) return false;
    }
    return true;
}

static bool copy_text(char destination[DL_METADATA_MAX], const char *source)
{
    size_t length;
    if (source == NULL) {
        destination[0] = '\0';
        return true;
    }
    length = strlen(source);
    if (length >= DL_METADATA_MAX) return false;
    memcpy(destination, source, length + 1);
    return true;
}

static bool valid_identity(const dl_process_identity *identity)
{
    return identity != NULL && identity->pid != 0 &&
           identity->pid_namespace_inode != 0;
}

static bool same_identity(const dl_process_identity *a,
                          const dl_process_identity *b)
{
    return a->pid == b->pid &&
           a->pid_namespace_inode == b->pid_namespace_inode &&
           a->process_start_time == b->process_start_time;
}

dl_manager *dl_manager_new(void)
{
    return calloc(1, sizeof(dl_manager));
}

void dl_manager_destroy(dl_manager *manager)
{
    struct dl_session *session;
    struct dl_user *user;
    if (manager == NULL) return;
    session = manager->sessions;
    while (session != NULL) {
        struct dl_session *next = session->next;
        free(session);
        session = next;
    }
    user = manager->users;
    while (user != NULL) {
        struct dl_user *next = user->next;
        free(user);
        user = next;
    }
    free(manager);
}

dl_result dl_session_create(dl_manager *manager, const dl_session_spec *spec,
                            dl_session **out_session)
{
    struct dl_session *session;
    struct dl_user *user;
    if (out_session != NULL) *out_session = NULL;
    if (manager == NULL || spec == NULL || out_session == NULL ||
        !valid_identity(&spec->leader) ||
        !valid_text(spec->seat) || !valid_text(spec->tty) ||
        !valid_text(spec->display) || !valid_text(spec->service) ||
        !valid_text(spec->type) || !valid_text(spec->session_class) ||
        !valid_text(spec->remote_user) || !valid_text(spec->remote_host)) {
        return DL_ERR_INVALID;
    }
    for (session = manager->sessions; session != NULL; session = session->next) {
        if (session->state != DL_SESSION_CLOSED &&
            same_identity(&session->leader, &spec->leader)) {
            return DL_ERR_CONFLICT;
        }
    }
    if (manager->next_session_number == UINT64_MAX) return DL_ERR_STATE;
    user = get_or_create_user(manager, spec->uid);
    if (user == NULL) return DL_ERR_NOMEM;
    session = calloc(1, sizeof(*session));
    if (session == NULL) return DL_ERR_NOMEM;

    ++manager->next_session_number;
    (void)snprintf(session->id, sizeof(session->id), "session-%llu",
                   (unsigned long long)manager->next_session_number);
    session->uid = spec->uid;
    session->leader = spec->leader;
    session->state = DL_SESSION_OPEN;
    session->vtnr = spec->vtnr;
    session->remote = spec->remote;
    session->user = user;
    if (!copy_text(session->seat, spec->seat) ||
        !copy_text(session->tty, spec->tty) ||
        !copy_text(session->display, spec->display) ||
        !copy_text(session->service, spec->service) ||
        !copy_text(session->type, spec->type) ||
        !copy_text(session->session_class, spec->session_class) ||
        !copy_text(session->remote_user, spec->remote_user) ||
        !copy_text(session->remote_host, spec->remote_host)) {
        free(session);
        return DL_ERR_INVALID;
    }
    session->next = manager->sessions;
    manager->sessions = session;
    ++user->active_sessions;
    *out_session = session;
    return DL_OK;
}

dl_session *dl_session_find(dl_manager *manager, const char *session_id)
{
    struct dl_session *session;
    if (manager == NULL || session_id == NULL) return NULL;
    for (session = manager->sessions; session != NULL; session = session->next) {
        if (strcmp(session->id, session_id) == 0) return session;
    }
    return NULL;
}

dl_session *dl_session_find_by_identity(dl_manager *manager,
                                        const dl_process_identity *identity)
{
    struct dl_session *session;
    if (manager == NULL || !valid_identity(identity)) return NULL;
    for (session = manager->sessions; session != NULL; session = session->next) {
        if (session->state != DL_SESSION_CLOSED &&
            same_identity(&session->leader, identity)) return session;
    }
    return NULL;
}

dl_result dl_session_close(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED) return DL_OK;
    session->state = DL_SESSION_CLOSED;
    if (session->user->active_sessions > 0) --session->user->active_sessions;
    return DL_OK;
}

dl_result dl_session_activate(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED) return DL_ERR_STATE;
    session->state = DL_SESSION_ACTIVE;
    return DL_OK;
}

const char *dl_session_id(const dl_session *s) { return s == NULL ? NULL : s->id; }
uint32_t dl_session_uid(const dl_session *s) { return s == NULL ? 0 : s->uid; }
dl_process_identity dl_session_leader(const dl_session *s)
{
    dl_process_identity empty = {0, 0, 0};
    return s == NULL ? empty : s->leader;
}
dl_session_state dl_session_get_state(const dl_session *s)
{
    return s == NULL ? DL_SESSION_CLOSED : s->state;
}
const char *dl_session_seat(const dl_session *s) { return s == NULL ? NULL : s->seat; }
uint32_t dl_session_vtnr(const dl_session *s) { return s == NULL ? 0 : s->vtnr; }
const char *dl_session_tty(const dl_session *s) { return s == NULL ? NULL : s->tty; }
const char *dl_session_display(const dl_session *s) { return s == NULL ? NULL : s->display; }
const char *dl_session_service(const dl_session *s) { return s == NULL ? NULL : s->service; }
const char *dl_session_type(const dl_session *s) { return s == NULL ? NULL : s->type; }
const char *dl_session_class(const dl_session *s) { return s == NULL ? NULL : s->session_class; }
bool dl_session_is_remote(const dl_session *s) { return s != NULL && s->remote; }
const char *dl_session_remote_user(const dl_session *s) { return s == NULL ? NULL : s->remote_user; }
const char *dl_session_remote_host(const dl_session *s) { return s == NULL ? NULL : s->remote_host; }

dl_result dl_user_set_linger(dl_manager *manager, uint32_t uid, bool enabled)
{
    struct dl_user *user;
    if (manager == NULL) return DL_ERR_INVALID;
    user = get_or_create_user(manager, uid);
    if (user == NULL) return DL_ERR_NOMEM;
    user->linger = enabled;
    return DL_OK;
}

const dl_user *dl_user_find(const dl_manager *manager, uint32_t uid)
{
    const struct dl_user *user;
    if (manager == NULL) return NULL;
    for (user = manager->users; user != NULL; user = user->next) {
        if (user->uid == uid) return user;
    }
    return NULL;
}

bool dl_user_linger_enabled(const dl_user *user)
{
    return user != NULL && user->linger;
}

uint32_t dl_user_active_session_count(const dl_user *user)
{
    return user == NULL ? 0 : user->active_sessions;
}
