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
    uint32_t sessions;
    uint32_t active_sessions;
    struct dl_user *next;
};

struct dl_seat {
    char id[DL_METADATA_MAX];
    struct dl_session *active_session;
    uint32_t sessions;
    struct dl_seat *next;
};

struct dl_session {
    char id[DL_SESSION_ID_MAX];
    uint32_t uid;
    dl_process_identity leader;
    dl_session_state state;
    bool stopping;
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
    struct dl_seat *seat_object;
    struct dl_session *next;
};

struct dl_manager {
    struct dl_user *users;
    struct dl_seat *seats;
    struct dl_session *sessions;
    uint64_t next_session_number;
    uint64_t event_generation;
    dl_event events[DL_EVENT_HISTORY_MAX];
};

static void event_push(dl_manager *manager, dl_event *event)
{
    uint64_t generation = ++manager->event_generation;
    event->generation = generation;
    manager->events[(generation - 1) % DL_EVENT_HISTORY_MAX] = *event;
}

static void event_simple(dl_manager *manager, dl_event_type type, uint32_t uid)
{
    dl_event event = {0};
    event.type = type;
    event.uid = uid;
    event_push(manager, &event);
}

static void event_session_state(dl_manager *manager,
                                const struct dl_session *session,
                                dl_session_state old_state)
{
    dl_event event = {0};
    event.type = DL_EVENT_SESSION_STATE_CHANGED;
    event.uid = session->uid;
    event.old_state = old_state;
    event.new_state = session->state;
    (void)snprintf(event.session_id, sizeof(event.session_id), "%s", session->id);
    if (session->seat_object != NULL)
        (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s",
                       session->seat_object->id);
    event_push(manager, &event);
}

static void event_session_removed(dl_manager *manager,
                                  const struct dl_session *session)
{
    dl_event event = {0};
    event.type = DL_EVENT_SESSION_REMOVED;
    event.uid = session->uid;
    event.old_state = DL_SESSION_CLOSED;
    event.new_state = DL_SESSION_CLOSED;
    (void)snprintf(event.session_id, sizeof(event.session_id), "%s", session->id);
    if (session->seat_object != NULL)
        (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s",
                       session->seat_object->id);
    event_push(manager, &event);
}

static void event_seat_active(dl_manager *manager, const struct dl_seat *seat)
{
    dl_event event = {0};
    event.type = DL_EVENT_SEAT_ACTIVE_SESSION_CHANGED;
    (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s", seat->id);
    if (seat->active_session != NULL) {
        event.uid = seat->active_session->uid;
        (void)snprintf(event.active_session_id, sizeof(event.active_session_id),
                       "%s", seat->active_session->id);
    }
    event_push(manager, &event);
}

static struct dl_user *find_user_mut(dl_manager *manager, uint32_t uid)
{
    struct dl_user *user;
    for (user = manager->users; user != NULL; user = user->next)
        if (user->uid == uid) return user;
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
    event_simple(manager, DL_EVENT_USER_ADDED, uid);
    return user;
}

static struct dl_seat *find_seat_mut(dl_manager *manager, const char *seat_id)
{
    struct dl_seat *seat;
    if (seat_id == NULL || seat_id[0] == '\0') return NULL;
    for (seat = manager->seats; seat != NULL; seat = seat->next)
        if (strcmp(seat->id, seat_id) == 0) return seat;
    return NULL;
}

static struct dl_seat *get_or_create_seat(dl_manager *manager,
                                          const char *seat_id)
{
    struct dl_seat *seat;
    size_t length;
    if (seat_id == NULL || seat_id[0] == '\0') return NULL;
    seat = find_seat_mut(manager, seat_id);
    if (seat != NULL) return seat;
    length = strlen(seat_id);
    if (length >= DL_METADATA_MAX) return NULL;
    seat = calloc(1, sizeof(*seat));
    if (seat == NULL) return NULL;
    memcpy(seat->id, seat_id, length + 1);
    seat->next = manager->seats;
    manager->seats = seat;
    {
        dl_event event = {0};
        event.type = DL_EVENT_SEAT_ADDED;
        (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s", seat->id);
        event_push(manager, &event);
    }
    return seat;
}

static bool valid_text(const char *value)
{
    const unsigned char *p;
    size_t length;
    if (value == NULL) return true;
    length = strlen(value);
    if (length >= DL_METADATA_MAX) return false;
    for (p = (const unsigned char *)value; *p != '\0'; ++p)
        if (*p < 0x20 || *p == 0x7f) return false;
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
    struct dl_seat *seat;
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
    seat = manager->seats;
    while (seat != NULL) {
        struct dl_seat *next = seat->next;
        free(seat);
        seat = next;
    }
    free(manager);
}

dl_result dl_session_create(dl_manager *manager, const dl_session_spec *spec,
                            dl_session **out_session)
{
    struct dl_session *session;
    struct dl_user *user;
    struct dl_seat *seat = NULL;
    if (out_session != NULL) *out_session = NULL;
    if (manager == NULL || spec == NULL || out_session == NULL ||
        !valid_identity(&spec->leader) ||
        !valid_text(spec->seat) || !valid_text(spec->tty) ||
        !valid_text(spec->display) || !valid_text(spec->service) ||
        !valid_text(spec->type) || !valid_text(spec->session_class) ||
        !valid_text(spec->remote_user) || !valid_text(spec->remote_host))
        return DL_ERR_INVALID;

    for (session = manager->sessions; session != NULL; session = session->next)
        if (session->state != DL_SESSION_CLOSED &&
            same_identity(&session->leader, &spec->leader))
            return DL_ERR_CONFLICT;
    if (manager->next_session_number == UINT64_MAX) return DL_ERR_STATE;

    session = calloc(1, sizeof(*session));
    if (session == NULL) return DL_ERR_NOMEM;
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

    user = get_or_create_user(manager, spec->uid);
    if (user == NULL) {
        free(session);
        return DL_ERR_NOMEM;
    }
    if (user->sessions == UINT32_MAX) {
        free(session);
        return DL_ERR_STATE;
    }
    if (session->seat[0] != '\0') {
        seat = get_or_create_seat(manager, session->seat);
        if (seat == NULL) {
            free(session);
            return DL_ERR_NOMEM;
        }
        if (seat->sessions == UINT32_MAX) {
            free(session);
            return DL_ERR_STATE;
        }
    }

    ++manager->next_session_number;
    (void)snprintf(session->id, sizeof(session->id), "session-%llu",
                   (unsigned long long)manager->next_session_number);
    session->uid = spec->uid;
    session->leader = spec->leader;
    session->state = DL_SESSION_OPEN;
    session->vtnr = spec->vtnr;
    session->remote = spec->remote;
    session->user = user;
    session->seat_object = seat;
    session->next = manager->sessions;
    manager->sessions = session;
    ++user->sessions;
    if (seat != NULL) ++seat->sessions;

    {
        dl_event event = {0};
        event.type = DL_EVENT_SESSION_ADDED;
        event.uid = session->uid;
        event.new_state = session->state;
        (void)snprintf(event.session_id, sizeof(event.session_id), "%s",
                       session->id);
        if (seat != NULL)
            (void)snprintf(event.seat_id, sizeof(event.seat_id), "%s", seat->id);
        event_push(manager, &event);
    }
    *out_session = session;
    return DL_OK;
}

dl_session *dl_session_find(dl_manager *manager, const char *session_id)
{
    struct dl_session *session;
    if (manager == NULL || session_id == NULL) return NULL;
    for (session = manager->sessions; session != NULL; session = session->next)
        if (strcmp(session->id, session_id) == 0) return session;
    return NULL;
}

dl_session *dl_session_find_by_identity(dl_manager *manager,
                                        const dl_process_identity *identity)
{
    struct dl_session *session;
    if (manager == NULL || !valid_identity(identity)) return NULL;
    for (session = manager->sessions; session != NULL; session = session->next)
        if (session->state != DL_SESSION_CLOSED &&
            same_identity(&session->leader, identity)) return session;
    return NULL;
}

dl_result dl_session_close(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    dl_session_state old_state;
    bool seat_active;
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED) return DL_OK;
    old_state = session->state;
    seat_active = session->seat_object != NULL &&
                  session->seat_object->active_session == session;
    if (session->seat_object != NULL) {
        if (seat_active) session->seat_object->active_session = NULL;
        if (session->seat_object->sessions > 0) --session->seat_object->sessions;
    }
    session->state = DL_SESSION_CLOSED;
    if (session->user->sessions > 0) --session->user->sessions;
    if (old_state == DL_SESSION_ACTIVE && session->user->active_sessions > 0)
        --session->user->active_sessions;
    event_session_state(manager, session, old_state);
    if (seat_active) event_seat_active(manager, session->seat_object);
    event_session_removed(manager, session);
    return DL_OK;
}

dl_result dl_session_begin_stop(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED) return DL_ERR_STATE;
    if (session->stopping) return DL_OK;
    session->stopping = true;
    event_session_state(manager, session, session->state);
    return DL_OK;
}

bool dl_session_is_stopping(const dl_session *session)
{
    return session != NULL && session->stopping;
}

dl_result dl_session_activate(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED || session->stopping)
        return DL_ERR_STATE;
    if (session->state == DL_SESSION_ACTIVE &&
        (session->seat_object == NULL ||
         session->seat_object->active_session == session))
        return DL_OK;

    if (session->seat_object != NULL &&
        session->seat_object->active_session != session) {
        struct dl_session *previous = session->seat_object->active_session;
        if (previous != NULL) {
            previous->state = DL_SESSION_OPEN;
            if (previous->user->active_sessions > 0)
                --previous->user->active_sessions;
            event_session_state(manager, previous, DL_SESSION_ACTIVE);
        }
        session->seat_object->active_session = session;
    }
    {
        dl_session_state old_state = session->state;
        session->state = DL_SESSION_ACTIVE;
        if (old_state != DL_SESSION_ACTIVE) {
            ++session->user->active_sessions;
            event_session_state(manager, session, old_state);
        }
    }
    if (session->seat_object != NULL)
        event_seat_active(manager, session->seat_object);
    return DL_OK;
}

dl_result dl_session_deactivate(dl_manager *manager, const char *session_id)
{
    struct dl_session *session = dl_session_find(manager, session_id);
    bool seat_active;
    if (session == NULL) return DL_ERR_NOT_FOUND;
    if (session->state == DL_SESSION_CLOSED || session->stopping)
        return DL_ERR_STATE;
    seat_active = session->seat_object != NULL &&
                  session->seat_object->active_session == session;
    if (session->state == DL_SESSION_ACTIVE) {
        session->state = DL_SESSION_OPEN;
        if (session->user->active_sessions > 0)
            --session->user->active_sessions;
        event_session_state(manager, session, DL_SESSION_ACTIVE);
    }
    if (seat_active) {
        session->seat_object->active_session = NULL;
        event_seat_active(manager, session->seat_object);
    }
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
const char *dl_session_seat(const dl_session *s) { return s == NULL ? NULL : (s->seat[0] ? s->seat : NULL); }
uint32_t dl_session_vtnr(const dl_session *s) { return s == NULL ? 0 : s->vtnr; }
const char *dl_session_tty(const dl_session *s) { return s == NULL ? NULL : (s->tty[0] ? s->tty : NULL); }
const char *dl_session_display(const dl_session *s) { return s == NULL ? NULL : (s->display[0] ? s->display : NULL); }
const char *dl_session_service(const dl_session *s) { return s == NULL ? NULL : (s->service[0] ? s->service : NULL); }
const char *dl_session_type(const dl_session *s) { return s == NULL ? NULL : (s->type[0] ? s->type : NULL); }
const char *dl_session_class(const dl_session *s) { return s == NULL ? NULL : (s->session_class[0] ? s->session_class : NULL); }
bool dl_session_is_remote(const dl_session *s) { return s != NULL && s->remote; }
const char *dl_session_remote_user(const dl_session *s) { return s == NULL ? NULL : (s->remote_user[0] ? s->remote_user : NULL); }
const char *dl_session_remote_host(const dl_session *s) { return s == NULL ? NULL : (s->remote_host[0] ? s->remote_host : NULL); }

size_t dl_manager_user_count(const dl_manager *manager)
{
    const struct dl_user *u;
    size_t count = 0;
    if (manager == NULL) return 0;
    for (u = manager->users; u != NULL; u = u->next) ++count;
    return count;
}
const dl_user *dl_manager_user_at(const dl_manager *manager, size_t index)
{
    const struct dl_user *u;
    if (manager == NULL) return NULL;
    for (u = manager->users; u != NULL; u = u->next)
        if (index-- == 0) return u;
    return NULL;
}
size_t dl_manager_seat_count(const dl_manager *manager)
{
    const struct dl_seat *s;
    size_t count = 0;
    if (manager == NULL) return 0;
    for (s = manager->seats; s != NULL; s = s->next) ++count;
    return count;
}
const dl_seat *dl_manager_seat_at(const dl_manager *manager, size_t index)
{
    const struct dl_seat *s;
    if (manager == NULL) return NULL;
    for (s = manager->seats; s != NULL; s = s->next)
        if (index-- == 0) return s;
    return NULL;
}
size_t dl_manager_session_count(const dl_manager *manager)
{
    const struct dl_session *s;
    size_t count = 0;
    if (manager == NULL) return 0;
    for (s = manager->sessions; s != NULL; s = s->next)
        if (s->state != DL_SESSION_CLOSED) ++count;
    return count;
}
const dl_session *dl_manager_session_at(const dl_manager *manager, size_t index)
{
    const struct dl_session *s;
    if (manager == NULL) return NULL;
    for (s = manager->sessions; s != NULL; s = s->next) {
        if (s->state == DL_SESSION_CLOSED) continue;
        if (index-- == 0) return s;
    }
    return NULL;
}

const dl_seat *dl_seat_find(const dl_manager *manager, const char *seat_id)
{
    const struct dl_seat *seat;
    if (manager == NULL || seat_id == NULL) return NULL;
    for (seat = manager->seats; seat != NULL; seat = seat->next)
        if (strcmp(seat->id, seat_id) == 0) return seat;
    return NULL;
}
const char *dl_seat_id(const dl_seat *seat) { return seat == NULL ? NULL : seat->id; }
const char *dl_seat_active_session_id(const dl_seat *seat)
{
    return seat == NULL || seat->active_session == NULL ? NULL : seat->active_session->id;
}
uint32_t dl_seat_session_count(const dl_seat *seat) { return seat == NULL ? 0 : seat->sessions; }

dl_result dl_user_set_linger(dl_manager *manager, uint32_t uid, bool enabled)
{
    struct dl_user *user;
    dl_event event = {0};
    if (manager == NULL) return DL_ERR_INVALID;
    user = get_or_create_user(manager, uid);
    if (user == NULL) return DL_ERR_NOMEM;
    if (user->linger == enabled) return DL_OK;
    user->linger = enabled;
    event.type = DL_EVENT_USER_LINGER_CHANGED;
    event.uid = uid;
    event_push(manager, &event);
    return DL_OK;
}
const dl_user *dl_user_find(const dl_manager *manager, uint32_t uid)
{
    const struct dl_user *user;
    if (manager == NULL) return NULL;
    for (user = manager->users; user != NULL; user = user->next)
        if (user->uid == uid) return user;
    return NULL;
}
uint32_t dl_user_uid(const dl_user *user) { return user == NULL ? 0 : user->uid; }
bool dl_user_linger_enabled(const dl_user *user) { return user != NULL && user->linger; }
uint32_t dl_user_session_count(const dl_user *user) { return user == NULL ? 0 : user->sessions; }
uint32_t dl_user_active_session_count(const dl_user *user)
{
    return user == NULL ? 0 : user->active_sessions;
}

uint64_t dl_manager_event_generation(const dl_manager *manager)
{
    return manager == NULL ? 0 : manager->event_generation;
}

dl_result dl_manager_next_event(const dl_manager *manager,
                                uint64_t after_generation,
                                dl_event *out_event)
{
    uint64_t oldest, wanted;
    const dl_event *event;
    if (out_event != NULL) memset(out_event, 0, sizeof(*out_event));
    if (manager == NULL || out_event == NULL) return DL_ERR_INVALID;
    if (after_generation > manager->event_generation) return DL_ERR_INVALID;
    if (after_generation == manager->event_generation) return DL_ERR_NOT_FOUND;
    oldest = manager->event_generation > DL_EVENT_HISTORY_MAX
                 ? manager->event_generation - DL_EVENT_HISTORY_MAX + 1 : 1;
    wanted = after_generation + 1;
    if (wanted < oldest) {
        out_event->generation = manager->event_generation;
        out_event->type = DL_EVENT_OVERFLOW;
        return DL_ERR_STATE;
    }
    event = &manager->events[(wanted - 1) % DL_EVENT_HISTORY_MAX];
    if (event->generation != wanted) {
        out_event->generation = manager->event_generation;
        out_event->type = DL_EVENT_OVERFLOW;
        return DL_ERR_STATE;
    }
    *out_event = *event;
    return DL_OK;
}
