/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static dl_session_spec make_spec(uint32_t uid, uint32_t pid,
                                 uint64_t ns, uint64_t start)
{
    dl_session_spec spec = {0};
    spec.uid = uid;
    spec.leader.pid = pid;
    spec.leader.pid_namespace_inode = ns;
    spec.leader.process_start_time = start;
    spec.seat = "seat0";
    spec.vtnr = 2;
    spec.tty = "/dev/tty2";
    spec.service = "login";
    spec.type = "tty";
    spec.session_class = "user";
    return spec;
}

static void test_event_overflow(void)
{
    dl_manager *manager = dl_manager_new();
    dl_event event;
    uint64_t cursor;
    uint32_t uid;
    assert(manager != NULL);
    for (uid = 10000; uid < 10140; ++uid)
        assert(dl_user_set_linger(manager, uid, true) == DL_OK);
    cursor = 0;
    assert(dl_manager_next_event(manager, cursor, &event) == DL_ERR_STATE);
    assert(event.type == DL_EVENT_OVERFLOW);
    assert(event.generation == dl_manager_event_generation(manager));
    cursor = event.generation;
    assert(dl_manager_next_event(manager, cursor, &event) == DL_ERR_NOT_FOUND);
    assert(dl_manager_next_event(manager, cursor + 1, &event) == DL_ERR_INVALID);
    dl_manager_destroy(manager);
}

int main(void)
{
    dl_manager *manager = dl_manager_new();
    dl_session *first = NULL, *second = NULL;
    dl_session_spec spec;
    dl_process_identity reused_pid = {77, 1001, 5000};
    const dl_user *user;
    const dl_seat *seat;
    const dl_session *listed_session;
    dl_event event;
    uint64_t cursor = 0;
    char first_id[DL_SESSION_ID_MAX];

    assert(manager != NULL);
    assert(dl_manager_event_generation(manager) == 0);
    assert(dl_manager_user_count(manager) == 0);
    assert(dl_manager_seat_count(manager) == 0);
    assert(dl_manager_session_count(manager) == 0);
    assert(dl_manager_next_event(manager, 0, &event) == DL_ERR_NOT_FOUND);

    spec = make_spec(1000, 77, 1001, 5000);
    assert(dl_session_create(manager, &spec, &first) == DL_OK);
    assert(first != NULL);
    (void)snprintf(first_id, sizeof(first_id), "%s", dl_session_id(first));
    assert(strcmp(first_id, "session-1") == 0);
    assert(dl_session_get_state(first) == DL_SESSION_OPEN);
    assert(dl_session_uid(first) == 1000);
    assert(strcmp(dl_session_seat(first), "seat0") == 0);
    assert(dl_session_vtnr(first) == 2);

    assert(dl_manager_user_count(manager) == 1);
    assert(dl_manager_user_at(manager, 0) == dl_user_find(manager, 1000));
    assert(dl_manager_user_at(manager, 1) == NULL);
    assert(dl_manager_seat_count(manager) == 1);
    assert(dl_manager_seat_at(manager, 0) == dl_seat_find(manager, "seat0"));
    assert(dl_manager_session_count(manager) == 1);
    listed_session = dl_manager_session_at(manager, 0);
    assert(listed_session == first);
    assert(dl_manager_session_at(manager, 1) == NULL);
    assert(dl_user_session_count(dl_user_find(manager, 1000)) == 1);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 0);

    /* Initial object creation is observable in order: user, seat, session. */
    assert(dl_manager_next_event(manager, cursor, &event) == DL_OK);
    assert(event.type == DL_EVENT_USER_ADDED && event.uid == 1000);
    cursor = event.generation;
    assert(dl_manager_next_event(manager, cursor, &event) == DL_OK);
    assert(event.type == DL_EVENT_SEAT_ADDED && strcmp(event.seat_id, "seat0") == 0);
    cursor = event.generation;
    assert(dl_manager_next_event(manager, cursor, &event) == DL_OK);
    assert(event.type == DL_EVENT_SESSION_ADDED);
    assert(strcmp(event.session_id, first_id) == 0);
    cursor = event.generation;

    seat = dl_seat_find(manager, "seat0");
    assert(seat != NULL);
    assert(strcmp(dl_seat_id(seat), "seat0") == 0);
    assert(dl_seat_session_count(seat) == 1);
    assert(dl_seat_active_session_id(seat) == NULL);

    assert(dl_session_create(manager, &spec, &second) == DL_ERR_CONFLICT);
    assert(second == NULL);

    spec = make_spec(1000, 77, 1001, 5001);
    assert(dl_session_create(manager, &spec, &second) == DL_OK);
    assert(second != NULL);
    assert(dl_session_find_by_identity(manager, &reused_pid) == first);
    assert(dl_manager_session_count(manager) == 2);

    assert(dl_session_activate(manager, first_id) == DL_OK);
    assert(dl_session_activate(manager, first_id) == DL_OK);
    assert(dl_session_get_state(first) == DL_SESSION_ACTIVE);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 1);
    assert(strcmp(dl_seat_active_session_id(seat), first_id) == 0);
    assert(dl_session_activate(manager, dl_session_id(second)) == DL_OK);
    assert(dl_session_get_state(first) == DL_SESSION_OPEN);
    assert(dl_session_get_state(second) == DL_SESSION_ACTIVE);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 1);
    assert(strcmp(dl_seat_active_session_id(seat), dl_session_id(second)) == 0);
    assert(dl_seat_session_count(seat) == 2);

    /* Stopping is orthogonal to active/open and persists after the deferred
     * kill queue completes, matching logind's Session lifecycle. */
    assert(dl_session_begin_stop(manager, first_id) == DL_OK);
    assert(dl_session_is_stopping(first));
    assert(dl_session_begin_stop(manager, first_id) == DL_OK);
    assert(dl_session_activate(manager, first_id) == DL_ERR_STATE);
    assert(dl_session_deactivate(manager, first_id) == DL_ERR_STATE);

    assert(dl_session_deactivate(manager, dl_session_id(second)) == DL_OK);
    assert(dl_session_get_state(second) == DL_SESSION_OPEN);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 0);
    assert(dl_seat_active_session_id(seat) == NULL);
    assert(dl_session_activate(manager, dl_session_id(second)) == DL_OK);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 1);

    assert(dl_session_close(manager, first_id) == DL_OK);
    assert(dl_session_close(manager, first_id) == DL_OK);
    assert(dl_session_get_state(first) == DL_SESSION_CLOSED);
    assert(dl_session_find_by_identity(manager, &reused_pid) == NULL);
    user = dl_user_find(manager, 1000);
    assert(dl_user_session_count(user) == 1);
    assert(dl_user_active_session_count(user) == 1);
    assert(dl_session_activate(manager, first_id) == DL_ERR_STATE);
    assert(dl_seat_session_count(seat) == 1);
    assert(strcmp(dl_seat_active_session_id(seat), dl_session_id(second)) == 0);
    assert(dl_manager_session_count(manager) == 1);
    assert(dl_manager_session_at(manager, 0) == second);

    assert(dl_session_close(manager, dl_session_id(second)) == DL_OK);
    assert(dl_user_active_session_count(user) == 0);
    assert(dl_seat_session_count(seat) == 0);
    assert(dl_seat_active_session_id(seat) == NULL);
    assert(dl_manager_session_count(manager) == 0);

    assert(dl_user_set_linger(manager, 1000, true) == DL_OK);
    assert(dl_user_linger_enabled(dl_user_find(manager, 1000)));
    assert(dl_user_set_linger(manager, 1000, true) == DL_OK); /* no duplicate event */
    assert(dl_user_set_linger(manager, 1000, false) == DL_OK);
    assert(!dl_user_linger_enabled(dl_user_find(manager, 1000)));
    assert(dl_user_set_linger(manager, 2000, true) == DL_OK);
    assert(dl_user_find(manager, 2000) != NULL);
    assert(dl_user_session_count(dl_user_find(manager, 2000)) == 0);
    assert(dl_manager_user_count(manager) == 2);

    spec = make_spec(3000, 88, 900, 123);
    spec.seat = NULL;
    assert(dl_session_create(manager, &spec, &first) == DL_OK);
    assert(dl_session_seat(first) == NULL);
    assert(dl_session_activate(manager, dl_session_id(first)) == DL_OK);
    assert(dl_user_active_session_count(dl_user_find(manager, 3000)) == 1);
    assert(dl_session_close(manager, dl_session_id(first)) == DL_OK);
    assert(dl_user_active_session_count(dl_user_find(manager, 3000)) == 0);

    spec = make_spec(4000, 88, 0, 123);
    assert(dl_session_create(manager, &spec, &first) == DL_ERR_INVALID);
    spec = make_spec(4000, 88, 900, 123);
    spec.tty = "tty\nmalformed";
    assert(dl_session_create(manager, &spec, &first) == DL_ERR_INVALID);
    assert(dl_session_close(manager, "does-not-exist") == DL_ERR_NOT_FOUND);

    /* Consume remaining event history and verify monotonic generations. */
    while (dl_manager_next_event(manager, cursor, &event) == DL_OK) {
        assert(event.generation == cursor + 1);
        cursor = event.generation;
    }
    assert(cursor == dl_manager_event_generation(manager));
    test_event_overflow();
    dl_manager_destroy(manager);
    puts("core enumeration, lifecycle and event tests: ok");
    return 0;
}
