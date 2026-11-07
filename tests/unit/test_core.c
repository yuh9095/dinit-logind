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

int main(void)
{
    dl_manager *manager = dl_manager_new();
    dl_session *first = NULL;
    dl_session *second = NULL;
    dl_session_spec spec;
    dl_process_identity reused_pid = {77, 1001, 5000};
    const dl_user *user;
    char first_id[DL_SESSION_ID_MAX];

    assert(manager != NULL);

    spec = make_spec(1000, 77, 1001, 5000);
    assert(dl_session_create(manager, &spec, &first) == DL_OK);
    assert(first != NULL);
    (void)snprintf(first_id, sizeof(first_id), "%s", dl_session_id(first));
    assert(strcmp(first_id, "session-1") == 0);
    assert(dl_session_get_state(first) == DL_SESSION_OPEN);
    assert(dl_session_uid(first) == 1000);
    assert(strcmp(dl_session_seat(first), "seat0") == 0);
    assert(dl_session_vtnr(first) == 2);
    assert(dl_user_active_session_count(dl_user_find(manager, 1000)) == 1);

    /* Same process identity cannot own two live sessions. */
    assert(dl_session_create(manager, &spec, &second) == DL_ERR_CONFLICT);
    assert(second == NULL);

    /* PID reuse and PID namespace changes are distinct identities. */
    spec = make_spec(1000, 77, 1001, 5001);
    assert(dl_session_create(manager, &spec, &second) == DL_OK);
    assert(second != NULL);
    assert(dl_session_find_by_identity(manager, &reused_pid) == first);
    assert(dl_session_activate(manager, first_id) == DL_OK);
    assert(dl_session_activate(manager, first_id) == DL_OK);
    assert(dl_session_get_state(first) == DL_SESSION_ACTIVE);

    assert(dl_session_close(manager, first_id) == DL_OK);
    assert(dl_session_close(manager, first_id) == DL_OK);
    assert(dl_session_get_state(first) == DL_SESSION_CLOSED);
    assert(dl_session_find_by_identity(manager, &reused_pid) == NULL);
    user = dl_user_find(manager, 1000);
    assert(dl_user_active_session_count(user) == 1);
    assert(dl_session_activate(manager, first_id) == DL_ERR_STATE);

    assert(dl_user_set_linger(manager, 1000, true) == DL_OK);
    assert(dl_user_linger_enabled(dl_user_find(manager, 1000)));
    assert(dl_user_set_linger(manager, 1000, false) == DL_OK);
    assert(!dl_user_linger_enabled(dl_user_find(manager, 1000)));

    /* Linger can create a user record before any session exists. */
    assert(dl_user_set_linger(manager, 2000, true) == DL_OK);
    assert(dl_user_find(manager, 2000) != NULL);
    assert(dl_user_active_session_count(dl_user_find(manager, 2000)) == 0);

    /* Reject incomplete process identities and unsafe metadata. */
    spec = make_spec(3000, 88, 0, 123);
    assert(dl_session_create(manager, &spec, &first) == DL_ERR_INVALID);
    spec = make_spec(3000, 88, 900, 123);
    spec.tty = "tty\nmalformed";
    assert(dl_session_create(manager, &spec, &first) == DL_ERR_INVALID);

    assert(dl_session_close(manager, "does-not-exist") == DL_ERR_NOT_FOUND);
    dl_manager_destroy(manager);
    puts("core tests: ok");
    return 0;
}
