/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "../../src/platform/linux/cgroup_v2.h"
#include "../../src/session/termination.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

struct fake_io {
    int open_error, write_error, interrupt_once, short_write;
    int opens, writes, closes, flags;
};
static int fake_open(int dirfd, int flags, void *opaque)
{
    struct fake_io *s = opaque;
    (void)dirfd;
    ++s->opens;
    s->flags = flags;
    if (s->open_error) { errno = s->open_error; return -1; }
    return 77;
}
static ssize_t fake_write(int fd, const void *buf, size_t size, void *opaque)
{
    struct fake_io *s = opaque;
    (void)fd;
    assert(size == 1 && memcmp(buf, "1", 1) == 0);
    ++s->writes;
    if (s->interrupt_once) { s->interrupt_once = 0; errno = EINTR; return -1; }
    if (s->write_error) { errno = s->write_error; return -1; }
    return s->short_write ? 0 : 1;
}
static int fake_close(int fd, void *opaque)
{
    struct fake_io *s = opaque;
    assert(fd == 77);
    ++s->closes;
    return 0;
}
struct queued_session {
    dl_linux_cgroup_v2_session session;
    const dl_linux_cgroup_v2_kill_io *io;
    int releases;
};
static int queued_kill(void *opaque)
{
    struct queued_session *p = opaque;
    return dl_linux_cgroup_v2_session_kill_all_with_io(&p->session, p->io);
}
static void queued_release(void *opaque)
{
    ++((struct queued_session *)opaque)->releases;
}
static struct timespec now = {10, 0};
static int fake_clock(struct timespec *out) { *out = now; return 0; }

static void test_open_errors_and_flags(void)
{
    struct fake_io state = {.open_error = EPERM};
    dl_linux_cgroup_v2_kill_io io = {fake_open, fake_write, fake_close, &state};
    dl_linux_cgroup_v2_session session = {.parent_fd = -1, .fd = 42};
    assert(dl_linux_cgroup_v2_session_kill_all_with_io(&session, &io) == -EPERM);
    assert(state.opens == 1 && state.writes == 0 && state.closes == 0);
    assert((state.flags & O_WRONLY) && (state.flags & O_NOFOLLOW));
    state.open_error = ENOENT;
    assert(dl_linux_cgroup_v2_session_kill_all_with_io(&session, &io) == -ENOTSUP);
}
static void test_write_eintr_and_short_write(void)
{
    struct fake_io state = {.interrupt_once = 1};
    dl_linux_cgroup_v2_kill_io io = {fake_open, fake_write, fake_close, &state};
    dl_linux_cgroup_v2_session session = {.parent_fd = -1, .fd = 42};
    assert(dl_linux_cgroup_v2_session_kill_all_with_io(&session, &io) == 0);
    assert(state.opens == 1 && state.writes == 2 && state.closes == 1);
    state.short_write = 1;
    assert(dl_linux_cgroup_v2_session_kill_all_with_io(&session, &io) == -EIO);
    assert(state.closes == 2);
}
static void test_permission_recovery_with_scheduler(void)
{
    struct fake_io state = {.write_error = EPERM};
    dl_linux_cgroup_v2_kill_io io = {fake_open, fake_write, fake_close, &state};
    struct queued_session payload = {
        .session = {.parent_fd = -1, .fd = 42}, .io = &io
    };
    dl_termination_queue queue;
    dl_termination_queue_init(&queue, 1);
    dl_termination_queue_set_clock(&queue, fake_clock);
    now.tv_sec = 20;
    assert(dl_termination_queue_schedule(&queue, "permission-retry",
        &payload, queued_kill, queued_release) == 0);
    now.tv_sec = 21;
    assert(dl_termination_queue_process(&queue) == 0);
    assert(dl_termination_queue_contains(&queue, "permission-retry"));
    assert(payload.releases == 0 && state.writes == 1 && state.closes == 1);
    state.write_error = 0; /* permissions recover before the next event-loop tick */
    assert(dl_termination_queue_process(&queue) == 0);
    assert(!dl_termination_queue_contains(&queue, "permission-retry"));
    assert(payload.releases == 1 && state.writes == 2 && state.closes == 2);
}
int main(void)
{
    test_open_errors_and_flags();
    test_write_eintr_and_short_write();
    test_permission_recovery_with_scheduler();
    return 0;
}
