/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#include "../../src/session/termination.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

struct fake_payload {
    int kills;
    int releases;
    int fail_kills;
};

static struct timespec fake_now = {100, 0};
static int clock_error;

static int fake_clock(clockid_t id, struct timespec *now)
{
    (void)id;
    if (clock_error) { errno = clock_error; return -1; }
    *now = fake_now;
    return 0;
}

static int fake_kill(void *opaque)
{
    struct fake_payload *p = opaque;
    ++p->kills;
    if (p->fail_kills > 0) { --p->fail_kills; return -EIO; }
    return 0;
}

static void fake_release(void *opaque)
{
    struct fake_payload *p = opaque;
    ++p->releases;
}

static void test_deadline_and_expiry(void)
{
    dl_termination_queue q;
    struct fake_payload p = {0};
    dl_termination_queue_init(&q, 5);
    dl_termination_queue_set_clock(&q, fake_clock);
    fake_now.tv_sec = 100;
    assert(dl_termination_queue_schedule(&q, "s1", &p, fake_kill,
                                         fake_release) == 0);
    assert(dl_termination_queue_contains(&q, "s1"));
    fake_now.tv_sec = 104;
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 0 && p.releases == 0);
    fake_now.tv_sec = 105;
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 1 && p.releases == 1);
    assert(!dl_termination_queue_contains(&q, "s1"));
}

static void test_schedule_clock_failure_keeps_ownership(void)
{
    dl_termination_queue q;
    struct fake_payload p = {0};
    dl_termination_queue_init(&q, 1);
    dl_termination_queue_set_clock(&q, fake_clock);
    clock_error = EIO;
    assert(dl_termination_queue_schedule(&q, "schedule-fail", &p,
                                         fake_kill, fake_release) == -EIO);
    assert(!dl_termination_queue_contains(&q, "schedule-fail"));
    assert(p.kills == 0 && p.releases == 0);
    clock_error = 0;
}

static void test_clock_failure_postpones(void)
{
    dl_termination_queue q;
    struct fake_payload p = {0};
    dl_termination_queue_init(&q, 1);
    dl_termination_queue_set_clock(&q, fake_clock);
    fake_now.tv_sec = 200;
    assert(dl_termination_queue_schedule(&q, "s2", &p, fake_kill,
                                         fake_release) == 0);
    fake_now.tv_sec = 500;
    clock_error = EIO;
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 0 && p.releases == 0);
    clock_error = 0;
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 1 && p.releases == 1);
}

static void test_retry_and_duplicate(void)
{
    dl_termination_queue q;
    struct fake_payload p = {0, 0, 1};
    struct fake_payload duplicate = {0};
    dl_termination_queue_init(&q, 1);
    dl_termination_queue_set_clock(&q, fake_clock);
    fake_now.tv_sec = 300;
    assert(dl_termination_queue_schedule(&q, "s3", &p, fake_kill,
                                         fake_release) == 0);
    assert(dl_termination_queue_schedule(&q, "s3", &duplicate, fake_kill,
                                         fake_release) == -EALREADY);
    fake_now.tv_sec = 301;
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 1 && p.releases == 0);
    assert(dl_termination_queue_contains(&q, "s3"));
    assert(dl_termination_queue_process(&q) == 0);
    assert(p.kills == 2 && p.releases == 1);
}

static void test_shutdown_finishes_all(void)
{
    dl_termination_queue q;
    struct fake_payload a = {0}, b = {0};
    dl_termination_queue_init(&q, 90);
    assert(dl_termination_queue_schedule(&q, "a", &a, fake_kill,
                                         fake_release) == 0);
    assert(dl_termination_queue_schedule(&q, "b", &b, fake_kill,
                                         fake_release) == 0);
    dl_termination_queue_finish(&q);
    assert(a.kills == 1 && a.releases == 1);
    assert(b.kills == 1 && b.releases == 1);
    assert(!dl_termination_queue_contains(&q, "a"));
    assert(!dl_termination_queue_contains(&q, "b"));
}

int main(void)
{
    test_deadline_and_expiry();
    test_schedule_clock_failure_keeps_ownership();
    test_clock_failure_postpones();
    test_retry_and_duplicate();
    test_shutdown_finishes_all();
    return 0;
}
