/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _POSIX_C_SOURCE 200809L
#include "termination.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dl_termination_item {
    char session_id[DL_TERMINATION_ID_MAX];
    struct timespec deadline;
    void *payload;
    dl_termination_kill_fn kill_fn;
    dl_termination_release_fn release_fn;
    bool warned;
    struct dl_termination_item *next;
};

static int default_clock(struct timespec *now)
{
    return clock_gettime(CLOCK_MONOTONIC, now);
}

void dl_termination_queue_init(dl_termination_queue *queue,
                               uint32_t timeout_sec)
{
    if (!queue) return;
    memset(queue, 0, sizeof(*queue));
    queue->timeout_sec = timeout_sec;
    queue->clock_fn = default_clock;
}

void dl_termination_queue_set_clock(dl_termination_queue *queue,
                                    int (*clock_fn)(struct timespec *))
{
    if (queue) queue->clock_fn = clock_fn ? clock_fn : default_clock;
}

bool dl_termination_queue_contains(const dl_termination_queue *queue,
                                   const char *session_id)
{
    const dl_termination_item *item;
    if (!queue || !session_id) return false;
    for (item = queue->head; item; item = item->next)
        if (strcmp(item->session_id, session_id) == 0) return true;
    return false;
}

int dl_termination_queue_schedule_at(dl_termination_queue *queue,
                                     const char *session_id,
                                     const struct timespec *deadline,
                                     void *payload,
                                     dl_termination_kill_fn kill_fn,
                                     dl_termination_release_fn release_fn)
{
    dl_termination_item *item;
    size_t id_len;
    if (!queue || !session_id || !deadline || !payload || !kill_fn ||
        !release_fn || deadline->tv_sec < 0 || deadline->tv_nsec < 0 ||
        deadline->tv_nsec >= 1000000000L)
        return -EINVAL;
    if (dl_termination_queue_contains(queue, session_id)) return -EALREADY;
    id_len = strlen(session_id);
    if (id_len == 0 || id_len >= sizeof(item->session_id)) return -EINVAL;
    item = calloc(1, sizeof(*item));
    if (!item) return -ENOMEM;
    memcpy(item->session_id, session_id, id_len + 1);
    item->deadline = *deadline;
    item->payload = payload;
    item->kill_fn = kill_fn;
    item->release_fn = release_fn;
    item->next = queue->head;
    queue->head = item;
    return 0;
}

int dl_termination_queue_schedule(dl_termination_queue *queue,
                                  const char *session_id, void *payload,
                                  dl_termination_kill_fn kill_fn,
                                  dl_termination_release_fn release_fn)
{
    struct timespec now, deadline;
    if (!queue || queue->timeout_sec < 1 || queue->timeout_sec > 86400)
        return -EINVAL;
    if (!queue->clock_fn) queue->clock_fn = default_clock;
    if (queue->clock_fn(&now) != 0)
        return errno ? -errno : -EIO;
    if (now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000L) return -EINVAL;
    if ((uintmax_t)now.tv_sec > (uintmax_t)INTMAX_MAX -
                                queue->timeout_sec) return -EOVERFLOW;
    deadline = now;
    deadline.tv_sec += (time_t)queue->timeout_sec;
    if (deadline.tv_sec < now.tv_sec) return -EOVERFLOW;
    return dl_termination_queue_schedule_at(queue, session_id, &deadline,
                                            payload, kill_fn, release_fn);
}

static void item_release(dl_termination_item *item)
{
    if (!item) return;
    item->release_fn(item->payload);
    free(item);
}

int dl_termination_queue_process(dl_termination_queue *queue)
{
    dl_termination_item **link;
    struct timespec now;
    if (!queue) return -EINVAL;
    if (!queue->head) return 0;
    if (!queue->clock_fn) queue->clock_fn = default_clock;
    if (queue->clock_fn(&now) != 0) {
        int saved = errno ? errno : EIO;
        dl_termination_item *item;
        for (item = queue->head; item; item = item->next) {
            if (!item->warned) {
                fprintf(stderr,
                    "dinit-logind: monotonic clock unavailable; postponing "
                    "SIGKILL for session %s (%s)\n",
                    item->session_id, strerror(saved));
                item->warned = true;
            }
        }
        return 0;
    }
    for (link = &queue->head; *link;) {
        dl_termination_item *item = *link;
        int r;
        if (now.tv_sec < item->deadline.tv_sec ||
            (now.tv_sec == item->deadline.tv_sec &&
             now.tv_nsec < item->deadline.tv_nsec)) {
            link = &item->next;
            continue;
        }
        r = item->kill_fn(item->payload);
        if (r == 0 || r == -ENOENT) {
            *link = item->next;
            item_release(item);
            continue;
        }
        if (!item->warned) {
            fprintf(stderr,
                "dinit-logind: deferred SIGKILL for session %s failed (%d); retrying\n",
                item->session_id, r);
            item->warned = true;
        }
        link = &item->next;
    }
    return 0;
}

void dl_termination_queue_finish(dl_termination_queue *queue)
{
    if (!queue) return;
    while (queue->head) {
        dl_termination_item *item = queue->head;
        int r = item->kill_fn(item->payload);
        if (r < 0 && r != -ENOENT)
            fprintf(stderr,
                "dinit-logind: final SIGKILL for session %s failed (%d) during shutdown\n",
                item->session_id, r);
        queue->head = item->next;
        item_release(item);
    }
}
