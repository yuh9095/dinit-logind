/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_TERMINATION_H
#define DINIT_LOGIND_TERMINATION_H

#include <stdbool.h>
#include <time.h>
#include <stdint.h>

#ifndef DL_TERMINATION_ID_MAX
#define DL_TERMINATION_ID_MAX 64
#endif

typedef struct dl_termination_item dl_termination_item;

typedef struct {
    dl_termination_item *head;
    uint32_t timeout_sec;
    int (*clock_fn)(struct timespec *);
} dl_termination_queue;

typedef int (*dl_termination_kill_fn)(void *payload);
typedef void (*dl_termination_release_fn)(void *payload);

void dl_termination_queue_init(dl_termination_queue *queue,
                               uint32_t timeout_sec);
void dl_termination_queue_set_clock(dl_termination_queue *queue,
                                    int (*clock_fn)(struct timespec *));
bool dl_termination_queue_contains(const dl_termination_queue *queue,
                                   const char *session_id);
/* On success, the queue takes ownership of payload. On failure, caller
 * retains ownership. */
int dl_termination_queue_schedule(dl_termination_queue *queue,
                                  const char *session_id, void *payload,
                                  dl_termination_kill_fn kill_fn,
                                  dl_termination_release_fn release_fn);
/* Restore a previously persisted absolute CLOCK_MONOTONIC deadline. */
int dl_termination_queue_schedule_at(dl_termination_queue *queue,
                                     const char *session_id,
                                     const struct timespec *deadline,
                                     void *payload,
                                     dl_termination_kill_fn kill_fn,
                                     dl_termination_release_fn release_fn);
/* Clock failures postpone work; kill failures remain queued for retry. */
int dl_termination_queue_process(dl_termination_queue *queue);
/* Attempts every pending kill and releases all payloads during shutdown. */
void dl_termination_queue_finish(dl_termination_queue *queue);

#endif
