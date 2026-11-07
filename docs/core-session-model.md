# Core, enumeration, events, and PAM session lifecycle

Status: the manager owns User, Seat, and Session records. The Linux PAM ingress creates and closes sessions through this core; login1 D-Bus publication is a later adapter.

## Ownership and threading

The manager is the sole owner of every User, Seat, and Session object. Adapter pointers are borrowed and remain valid until manager destruction. Calls are serialized on one owner thread; the core is not internally thread-safe.

Closed Session records remain allocated until manager destruction. This preserves stable IDs and makes repeated close requests safe. Enumeration APIs return borrowed pointers and are only stable until the next manager mutation.

## User model

A User is keyed by numeric UID. It may exist before its first session (for example, because linger is configured) and remains present until manager destruction. Its session count includes all sessions not in CLOSED state. Its active-session count includes only sessions whose core state is ACTIVE; activating a different session on the same seat decrements the previous user's active count and increments the new user's count. The `dl_user_active_session_count()` accessor reports this distinct count.

## Seat model

A Seat is manager-owned and keyed by its seat ID. Seats are created lazily when a session is associated with one. A Seat tracks its live session count and at most one active Session. Activating another Session on the same Seat deactivates the previous active Session. Seats remain represented after their session count reaches zero; physical device discovery and seat removal are not implemented yet.

The PAM ingress only maps a local canonical Linux virtual-console TTY (`/dev/tty1` through `/dev/tty63`) to `seat0`. Pseudo-terminals, serial devices, remote sessions, and arbitrary TTY labels are not assigned to a seat. The daemon derives VT number from the TTY path and rejects a nonzero client-supplied VT number that disagrees. This is intentionally conservative; device-based seat assignment will replace this limited mapping when the device backend is implemented.

## Session identity and metadata

A Session has a daemon-generated ID and authenticated UID. Its leader identity is a tuple of PID from kernel peer credentials, PID namespace inode, and process start time from procfs. PID alone is never treated as identity. The tuple avoids accidental matches across PID namespaces and PID reuse.

Metadata is copied into bounded manager-owned storage at creation. Optional metadata accessors return NULL when the field is absent. The core rejects overlong strings and control characters. Seat/VT semantic checks belong to platform adapters.

## Lifecycle

```text
          activate
  OPEN --------------> ACTIVE
   |                     |
   | close               | close
   v                     v
               CLOSED
```

- Creation produces OPEN.
- Activation is allowed from OPEN and is idempotent in ACTIVE.
- A Seat has at most one active Session; switching sessions changes both Session states.
- Deactivation returns ACTIVE to OPEN.
- Close is allowed from OPEN or ACTIVE; CLOSED is terminal.
- Repeated close is successful and produces no duplicate event.
- The core never starts or stops a Dinit service. That belongs to a separate policy/backend layer.

## Enumeration

The manager provides count/index accessors for Users, Seats, and live Sessions. Session enumeration excludes CLOSED records. User and Seat enumeration includes manager-owned records even when they currently have no sessions. These APIs are intended for building a consistent login1 object snapshot; callers must serialize enumeration with mutations on the owner thread.

## Event journal

The core exposes a bounded, non-destructive event journal with monotonically increasing generation numbers. Each consumer tracks its own cursor; reading events does not consume them for other consumers. Events include User/Seat/Session creation, Session state changes/removal, Seat active-session changes, and User linger changes.

The journal retains the newest 256 events. If a consumer's cursor falls behind retained history, `dl_manager_next_event()` returns `DL_ERR_STATE` and an `DL_EVENT_OVERFLOW` marker with the current generation. The consumer must rebuild its object snapshot and resume from that generation. This avoids callbacks, re-entrancy, and subscriber lifetime hazards while providing a bridge to future D-Bus `PropertiesChanged`, `SessionNew`, `SessionRemoved`, and Seat state signals.

## PAM lifetime integration

The PAM module opens a persistent Unix stream connection to the daemon and retains it for the PAM session lifetime. The daemon authenticates the peer using kernel-supplied Unix socket credentials, validates the request and target UID, binds the process identity to the peer PID, creates the core Session, and replies with its ID. The daemon retains a duplicate of the socket after sending the response. Orderly PAM close or client disconnect closes the core Session and publishes the corresponding core events.

The peer UID authenticates the PAM helper; it is deliberately not required to equal the target login UID because privileged PAM stacks commonly create sessions for another account. This is authentication metadata, not authorization for future privileged login1 methods.

## Persistence and recovery

The in-memory manager is lost on daemon restart. Runtime directory and linger marker persistence are handled by the runtime module; restoring live sessions after a daemon crash is not attempted. Stale runtime cleanup and robust crash recovery remain separate work.

## Deliberately deferred

- login1 D-Bus object paths, method/property/signal wire compatibility;
- physical seat discovery, device assignment, VT switching and seat removal;
- pidfd ownership and independent process-exit monitoring;
- authorization policy and Polkit integration;
- Dinit service lifecycle operations;
- multi-threaded access.
