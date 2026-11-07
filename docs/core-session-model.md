# Core and session model

Status: initial implementation contract.

## Ownership

The manager is the sole owner of every User and Session object. Adapters receive borrowed pointers and must not free objects or mutate their fields. The manager retains closed Session records until manager destruction in this initial implementation; this makes repeated release requests safe and keeps returned session IDs from being recycled during the daemon lifetime.

A User is keyed by the numeric UID. A User may exist before its first session (for example, because linger was configured), and remains present until manager destruction. Its active session count is derived only from sessions not in CLOSED state.

## Session identity

A session has a daemon-generated stable ID and an authenticated UID. Its leader identity is a tuple:

- PID as validated by the Linux ingress adapter;
- PID namespace inode;
- process start time from procfs (clock ticks since boot).

PID alone is never an identity. The tuple prevents accidental matching across PID namespaces and PID reuse. The Linux adapter must obtain peer credentials from the transport and validate the process identity; the core does not trust caller-provided textual PIDs and does not itself perform procfs I/O.

The tuple is intentionally not an exposed stable ABI. A future pidfd integration may strengthen liveness checks, but must retain a portable fallback for kernels/libcs without pidfd support.

## Metadata

Session metadata includes seat, VT number, TTY, display, service, session type, session class, remote flag, and remote user/host labels. Metadata is copied into manager-owned bounded storage at creation. Optional fields may be empty. The core validates lengths and rejects control characters; semantic checks such as whether a seat or VT exists belong to the corresponding adapter/policy module.

## Lifecycle

Initial state machine:

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
- Close is allowed from OPEN or ACTIVE.
- Closing an already CLOSED session succeeds without changing state.
- CLOSED is terminal.
- No core operation starts or stops a Dinit service. Such work is requested through a separate backend after the state/policy decision.

The core emits no callbacks in this first slice. This avoids re-entrancy and callback lifetime hazards before the event-loop contract is selected. Later event publication must use immutable snapshots or explicitly retained references.

## PAM lifetime

The PAM adapter will own the transport/channel and associate its lifetime with the created session. On orderly PAM close or channel disconnect it asks core to close the session. Duplicate close/disconnect notifications are harmless. Core does not store a raw file descriptor or PAM handle.

A daemon restart loses in-memory records; persistence/recovery is deliberately not part of this first implementation. Stale runtime directories and crash recovery will be handled by the runtime module.

## Concurrency and teardown

The first implementation is single-owner-thread code and is not internally thread-safe. All calls must be serialized by the daemon's eventual event loop. Worker threads must marshal results back to that owner thread and must not retain borrowed pointers across asynchronous boundaries.

Shutdown order: stop accepting PAM/D-Bus ingress; cancel or drain asynchronous adapter work; destroy the manager; then release platform adapters. Manager destruction invalidates all borrowed User/Session pointers.

## User and linger

Users are keyed by UID. Linger is a persistent boolean in manager memory in this slice; persistence and policy authorization are deferred to the user/runtime adapter. Enabling linger may create a User without sessions. Closing the last session does not remove the User and does not implicitly clear linger.

## Deliberately deferred

- D-Bus object paths and login1 wire compatibility;
- PAM module and socket protocol;
- runtime directory creation;
- NSS/userdb records beyond UID identity;
- seat/VT/device state;
- process monitoring and pidfd ownership;
- persistent linger storage;
- multi-threaded access and event-loop integration.
