# Internal interface design

This document establishes interface rules before implementation. Exact C declarations will be added alongside the first compiling module, after dependency choices are finalized.

## General conventions

- Use opaque object types across module boundaries.
- Use explicit result/error values; do not overload errno-style integers with module-specific meanings.
- Functions that return allocated objects or strings must document ownership and the matching release function.
- Borrowed references must state their lifetime and whether they remain valid after callbacks.
- Avoid global mutable state. The manager context is passed explicitly.
- Do not expose D-Bus types, PAM types, or Dinit protocol details in core headers.
- Use fixed-width integer types for externally meaningful IDs and timestamps.
- Treat all caller-controlled strings and paths as untrusted input.
- Any operation that can block on I/O or external service completion must be asynchronous or explicitly isolated from the main event loop.

## Core manager boundary

The core manager is the authoritative owner of session, user, seat, device, and inhibitor state.

The initial conceptual operations are:

- create/release a session from authenticated credentials and validated PAM metadata;
- look up a session by stable session ID or verified process identity;
- enumerate sessions/users/seats using snapshots or iterators with defined lifetime;
- activate or terminate a session through policy-checked state transitions;
- update user linger state;
- publish lifecycle events for D-Bus signal emission.

Ingress adapters must not write internal object fields directly.

## Session identity and credentials

A session creation request must distinguish:
- authenticated UID;
- peer PID as observed/validated by the daemon;
- PAM service and session type/class;
- seat and VT claims, which require validation;
- local versus remote session metadata;
- the lifetime token/channel used to detect PAM session teardown.

Never trust a PID supplied only as a string. Account for PID reuse and namespace boundaries. Use kernel credentials and process identity checks as the source of truth.

## Dinit backend boundary

The backend exposes Dinit-native operations, not systemd unit names or systemd job objects.

Conceptual operations:
- start/stop a configured Dinit service or user service;
- query whether a known service is active;
- request a user-service lifecycle transition;
- receive completion/failure/cancellation results.

The backend must define:
- service-name validation and allowlisting;
- timeout and cancellation behavior;
- whether the operation is synchronous or event-driven;
- how Dinit connection loss is reported;
- behavior when the requested operation has no Dinit equivalent.

Do not pretend Dinit operations are systemd jobs. login1-facing behavior must translate only the observable semantics that can be represented honestly.

## Runtime directory boundary

Runtime operations must:
- create and validate per-UID directories;
- enforce ownership and mode;
- reject unsafe symlink/path traversal conditions;
- clean up only directories owned by this service and associated with a completed user lifecycle;
- handle stale state after crashes without deleting unrelated content.

The interface should accept a validated UID and policy, not an arbitrary caller-provided filesystem path.

## Device and seat boundary

Device events enter through a device-provider adapter. Seat/session ownership decisions remain in core. Device access changes must be reversible and tied to a specific session lifecycle.

VT operations are optional platform capabilities. A headless system must still support sessions that do not require a physical VT.

## Power and inhibitor boundary

D-Bus handlers request a named policy operation from the power module. The power module:
1. checks platform capability;
2. checks container/namespace scope and whether host impact can be ruled out;
3. applies inhibitor policy;
4. obtains authorization through Polkit where required;
5. invokes the selected safe platform/backend operation;
6. reports the actual result.

Unknown or ambiguous scope must fail closed. A container must not gain host-wide power control through login1 compatibility.

## D-Bus boundary

The D-Bus module owns wire-level details:
- object paths and interface names;
- exact method/property/signal signatures;
- D-Bus error names;
- peer credential extraction;
- Polkit action mapping;
- serialization and lifecycle signal ordering.

It calls core/policy interfaces and does not implement session policy itself.

## Event and concurrency model

Before choosing the event-loop library, document the dependency trade-offs. Regardless of implementation:
- callbacks must not retain unowned object pointers;
- object removal must invalidate or safely retire outstanding references;
- shutdown must stop ingress before destroying manager state;
- D-Bus disconnects and PAM channel closure must be handled idempotently;
- tests must cover duplicate release, late callbacks, and abrupt client termination.

## ABI policy

Internal interfaces are not a stable ABI until explicitly declared public. Keep internal headers under `src/`; install headers under `include/dinit-logind/` only when an external consumer genuinely needs them.
