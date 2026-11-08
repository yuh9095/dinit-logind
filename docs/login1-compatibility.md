# login1 compatibility plan

## Reference baseline

The primary behavioral/API reference is systemd v262.2. The implementation must be independent of systemd at runtime. Compatibility claims must be tied to tests and documented deviations.

## Compatibility scope

For every exported interface, audit and test object paths, interface names, method signatures, argument validation, return values, property types/defaults/change notifications, signals and ordering, D-Bus error names, peer credentials, Polkit actions, object lifetimes, and behavior when optional hardware/kernel facilities are absent.

## Implemented compatibility slices

### Inhibitor registration and reporting

The current implementation provides:

- `Inhibit(what, who, why, mode) -> h` using a pipe descriptor whose open lifetime represents the lock.
- `ListInhibitors() -> a(ssssuu)`, including the effective UID and PID of the D-Bus caller.
- `BlockInhibited`, `DelayInhibited`, `NCurrentInhibitors`, and `InhibitDelayMaxUSec`.
- Property-change notifications when inhibitors are registered or reaped.
- A bounded in-memory inhibitor table. Closing the final client copy releases the inhibitor.
- Delay-mode requests are explicitly rejected with `NotSupported` until transition coordination exists; `InhibitDelayMaxUSec` is therefore zero.

This is not yet full inhibitor orchestration. Power/sleep actions do not yet emit the prepare signals or consult the block-inhibitor table. Do not advertise these parts as complete until orchestration, delay deadlines, and timeout behavior have tests.

## Manager API inventory

Groups in scope for audit and staged implementation:

- Discovery: GetSession, GetSessionByPID, GetUser, GetUserByPID, GetSeat, ListSessions, ListSessionsEx, ListUsers, ListSeats, ListInhibitors.
- Session lifecycle: CreateSession, ReleaseSession, ActivateSession, ActivateSessionOnSeat, LockSession, LockSessions, KillSession, TerminateSession.
- User lifecycle: KillUser, TerminateUser, SetUserLinger, TerminateSeat.
- Devices: AttachDevice, FlushDevices.
- Inhibitors: Inhibit.
- Power: PowerOff, Reboot, Halt, Suspend, Hibernate, HybridSleep, SuspendThenHibernate, ScheduleShutdown, CancelScheduledShutdown.
- Capability queries: CanPowerOff, CanReboot, CanSuspend, and related capability methods.

This is an initial inventory, not a claim that any method is implemented. The complete v262.2 introspection and source audit remains authoritative.

## Signals and properties

Audit at minimum SessionNew, SessionRemoved, PrepareForShutdown, and PrepareForSleep. Also audit session/user/seat state, IdleHint, Preparing, SleepOperations, ScheduledShutdown, and supported reboot-configuration properties. Exact signatures and semantics must be pinned in machine-readable compatibility tests before implementation.

## Backend translation

Systemd unit/job operations and cgroup-manager assumptions must not leak into the public compatibility layer. Dinit operations need explicit translation with defined behavior for unsupported transient scopes, completion, cancellation, and failure reporting.

## Test layers

1. Introspection/signature tests.
2. Method/property/signal conformance tests.
3. Authorization and negative-permission tests.
4. Session lifecycle tests, including abrupt PAM client disconnect.
5. Seat/VT/device tests with and without hardware.
6. Dinit backend tests using a disposable test service manager.
7. Container boundary and host-power safety tests.
8. Desktop client interoperability tests.

No compatibility deviation is approved yet. Every deliberate deviation must state the v262.2 behavior, reason, observable difference, and corresponding test.
