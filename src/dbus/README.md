# D-Bus manager discovery implementation

The daemon now connects to the system bus, requests the well-known name
`org.freedesktop.login1`, and exports the Manager object at
`/org/freedesktop/login1`.

The first implemented discovery methods are:

| Method | Signature | Status |
| --- | --- | --- |
| GetSession | `s -> o` | Implemented against Core |
| GetUser | `u -> o` | Implemented against Core |
| GetSeat | `s -> o` | Implemented against Core |
| ListSessions | `() -> a(susso)` | Implemented against Core |
| ListUsers | `() -> a(uso)` | Implemented against Core |
| ListSeats | `() -> a(so)` | Implemented against Core |

The method signatures are checked against the systemd v262.2 login1
introspection published in `man/org.freedesktop.login1.xml`.

This is an initial Manager discovery slice, not full login1 compatibility.
PID-based lookups, session/user/seat object interfaces and properties,
lifecycle signals, authorization, inhibitors, devices, and power operations
remain unimplemented and must not be advertised as supported. In particular,
object paths returned by the discovery methods are not yet backed by exported
Session, User, or Seat interfaces; that is the next implementation stage.

The D-Bus transport uses the sd-bus API from libsystemd. It does not connect
to or depend on systemd PID 1, systemd-logind, or the systemd service manager.
The system bus itself must be provided by the host's D-Bus implementation.
