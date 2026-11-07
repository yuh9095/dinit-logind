# dinit-logind

A native login and seat-management service for Dinit systems.

> Status: active implementation. Core session/user/seat tracking, PAM ingress foundations, daemon runtime, and an initial login1 Manager D-Bus discovery interface are implemented. Full systemd-logind compatibility is not yet complete.

## Goals

- Provide a native Dinit-oriented login/session manager.
- Preserve useful session, PAM, runtime-directory, linger, and user-service lifecycle capabilities found in Turnstile.
- Implement seat, VT, device, inhibitor, and power-management behavior against the systemd login1 D-Bus compatibility contract.
- Use systemd v262.2 as the primary behavioral/API reference, not as a runtime dependency.
- Integrate with Dinit, D-Bus, PAM, Polkit, and device-management integration without requiring systemd as PID 1 or a systemd user manager.
- Deliver one coherent daemon with modular internal components.

## Principles

1. Dinit owns system and user service lifecycles.
2. Compatibility includes methods, properties, signals, errors, authorization, and lifecycle semantics—not just method names.
3. Replace systemd-private unit, cgroup-manager, and manager APIs with explicit Dinit/Linux abstractions.
4. Power operations must detect capabilities and container boundaries conservatively, failing closed when host-safe behavior is uncertain.
5. Audit, document provenance and licensing, implement incrementally, and test each subsystem.
6. Preserve expected behavior outside containers and avoid unrelated behavior changes.
7. Keep the implementation portable across glibc and musl; do not assume GNU libc extensions where portable POSIX/Linux interfaces suffice.

## Implemented areas

- Core User, Session, and Seat state model and enumeration.
- PAM session ingress foundations and peer/process identity validation.
- Daemon runtime and configuration.
- Initial login1 Manager D-Bus discovery methods: GetSession, GetUser, GetSeat, ListSessions, ListUsers, and ListSeats.

Returned Session/User/Seat object paths are not yet equivalent to complete exported login1 objects. See `src/dbus/README.md` and `docs/login1-compatibility.md` for the current boundary.

## Build and portability validation

CI currently validates both:
- Ubuntu with glibc, using the distribution's `libsystemd` development package.
- Alpine Linux with musl, using Alpine's `elogind-dev` package, which supplies a `libsystemd.pc`-compatible sd-bus development interface and library.

The Alpine job is a musl portability/build/test check; it does not claim that elogind is a runtime dependency or that systemd is required as PID 1. Runtime D-Bus integration and full login1 behavioral compatibility require additional dedicated tests.

## License

The project-wide license has not yet been selected. No upstream implementation code is copied into this scaffold. Before adapting code, record each source component's license, copyright notices, SPDX identifiers, and required notices in THIRD_PARTY_NOTICES.md.
