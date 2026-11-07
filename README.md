# dinit-logind

A native login and seat-management service for Dinit systems.

> Status: project scaffold / design phase. This repository does not yet provide a working login manager, PAM module, D-Bus service, or power-management implementation.

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

## Planned subsystems

Session/user tracking; PAM integration; runtime directory and linger; seat/VT/device management; inhibitors; power policy; login1-compatible D-Bus; Dinit backend; Polkit integration.

See docs/architecture.md and docs/login1-compatibility.md.

## Build status

The initial repository is a documentation and build-system scaffold. There is no daemon target or functional test suite yet. Initial CI validates the Meson project setup only; it is not feature validation.

## License

The project-wide license has not yet been selected. No upstream implementation code is copied into this scaffold. Before adapting code, record each source component's license, copyright notices, SPDX identifiers, and required notices in THIRD_PARTY_NOTICES.md.