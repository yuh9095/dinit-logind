# Architecture

## Runtime shape

The intended deliverable is one daemon, dinit-logind, with internal modules. Turnstile is a source of existing functionality and design knowledge, not a required second daemon at runtime.

PAM clients and login1 clients communicate with dinit-logind. The daemon owns session/user state, seat/VT/device state, inhibitor state, and power policy. A platform abstraction connects those modules to Dinit, Linux APIs, device management, and Polkit.

## Subsystem boundaries

- Core manager: owns users, sessions, seats, devices, inhibitors, and object lifetimes.
- PAM/session ingress: creates and releases sessions from authenticated PAM lifecycle events. Socket disconnect handling must be explicit and race-tested.
- Runtime/linger: manages runtime state with strict UID ownership and path protections; starts/stops Dinit user instances through the backend.
- Seat/VT: handles seat activation and VT operations where available; systems without physical VTs must remain supported.
- Device: tracks device events and session attachment without assuming systemd-udevd.
- Inhibitor: implements block/delay semantics and correct prepare-for-sleep/shutdown ordering.
- Power: exposes only operations the active backend and platform can safely perform.
- D-Bus: implements login1 objects, methods, properties, signals, errors, and authorization checks.
- Dinit backend: maps lifecycle operations to Dinit-native operations and reports real completion/failure.

## Dependency policy

Expected runtime dependencies are Linux/POSIX facilities, D-Bus, PAM, and selected authorization/device integrations. Exact dependencies will be finalized before implementation. There must be no dependency on systemd PID 1, systemd's user manager, or systemd-private libraries.

## Security invariants

- Validate caller identity using D-Bus peer credentials and kernel process identity; account for PID reuse.
- Treat caller-provided UID, PID, seat, and device paths as untrusted.
- Protect runtime paths against symlink and ownership attacks.
- Apply Polkit checks to privileged actions and re-check authorization at the point of action.
- Container detection is not authorization. Power operations fail closed if host/container scope is ambiguous.
- A container session must never trigger host-wide reboot, shutdown, suspend, or device operations.
- Define ownership and cleanup behavior for every object and file descriptor.

## Implementation sequence

1. Lock down source provenance, licenses, interfaces, and threat model.
2. Implement core object model and testable backend/platform interfaces.
3. Integrate PAM session lifecycle and runtime-directory handling.
4. Implement Dinit system/user backend operations.
5. Implement seat, VT, and device management.
6. Implement inhibitors and power policy.
7. Implement login1 D-Bus compatibility in audited groups.
8. Add desktop-client interoperability and adversarial integration tests.
