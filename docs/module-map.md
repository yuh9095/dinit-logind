# Source module map

This document defines the initial source boundaries. It is a design contract, not a claim that the modules are implemented.

## Planned tree

```text
src/
  daemon/       process entry point, startup, shutdown, configuration
  core/         manager state, object registry, lifecycle and shared types
  session/      session creation, lookup, activation, termination
  user/         user records, UID lifecycle, linger state
  pam/          PAM-facing session ingress and module
  runtime/      XDG_RUNTIME_DIR creation, validation, cleanup
  seat/         seats, seat assignment, VT activation
  device/       device event ingestion and per-session device access
  inhibitor/    block/delay inhibitors and prepare sequencing
  power/        capability checks, keys, sleep, reboot and shutdown policy
  dbus/          login1 object model, methods, properties, signals, errors
  polkit/        authorization adapter and action mapping
  backend/
    dinit/       Dinit system/user service lifecycle adapter
  platform/
    linux/       procfs, namespaces, ioctl, filesystem and kernel interfaces
include/
  dinit-logind/  stable public headers, if/when a public API is needed
tests/
  unit/
  dbus/
  pam/
  integration/
  security/
  compatibility/
docs/
packaging/
```

## Module ownership

| Module | Owns | Must not own |
|---|---|---|
| daemon | process lifecycle, configuration, signal handling | session policy or D-Bus method semantics |
| core | manager state and object lifetime | direct Dinit commands or raw D-Bus marshalling |
| session | session state transitions | PAM transport implementation |
| user | user state and linger metadata | starting services directly |
| pam | authenticated PAM ingress/egress | privileged policy decisions outside core |
| runtime | runtime directory lifecycle and filesystem safety | login1 D-Bus details |
| seat | seat state and VT operations | user service lifecycle |
| device | device inventory and session attachment | udev daemon implementation |
| inhibitor | inhibitor records and ordering | direct host power execution |
| power | policy and safe operation dispatch | D-Bus transport details |
| dbus | login1 wire contract | direct systemd-private API calls |
| polkit | authorization queries | deciding session ownership |
| backend/dinit | Dinit-native service operations | public login1 compatibility logic |
| platform/linux | narrow kernel/OS primitives | high-level login policy |

## Dependency direction

Allowed high-level direction:

```text
D-Bus / PAM ingress
        |
        v
      core
  /     |      \
session user  inhibitor
  |      |        |
  +--- runtime ---+
        |
  seat / device / power
        |
 platform adapters + Dinit backend + Polkit
```

The D-Bus and PAM edges are ingress/egress adapters. They must call core interfaces rather than mutate manager objects independently.

## Rules

1. No module may invoke systemd manager APIs, systemd unit jobs, or systemd-private libraries.
2. Only `backend/dinit` may translate service lifecycle requests into Dinit operations.
3. Only the power policy module may request privileged power actions; D-Bus handlers must not call reboot/ioctl primitives directly.
4. Session and user objects have one authoritative owner in core. Other modules hold validated references, not competing copies of state.
5. Platform-specific operations must be behind narrow interfaces and have explicit unsupported/error results.
6. Optional facilities (VT, physical seats, suspend, firmware boot options) must not prevent daemon startup when absent.
7. Public D-Bus compatibility must be independent of internal module layout.
8. Each module gets focused unit tests before cross-module integration tests are added.
