# Test strategy

- unit/: isolated state machines and validation helpers
- dbus/: login1 introspection, signatures, methods, properties, signals, and errors
- pam/: PAM open/close lifecycle and credential validation
- integration/: Dinit backend and multi-module lifecycle tests
- security/: authorization, path safety, PID reuse, container boundary, and host-power isolation
- compatibility/: behavior compared against the pinned systemd v262.2 contract

A test must distinguish an unsupported platform capability from an implementation failure. Tests must never perform real host shutdown, reboot, suspend, or device ownership changes.
