# Turnstile integration audit

## Audited upstream revision

- Repository: https://github.com/chimera-linux/turnstile
- Audited commit: e3413dad386bf72048646f9f9ffd3a8d60e10eb0
- License: BSD-2-Clause (see upstream COPYING.md)
- Scope: independent login/session tracker and service-manager-agnostic
  user-service lifecycle coordinator. It is explicitly not a seat tracker.

This is an implementation audit and mapping. It does not claim that Turnstile
source files have been copied into dinit-logind.

## Functionality mapping

| Turnstile behavior | dinit-logind owner | Decision |
|---|---|---|
| Multiple sessions grouped by UID | core/user/session | One authoritative User object and active-session count |
| One user manager shared by multiple logins | backend/dinit | Start once; stop after last session unless linger |
| PAM readiness handshake | pam + backend/dinit | Keep authenticated ingress; add asynchronous service-readiness phase |
| PAM-derived environment | pam/runtime | Merge only validated, explicitly allowed variables |
| XDG_RUNTIME_DIR provisioning | runtime | Descriptor-relative operations and strict owner/mode validation |
| Per-user/global linger | user/runtime | Persist per-UID state; do not rely on volatile core memory |
| Session bus environment | runtime | Export only after verifying a socket at the expected path |
| Dinit user manager launch | backend/dinit | Dinit-native dinit --user and control-socket readiness |
| Seat and VT tracking | seat | Not supplied by Turnstile; implement separately |
| login1 D-Bus API | dbus | Not supplied by Turnstile; implement against systemd v262.2 |

## Audited behavior

Turnstile groups logins by UID, starts one user service manager for the
first relevant login, and lets subsequent sessions share it. Its PAM module
waits for backend readiness before completing the login handshake. On last
logout, it checks linger before terminating the user manager.

Its Dinit backend creates a per-user service directory, starts dinit --user,
and waits for the Dinit control socket. Its ready action starts login.target,
separating manager availability from completion of the login-critical service
set.

Runtime management creates /run/user/UID-style paths, exports
XDG_RUNTIME_DIR, and can export DBUS_SESSION_BUS_ADDRESS when a bus socket
exists. Linger is based on regular marker files and is evaluated on last
logout. Persisted linger entries are scanned at daemon startup to pre-start
user managers.

## Security and design differences

The upstream implementation is a behavior reference, not a security template
to copy verbatim. dinit-logind retains its SO_PEERCRED plus PID namespace and
process start-time identity checks and uses descriptor-relative filesystem
operations.

- Never unlink a pre-existing control socket without proving it is stale and
  owned by this daemon.
- Never recursively clear runtime directories until a race-resistant,
  mount-aware deletion algorithm is available.
- Never let an untrusted session choose runtime or linger paths.
- Use numeric UID marker names, not usernames.
- Dinit startup and shutdown must be asynchronous and report actual readiness
  and exit status to PAM.
- Do not install a second Turnstile daemon or runtime dependency; integrate
  the behavior into the single dinit-logind daemon.

## libsystemd boundary

Turnstile does not provide the login1 D-Bus service/API. Use sd-bus from
libsystemd for the login1 transport and wire-level handling if the target
system provides it or the project's own systemd-compatible API layer supplies
the required ABI. This does not imply a dependency on systemd PID 1, systemd
unit management, or the systemd user manager. Dinit and the daemon retain
ownership of service lifecycle and event-loop policy.
