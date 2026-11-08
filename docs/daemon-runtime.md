# Daemon runtime and PAM listener

## Startup

The daemon must run as root and remains in the foreground for Dinit
supervision. It loads the optional root-owned `/etc/dinit-logind.conf`,
creates `/run/dinit-logind` with mode 0755 if absent, verifies the parent
and child directory are root-owned and not group/world-writable, and binds
`/run/dinit-logind/pam.sock` with mode 0660.

A root-owned mode-0600 lock file is held with an exclusive nonblocking
advisory lock for the daemon lifetime, preventing concurrent instances from
racing during stale-socket cleanup and bind. The lock file is kept in the
runtime directory and is not removed on shutdown.

The listener uses AF_UNIX SOCK_STREAM, nonblocking and close-on-exec flags.
A stale socket is removed only when it is a socket owned by root. Symlinks,
regular files, and foreign-owned sockets are refused. On shutdown, the daemon
removes the socket only if its device/inode still match the socket it created.

## Configuration

Supported settings:

- `allowed_peer_uid = 0`: non-root peer UIDs are rejected because the PAM ingress is a privileged session-creation interface.
- `session_terminate_timeout_sec = 90`: grace period between the initial best-effort SIGTERM and final `cgroup.kill`. Valid values are 1 through 86400 seconds. The default 90 seconds matches systemd v262.2's default `DefaultTimeoutStopSec`; administrators may tune it for their environment.

The configuration file must be regular, root-owned, and not group/world-writable; it is opened with O_NOFOLLOW. Unknown, duplicate, and out-of-range settings are errors. Do not allow untrusted users to control these values.

## Event loop and lifecycle

The foreground event loop accepts at most 128 concurrent PAM connections.
Each accepted stream is authenticated by the ingress adapter, incrementally
parsed, acknowledged after Core Session creation, and monitored for peer
disconnect. SIGTERM and SIGINT trigger orderly teardown; the listener and
all active sessions are released before exit.

This is the first runnable daemon foundation, not a complete logind service:
D-Bus login1, Polkit, seats, VTs, devices, Dinit user instances, linger
persistence, inhibitors, and power management remain future modules.
