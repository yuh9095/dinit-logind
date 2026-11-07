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

The only supported setting is `allowed_peer_uid = 0`. Non-root peer UIDs are rejected: the PAM ingress is a privileged session-creation interface and must only trust root-owned PAM clients. The
configuration file must be regular, root-owned, and not group/world-writable;
it is opened with O_NOFOLLOW. Unknown and duplicate settings are errors.
Do not allow untrusted users to control this value.

## Event loop and lifecycle

The foreground event loop accepts at most 128 concurrent PAM connections.
Each accepted stream is authenticated by the ingress adapter, incrementally
parsed, acknowledged after Core Session creation, and monitored for peer
disconnect. SIGTERM and SIGINT trigger orderly teardown; the listener and
all active sessions are released before exit.

This is the first runnable daemon foundation, not a complete logind service:
D-Bus login1, Polkit, seats, VTs, devices, Dinit user instances, linger
persistence, inhibitors, and power management remain future modules.
