# daemon module

`dinit-logind` runs in the foreground and is supervised by Dinit. It
creates `/run/dinit-logind/pam.sock`, accepts authenticated PAM clients,
and owns the Core manager and session lifecycle.

The runtime directory is created beneath a verified root-owned `/run`.
Existing directory and socket objects are checked without following
symlinks. A root-owned, mode-0600 lock file and an exclusive advisory lock
prevent a second daemon instance from replacing the active listener. The daemon refuses to replace non-socket or non-root-owned entries.
The socket is created with mode 0660; the default trusted peer UID is 0.

Configuration is optional. `/etc/dinit-logind.conf` supports only
`allowed_peer_uid = N`. The file must be a regular, root-owned file and
must not be group- or world-writable. Unknown keys, duplicate keys, malformed
values, and symlinks are rejected. The foreground process handles SIGTERM
and SIGINT and releases its listener and sessions during orderly shutdown.

The event loop currently uses a bounded 128-client table and a short poll
interval while driving the non-blocking ingress state machines. All Core
operations run on the single manager owner thread. D-Bus, seat/device,
runtime/linger, and power modules are not yet part of this executable.
