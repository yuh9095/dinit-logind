# PAM integration

The optional `pam_dinit_logind.so` implements PAM session open/close hooks.
It sends a bounded protocol-v1 request, waits for a daemon acknowledgement
containing the generated session ID, and keeps the Unix stream open for the
PAM session lifetime.

The Linux ingress authenticates the peer using SO_PEERCRED, checks the
configured trusted peer UID, validates the fixed-size request, checks the
target UID through NSS, creates the Core Session, and releases it on peer
disconnect. Peer UID and login UID are separate identities.

See `docs/pam-protocol-v1.md`. Runtime socket creation and daemon event-loop
integration remain to be wired into the daemon executable.
