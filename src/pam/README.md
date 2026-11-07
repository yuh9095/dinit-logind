# PAM integration

The optional `pam_dinit_logind.so` implements PAM session open/close hooks.
It sends a bounded protocol-v1 request and keeps the Unix stream open for the
PAM session lifetime.

The Linux daemon ingress authenticates the socket peer using SO_PEERCRED,
checks the configured trusted peer UID, validates the fixed-size request,
checks the target UID through NSS, creates the Core Session, and releases it
when the peer disconnects. Peer UID and login UID are separate identities.

See `docs/pam-protocol-v1.md`. Runtime socket creation and daemon event-loop
integration remain to be wired into the eventual daemon executable.
