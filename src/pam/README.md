# PAM ingress

The optional `pam_dinit_logind.so` module is built when the PAM development
dependency is available. It implements `pam_sm_open_session` and
`pam_sm_close_session`.

On open, it resolves PAM_USER through NSS, sends a bounded versioned request
to the configured daemon Unix socket, and retains the connection in PAM
handle data. On close or PAM handle cleanup, it closes the connection so the
daemon can release the associated session.

The daemon must authenticate the socket peer independently and validate the
requested login UID; peer UID and login UID are intentionally not assumed to
match. The daemon-side protocol acceptor is not implemented yet, so this
module is not deployable until that component and end-to-end tests exist.

See `docs/pam-protocol-v1.md`.
