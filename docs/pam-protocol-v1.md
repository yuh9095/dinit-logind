# PAM socket protocol v1 and daemon ingress

The PAM module connects to `/run/dinit-logind/pam.sock` and sends exactly
one fixed-size `dl_pam_open_request`. The connection remains open for the
PAM session lifetime; EOF/HUP releases the session.

The daemon ingress accepts an already-listening AF_UNIX stream socket,
checks SO_PEERCRED and requires the configured peer UID (production policy
should normally be UID 0), then incrementally reads the fixed-size record
without blocking the event loop. It rejects short/closed requests, invalid
magic/version/size, nonzero reserved bytes, invalid remote flags, unterminated
or control-character metadata, and UIDs absent from the daemon's NSS view.

The target login UID is intentionally not compared to the socket peer UID:
privileged PAM stacks commonly create sessions for other accounts. The
peer UID authorizes the PAM client process; the payload UID selects the
account and is independently checked through NSS. Metadata is bounded and
validated but remains descriptive input, not authorization.

The record uses native-endian fixed-width fields and is local-host/ABI only.
The daemon must create and protect the listening socket in a root-owned
runtime directory, pass only its listening fd to the event loop, and call
`dl_pam_ingress_accept()` for accepted connections. Call
`dl_pam_ingress_step()` when a pending client is readable; after it reports
complete, monitor `dl_pam_ingress_peer_closed()`. Destroy each ingress
object on errors or after disconnect.

The PAM module and protocol ingress are implemented, but a complete daemon
entry point, secure runtime-directory/socket creation, PAM response/ack
protocol, installation rules, and end-to-end system PAM tests remain
necessary before production deployment.
