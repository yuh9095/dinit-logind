# PAM socket protocol v1 and daemon ingress

The PAM module connects to `/run/dinit-logind/pam.sock`, sends one fixed-size
`dl_pam_open_request`, and waits for a fixed-size `dl_pam_open_response`.
A successful response contains the daemon-generated session ID. The
connection remains open for the PAM session lifetime; EOF/HUP releases it.

The daemon ingress accepts an already-listening AF_UNIX stream socket,
checks SO_PEERCRED and requires the configured peer UID (normally UID 0),
then incrementally reads the fixed-size record without blocking the event
loop. It rejects invalid magic/version/size, nonzero reserved bytes, invalid
remote flags, unterminated or control-character metadata, and UIDs absent
from the daemon's NSS view. Truncated requests are rejected on EOF.

The target login UID is intentionally not compared to the socket peer UID:
privileged PAM stacks commonly create sessions for other accounts. The peer
UID authorizes the PAM client process; the payload UID selects the account
and is independently checked through NSS. Metadata is descriptive input,
not authorization.

The record uses native-endian fixed-width fields and is local-host/ABI only.
The daemon must create and protect the listening socket in a root-owned
runtime directory, pass its listening fd to the event loop, and call
`dl_pam_ingress_accept()` for accepted connections. Call
`dl_pam_ingress_step()` when a pending client is readable; after it reports
complete, monitor `dl_pam_ingress_peer_closed()`. Destroy ingress objects
on errors or after disconnect.

The PAM client, strict protocol parser, peer-UID policy check, NSS target
UID validation, success acknowledgement, and Core Session lifecycle helper
are implemented. A complete daemon entry point, secure runtime-directory
and socket creation, installation rules, and end-to-end system PAM tests
remain before production deployment.
