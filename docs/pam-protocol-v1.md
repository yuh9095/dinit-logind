# PAM socket protocol v1

The PAM module connects to the daemon's Unix stream socket at
`/run/dinit-logind/pam.sock` (compile-time override: `DL_PAM_SOCKET_PATH`).
It sends exactly one fixed-size `dl_pam_open_request` record and keeps the
connection open for the lifetime of the PAM session. EOF/HUP is the release
signal. The daemon must reject truncated records, extra bytes, unsupported
versions, invalid magic/size, unterminated strings, and unknown flag bits.

The request carries the target account UID resolved through NSS by the PAM
module, plus PAM service/TTY/remote metadata and optional display/session
environment values. This UID is not the Unix socket peer UID: a privileged
PAM stack commonly opens sessions for another account. The daemon must
authorize the peer independently (normally a root-owned, root-only socket
and a root peer), and must independently validate the requested UID and
account using its own NSS/policy path. Never treat the payload UID or metadata
as proof of peer identity.

The wire record uses native-endian fixed-width integer fields and is intended
only for local processes on the same host/ABI. A future protocol revision
must use an explicitly encoded byte order before cross-ABI support.

The current PAM module is an ingress client only. A daemon-side acceptor,
strict record parser, socket activation/permissions, and end-to-end PAM
tests are still required before this module is suitable for deployment.
