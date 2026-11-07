# Linux platform adapter

Linux-specific process identity and Unix socket peer credential acquisition
lives here.

- `process_identity.c` reads the peer PID's PID-namespace inode and process
  start time through a single opened procfs process directory. It rejects
  missing, inaccessible, or inconsistent process state.
- `peer_credentials.c` obtains PID, UID, and GID from kernel-provided
  `SO_PEERCRED` on a connected Unix-domain socket, then binds that PID to the
  procfs identity tuple.

The caller must obtain the PID from the connected socket, not from client
payload fields. These credentials identify the peer but do not grant
authorization; PAM policy, socket access policy, and Polkit checks remain
separate. If procfs identity cannot be verified, the helper fails closed.
