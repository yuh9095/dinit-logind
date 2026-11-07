# PAM ingress

The PAM ingress adapter is being developed in layers.

- The Linux PAM-session lifetime helper binds a connected Unix stream socket
  to one core Session.
- The leader PID/UID/GID and process identity tuple are acquired from kernel
  peer credentials and procfs; caller-supplied leader identity is ignored.
- The login UID and session metadata are supplied by the trusted PAM ingress.
  They are not inferred from the socket peer because privileged PAM stacks
  can create sessions for a different account.
- The daemon event loop must monitor the retained socket and call the
  non-blocking disconnect check. Disconnect closes the associated core
  Session. Explicit close and disconnect are idempotent.

This is not yet a loadable PAM module or a complete daemon socket protocol.
PAM handle data storage, PAM_USER/NSS resolution, module configuration,
authentication policy, and end-to-end integration tests remain future work.
