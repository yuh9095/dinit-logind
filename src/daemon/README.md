# daemon module

The daemon entry point owns startup/shutdown ordering, signals, configuration,
and the event loop. The Linux PAM ingress accepts connections from a protected
AF_UNIX listener, authenticates SO_PEERCRED, parses requests incrementally,
and returns a success acknowledgement only after creating a Core Session.
The event loop calls `dl_pam_ingress_step()` on readable pending clients and
monitors completed clients for disconnect. All calls run on the manager owner
thread.

The listener must live beneath a root-owned, non-writable runtime directory
and the allowed peer UID should be root for normal system PAM deployment.
