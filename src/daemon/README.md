# daemon module

The daemon entry point owns startup/shutdown ordering, signals, configuration,
and the event loop. The PAM ingress adapter is now available as a Linux
platform component: accept connections from a protected AF_UNIX listener,
call `dl_pam_ingress_step()` on readable pending clients, and monitor
completed clients for disconnect. All Core and ingress calls must run on the
manager owner thread.

The daemon must create the listener beneath a root-owned, non-writable
runtime directory and configure the allowed peer UID as root for the normal
system PAM deployment. Do not expose a caller-controlled peer-UID setting
through an untrusted config source.
