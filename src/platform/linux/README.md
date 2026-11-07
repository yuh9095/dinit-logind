# Linux platform adapter

Linux-specific process identity acquisition lives here. The process identity
reader uses procfs and the PID namespace handle; callers must supply a PID
obtained from authenticated peer credentials. This layer does not decide
session ownership or authorization.

The reader opens the process directory once, reads its stat start-time twice,
and obtains the PID namespace inode from that process directory. It fails
closed when procfs data is missing, inconsistent, or inaccessible.
