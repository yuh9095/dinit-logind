# Runtime and linger module

The initial Turnstile-inspired implementation provides secure creation and
validation of per-UID XDG runtime directories and persistent, UID-keyed linger
markers in a trusted state directory.

Cleanup is deliberately conservative: it removes only an empty runtime
directory. It never recursively deletes user data. A later implementation
must prove race-resistant, mount-aware deletion before removing non-empty
contents.

The runtime and linger directories must be provisioned by packaging or the
service manager. In production, their trusted owner is root. This module is
unit-tested independently and is not yet wired into PAM ingress or the Dinit
user-service backend; those integrations are separate steps.
