# Session module

Session state machine, lookup, activation, release, and termination.

The asynchronous termination scheduler is implemented in `termination.c`.
It owns opaque operation payloads after successful scheduling, uses an
injectable monotonic clock for deterministic tests, retries failed final
SIGKILL operations, and completes pending operations during orderly shutdown.
The D-Bus adapter supplies the daemon-owned cgroup-v2 handle as its payload.
