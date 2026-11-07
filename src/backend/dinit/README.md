# Dinit backend

This is the only module allowed to translate service lifecycle requests into
Dinit-native operations. It must not emulate systemd job objects or depend on
systemd manager APIs.

## Cgroup boundary

Dinit's Linux cgroup support is a **service process-placement feature**, not a
public runtime cgroup-management API for other daemons.

The upstream process launcher accepts a `run_in_cgroup` path. When configured,
it opens `/sys/fs/cgroup`, resolves the configured path, opens the already
existing cgroup directory, opens its `cgroup.procs`, and writes the launcher's
own PID before dropping privileges. The target cgroup therefore has to exist
before Dinit starts the service. This behavior is visible in upstream
`src/run-child-proc.cc` and the `run_proc_params` definition in
`src/includes/proc-service.h`.

Consequences for dinit-logind:

- Dinit should place the daemon in a dedicated, pre-created service cgroup.
- dinit-logind must not pretend that Dinit exposes a transient-scope API or a
  public operation for moving arbitrary existing processes between cgroups.
- Per-login-session cgroups, if enabled, are child cgroups owned by
  dinit-logind below its dedicated service cgroup. Their creation, membership,
  cleanup, and recovery are Linux cgroup-v2 operations performed by the
  dedicated session-cgroup adapter, not calls into a nonexistent Dinit API.
- The adapter must verify that the cgroup filesystem is cgroup v2, that the
  daemon is in the expected delegated subtree, and that the required files are
  writable. It must fail closed when delegation or filesystem permissions are
  missing.
- Never move a process into a session cgroup based only on a caller-supplied
  PID. The PAM peer identity must be authenticated and revalidated around
  membership changes.
- `Kill("all")` may target only the exact cgroup created and recorded for
  that Session. It must not fall back to a UID-wide kill, process-group kill,
  or an unrelated Dinit service cgroup.
- Session teardown and daemon shutdown must account for descendant processes
  and remove only cgroups created by dinit-logind. Crash recovery must not
  blindly delete unknown directories.

The daemon's Dinit service configuration and the cgroup adapter must agree on
one dedicated parent cgroup. A cgroup path supplied by an administrator is
configuration, not proof of ownership: the adapter must validate it at
runtime.

## Implementation order

1. Add a Linux cgroup-v2 adapter with directory-FD-relative operations and a
   testable filesystem boundary.
2. Establish and validate the daemon's dedicated parent cgroup.
3. Create one child cgroup per authenticated PAM Session and attach only its
   verified leader.
4. Add membership-safe `Kill("all")`, graceful termination, and teardown.
5. Test delegated and non-delegated cgroups, stale directories, PID reuse,
   cross-namespace identities, daemon restart, and both glibc and musl.

Until those steps are implemented and tested, `Kill("all")` remains
`NotSupported`. No cgroup behavior is implied merely because Dinit itself was
built with cgroup support.
