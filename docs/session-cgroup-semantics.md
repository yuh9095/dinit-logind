# Session cgroup signaling and termination semantics

## Non-fatal signals

`dl_linux_cgroup_v2_session_signal_all()` walks the session cgroup and its
visible descendants. It reads each `cgroup.procs`, opens a pidfd for each
reported PID, and checks that the PID is still listed in the same cgroup
immediately before calling `pidfd_send_signal()`.

This provides two useful protections:

- A pidfd pins the referenced task, so a later PID reuse cannot redirect the
  signal to an unrelated task.
- The membership recheck avoids signaling a task that had already left the
  enumerated cgroup before the check.

It does **not** provide an atomic snapshot of the complete session. A process
may migrate after the membership check and before the signal is delivered.
Processes can also fork, exit, or move while the subtree is being enumerated.
Consequently, non-fatal whole-session signaling is best-effort and callers
must handle partial results. The function fails closed on traversal,
permission, pidfd, or parsing errors; it never falls back to `kill(pid, sig)`.

## Why cgroup.freeze is not a migration lock

Freezing a cgroup is not a solution to the membership race. The Linux cgroup
v2 documentation explicitly permits processes to enter and leave a frozen
cgroup through explicit migration. A frozen subtree therefore cannot be
treated as an immutable process set.

## SIGKILL

`dl_linux_cgroup_v2_session_kill_all()` uses the kernel's `cgroup.kill`
interface. Unlike userspace enumeration, the kernel operation handles
concurrent forks and is protected against process migration. It is the
required primitive for reliable whole-subtree SIGKILL; if unavailable, the
operation returns NotSupported rather than emulating it with a PID loop.

## Terminate() implementation requirements

A D-Bus `Terminate()` implementation must not equate signaling the session
leader with terminating the session. It must operate on the daemon-owned
session cgroup, report unsupported environments rather than silently falling
back to leader-only signaling, and keep its grace-period work asynchronous so
the D-Bus event loop is not blocked. The eventual SIGKILL phase must use
`cgroup.kill`. The initial non-fatal phase remains subject to the documented
best-effort migration semantics above.


## Asynchronous Terminate policy

`Terminate()` first sends `SIGTERM` to the daemon-owned session cgroup using pidfds, then returns to the D-Bus event loop. A monotonic deadline is tracked independently of the core Session object so PAM teardown cannot invalidate an accepted termination. At the deadline, the daemon uses `cgroup.kill` for the whole subtree. The default deadline is 90 seconds, matching systemd v262.2's default system-manager `DefaultTimeoutStopSec` / `default-timeout-sec`; it is not a timeout hard-coded by logind's D-Bus method itself.

The daemon checks that `cgroup.kill` is available before sending the initial signal. If the required primitive is unavailable, `Terminate()` fails closed. The initial signal sequence is `SIGTERM`, `SIGCONT`, then `SIGHUP`, matching the login session scope's `SendSIGHUP=true` policy. The Core Session records a persistent stopping flag, exposed as `State=closing`, so repeated `Terminate()` calls remain idempotent even after the deferred queue item has completed. During an orderly daemon shutdown (SIGTERM/SIGINT), pending terminations receive a final `cgroup.kill` attempt before their handles are released. A failed final kill is reported, but cannot be retried after the daemon exits. This is a best-effort shutdown guarantee, not an unconditional guarantee that every session is killed.

## Daemon crash and restart

The deferred termination queue is currently memory-only. If the daemon is killed abruptly (for example by SIGKILL, OOM termination, or a kernel crash), its deadlines and pending work are lost. The session cgroup itself may remain populated, but the next daemon instance does not currently reconstruct the old queue.

Startup must not compensate by killing every cgroup whose name begins with `login-`. Such cgroups can belong to still-valid login sessions, and a daemon restart alone is not evidence that those sessions should be terminated. The current implementation therefore leaves surviving cgroups alone after an unclean daemon exit; an accepted `Terminate()` may remain incomplete until another actor cleans up the session or an administrator intervenes.

A future crash-recovery implementation must persist an explicit termination intent before acknowledging the operation, bind that intent to a verifiable daemon-owned cgroup identity (not just a session ID or reusable path), use a reboot-safe deadline policy, and consume the record only after successful `cgroup.kill` or verified cgroup disappearance. Recovery must fail closed when ownership or identity cannot be revalidated. Until those conditions are implemented and tested, persistent recovery is intentionally not claimed.

If the initial pidfd-based SIGTERM pass fails after it may have made partial progress, the D-Bus method reports the failure but the daemon retains the cgroup handle and still performs the scheduled final `cgroup.kill`. This prevents a partial best-effort signal pass from silently abandoning the rest of the session.


The grace period defaults to 90 seconds and can be configured through the root-owned daemon configuration key `session_terminate_timeout_sec` (1–86400 seconds). This models systemd's configurable stop timeout rather than hard-coding a logind-specific interval. If `CLOCK_MONOTONIC` temporarily fails while processing pending work, the daemon postpones SIGKILL and retries on the next event-loop iteration; it never interprets a clock failure as an expired deadline.
