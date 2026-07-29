# procfs boot-smoke panic on main — `procfs read short`

Status: OPEN, unattributed. Found while boot-verifying F726/B1440; NOT caused by
either (see Evidence). Recorded here because it aborts the x86 boot at ~3.7s, so
it blocks every lane's smoke gate.

## Symptom

`make smoke-x86` on `05b5bb54b` (main) dies in early boot:

```
[3.727] [INFO]  dev-misc-smoke: ok
[PANIC] crates/kernel/procfs/src/live/boot.rs:66: procfs read short
[PANIC] halted
```

`boot.rs:66` is `kassert!(n >= prefix.len(), "procfs read short")` over six
files: `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`,
`/proc/sys/kernel/pid_max`, `/proc/sys/kernel/domainname`, `/proc/net/dev`.
The assert does not say which one, so step 1 for whoever picks this up is to
split it per-entry.

## Suspect mechanism (plausible, NOT confirmed)

`/proc/sys/kernel/domainname` must start `(none)` (6 bytes). Its reader hook is
`syscalls::hostname::domain_snapshot_current`:

```rust
pub fn domain_snapshot_current() -> Vec<u8> {
    current_uts_owner().and_then(|owner| dom_for(&owner).ok()).unwrap_or_default()
}
fn current_uts_owner() -> Option<NamespaceRef> {
    sched::live::current().and_then(|t| t.namespace_owner(NamespaceKind::Uts))
}
```

With no current task / no UTS owner — which is the case this early in boot —
`unwrap_or_default()` yields an EMPTY vec, so `n == 0 < 6` and the kassert
fires. `dom_for` already falls back to the global `domain_snapshot()` for the
initial owner; the no-owner path does not. `snapshot_current` (hostname) has the
identical shape and would have the identical bug.

If that is the cause, the fix is to fall back to the global snapshot when there
is no current UTS owner, in both `domain_snapshot_current` and
`snapshot_current` (`crates/kernel/syscalls/src/171_setdomainname.rs`).

## Evidence, and why it is NOT F726/B1440

- F726 touches `/proc/<pid>/status` only (`procfs/src/pid_status.rs`, umask
  accessor). It touches NONE of the six files this assert reads.
- A build containing ALL of F726's changes **passed** `make smoke-x86`,
  reaching `Reached target basic.target` in 124s on attempt 1. The panic
  appeared only after rebasing onto a main that had gained F724 (creds/userns
  id-map engine), F727 (uname/sysinfo/domainname), B1439 and F730.
- `/proc/sys/kernel/domainname` is exactly F727's audit surface.

## What is NOT established

Which commit introduced it. The bisect (boot `7900c22c7`, the commit before the
F726 merge) could not be completed: the dev box was running 6+ concurrent
`boot-smoke` invocations from sibling worktrees, and both bisect attempts died
with `make[1]: *** [Makefile:101: qemu-x86] Error 101` — a build collision over
shared target dirs, not a boot result. Two sibling worktrees were also deleted
mid-smoke (`wt-F728 (deleted)` in `/proc/<pid>/cwd`), which corrupts any run
still reading them.

**Re-run the bisect on a quiet box before trusting any attribution above.**
