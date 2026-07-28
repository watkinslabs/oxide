# state.md — session hand-off

## Headline

**The GNOME greeter renders.** QMP screendump at 1280×800: top bar, menu pill,
clock, power button on GNOME's `#222226`. First time this project has put pixels
on screen from a real session.

Syscall audit closed (`NEEDS-AUDIT` 198 → 0). Matrix: 165 IMPL / 193 PARTIAL /
22 LINUX-ENOSYS / 3 DONE. Four subsystem audits merged (~689 findings, all 14
blockers closed).

**Read first:** `scratch/linux-compliance-findings.md` (consolidated index) and
`scratch/partial-surface-2026-07-28.md` (the current PARTIAL re-triage —
`partial-gap-triage.md` is superseded and marked so).

## The one thing to know

**"Nothing deferred" is not done.** 193 PARTIAL rows = **162 real functional
gaps** from ~40 root causes (16 rows are user-ns id translation alone). The
re-triage found only **3** rows already-fixed-but-stale, not the ~30 expected:
every fix lane so far closed the **syscall-shim half** (errno order, ABI layout,
permission ladder) and left the **subsystem half** untouched. That is the shape
of the remaining work.

## Desktop state

`basic.target` 13.6s · `graphical.target` 19.4s · GNOME Shell 54.9s · greeter
paints. **Then it freezes** — five screendumps 150s→400s byte-identical, clock
stuck, alongside 183,326 `Failed to dispatch fd source: Invalid argument`.

Prime suspect, cited not fixed (findings §11): `DrmCardFileOps::read_file`
returns `Ok(0)` with no event queued; Linux `drm_read` returns `-EAGAIN` or
sleeps on `event_wait` and **never** returns 0 — a GLib fd source reads 0 as EOF.
Needs a waitqueue on the card fd. **This is the next lane.**

## Open, no lane

- **§10.2a — x86_64 runs syscalls (`IA32_FMASK`) and faults (interrupt gates) at
  IF=0 end to end**, where Linux enables interrupts in both. Only three
  `IrqGate::save_enable()` sites exist. Root cause under the CPU-stall class.
  A campaign, not a PR.
- §10.2b — `kalloc` free-list insert is an O(N) walk at IF=0.
- §10.4 — serial byte duplication unconfirmed; TX-side suspects only.
- Watch: `prctl(PR_SET_SECCOMP, MODE_FILTER)` was re-enabled after being
  EINVAL'd for an aarch64 boot kill. ARM passes now; revert is 3 lines in
  `seccomp/entry.rs::prctl_seccomp_op`.
- mountinfo render ~1.5 ms unaccounted at 780 mounts.

## Landed this session (selected)

| Fix | Effect |
|---|---|
| kalloc size-class front end | alloc+free on fragmented heap **128 µs → 20 ns**; `graphical.target` 265.9s → 19.4s; six services stopped blowing 90s timeouts |
| DRM ioctl size 64→56 | atomic modesetting was **complete and unreachable**; `MODE_SETPLANE` too (48 as 64) |
| `/proc/<pid>/root` | was ENOENT → systemd believed every tool was chrooted → udev refused → no seat → gdm dropped Wayland |
| `shared_pending` on ThreadGroup | `kill(pid,SIGTERM)` was ignored by any process whose main thread blocks it — every glib program |
| ext4 orphan list wired to `unlink` | unlink-while-open handed live blocks to the next allocation |
| `NEED_RESCHED` per-task | was per-CPU; task re-yielded once per intervening tick |
| TLB shootdown | blind 1e9-iteration spin + sender↔lock-waiter deadlock + per-round ACKs |
| `CLONE_SETTLS` on aarch64 | was x86-only: every pthread ran on **main's** TPIDR_EL0 |
| seccomp `BPF_RVAL` decode | `BPF_RET\|BPF_A` used `BPF_SRC`, so every `return A` became `return k` ≈ KILL |
| signal frames | arm64 `rt_sigreturn` let userspace run at **EL1**; same hole via `PTRACE_SETREGS` |

## Standing hazards (each cost real hours)

1. **Machinery with no callers is the dominant defect class** — now seven
   confirmed (orphan list, `timer_slack_ns`, `update_rtt`, `atime_needs_update`,
   `graft_mount` flags word, DRM `object_type`, a whole second `modeset.rs`
   property pair). **Grep call sites, not definitions.** Many "missing features"
   are wiring.
2. **Phantom tests.** `#[cfg(target_os = "oxide-kernel")]` files compile their
   `#[cfg(test)] mod tests` out **silently** while cargo prints "ok". Six
   shipped instances. Prove tests run by breaking an assertion.
3. **Hosted tests cannot see stack depth; boots cannot see host-cfg builds.**
   Three arm64 kernel-stack overflows were green in every hosted test and caught
   only by `boot-smoke` as `[BADSTACK]`; a host-target build break passed every
   gate we run.
4. **`SMOKE_KEEP_LOG` keeps only the LAST attempt** while a panic lands in the
   *failing* one. Use `SMOKE_KEEP_LOG_DIR`. This nearly produced a false
   retraction of a real panic.
5. **Don't mark on a process name** — unmeasurable if it writes nothing to
   serial. Use the sysrq task dump or `systemd.debug_shell=ttyS0` + `ps`.
6. **A weak implementation passes a naive test.** `AT_RANDOM`'s "two execs
   differ" passed with a clock-derived value. Assert against the real failure
   mode.
7. A consistency test that checks two of *our* values against each other proves
   nothing — the DRM `ioctl_size_fields_match_structs` test passed with both
   number and struct wrong. Anchor to Linux.

## First task next session

```
git -C /home/nd/oxide/kernel pull && cat scratch/linux-compliance-findings.md
```
Then the DRM `read_file` EOF bug (§11) — it is what stands between a painted
greeter and a live desktop.
