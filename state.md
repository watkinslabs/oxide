# state.md — session hand-off

Main `09d4695a3`. ~25 PRs merged this session across ~15 concurrent lanes.
`scratch/known_issues.md` is the ledger of record; **read it before picking up work.**

## Ledger mechanics changed — read this first

- Lanes write findings to `scratch/issues.d/<branch>.md`, one file per lane.
  Never edit `scratch/known_issues.md` / `scratch/fixed-issues.md` from a lane —
  a single shared table conflicted on every PR of a 15-lane wave. The
  integration owner folds drops in and moves closed rows to `fixed-issues.md`.
  `tools/issues.sh` renders curated + drops, `--count` shows counts. (`D441`)
- Branch counters: `tools/next-branch.sh <TYPE>` maxes `metadata/index.md`
  against git refs + merge subjects. Trust the tool; the file lags constantly.
  `make counter-check` fails when the file is behind. (`C247`)
- **`git stash` is banned** — the stack is shared across worktrees; a concurrent
  pop destroyed one lane's tracked edits. Park WIP as a temporary commit. (`D440`)
- Conflict resolution and "verification must be able to fail" are now CLAUDE.md
  hard rules. Both were earned this session; the second caught the integrator
  resolving a conflict by taking main's ledger wholesale, silently dropping 5
  FIXED rows.

## Open, in priority order

1. **`cargo check -p net` is RED on main** — ungated `ipv4_options`/`send_control`/
   `raw4::tx` import the gated `sock_opts`. `--features hosted` and `cfg(test)`
   both mask it, which is why it landed. Blocks `cargo test -p fs`/`-p procfs`.
   Lane `B1674-hosted-check-gate` (fix + the missing hosted `cargo check` gate).
2. **`cargo test --workspace` is not green and its failing set varies run to run**
   (`fbcon`, `softirq`, `pmm`, `socket`, `drv-virtio-input`, and a `net` ethernet
   `unwrap()` on None at `stack/core.rs:193`). Every per-package "0 failed" claim
   this session is weaker than it reads. Lane `B1680-workspace-suite-determinism`.
3. **Unknown filesystem mount parameters are silently ACCEPTED**, so the
   option-support probe always answers "yes". In the desktop image systemd then
   enables `ProtectProc=`/`ProcSubset=` because `proc` claims `hidepid`/`subset`,
   while procfs ignores mount data entirely — a confinement userspace believes it
   applied is absent. Found by B1668; needs boot access to change safely.
4. **GNOME Settings + Files both SIGSEGV** (user-reported). GTK4 GSK **Vulkan**
   renderer; trigger is the `powervr_mesa` ICD plus at least one other — alone it
   is clean. Disproven: ICD count, the DRM render node (`chmod 000` still faults),
   the device-select layer, and a TLS-size theory (retracted — both libraries use
   the identical TLSDESC relocation). The kernel now prints an unhandled-fault
   report with the faulting instruction's file offset, so the next boot yields a
   real `ip`. Take that boot when the box is quiet.
5. **Syscall matrix tracks 319 of 385 syscalls** — 66 missing rows including
   `read`, `mmap`, `fcntl`, `ptrace`, `prctl`, `execveat`. Spot-checked ones all
   have slot files and dispatch entries, so it is a tracking gap; every
   IMPL/PARTIAL statistic was computed over 83% of the surface. Being filled with
   the existing `NEEDS-AUDIT` status, `DISPATCH-GAP` where no route exists.
6. **`exit_shm` does not exist** — a SysV segment whose creator exits is never
   unlinked, so it leaks until an explicit `IPC_RMID` and `kernel.shm_rmid_forced`
   cannot exist. Needs a `Weak<Task>` creator back-reference; keying on `cpid`
   recycles tids.
7. Protection keys, `memfd_secret`, `map_shadow_stack`, `userfaultfd` WP/MINOR —
   all blocked on real hardware enablement (CR4.PKE/PKRU, FEAT_S1POE/POR_EL0,
   HHDM huge-leaf split, CET/GCS). Scoped in the matrix notes; not deferrable.

## Landed worth knowing about

| Area | What |
|---|---|
| net | NET_RX per-CPU backlog + softirq drain replaces inline receive at 32 call sites; aarch64 stack margin −344 B (main was FAILING the gate) → +1352 B |
| net | TCP_DEFER_ACCEPT on real request socks; TCP_ZEROCOPY_RECEIVE + `mmap(2)` on TCP fds; AF_UNIX MSG_OOB; IPv4 options on transmit |
| net | SACK blocks were emitted to peers that never permitted them; a declined window scale was never taken back |
| sched | `RLIMIT_NICE`/`RTPRIO` defaulted to infinity, so the `setpriority`/`sched_setscheduler` ladders could never refuse; hard-limit raise checked the effective set, so userns root could raise any limit |
| sched | child CPU time folded at exit instead of reap — zombies, `WNOWAIT` peeks and auto-reaped children all counted |
| mm | `cachestat` returned an all-zero struct to every caller; `process_madvise` re-implemented dispatch instead of calling the work fn |
| keys | keyctl DH-compute + PKEY family; request-key upcall |
| gates | the routine gate compiled ZERO feature-gated code (pre-push skipped it on every PR-branch push); ~75 `debug-*` features were built by nothing, four rotted |

## Negative results — do not re-derive

- `timerfd_settime(flags=3)`, the polkitd `pidfd_open` EINVAL storm, and the
  systemd `fsconfig`/`mount_setattr` EINVALs are all **reference-correct**. The
  pidfd storm is polkitd passing `pid = 0`; the fsconfig/mount_setattr calls are
  systemd feature probes whose right answer is EINVAL.
- A runtime re-entrancy guard cannot fix inline receive depth — the stack walker
  follows static call edges; only breaking the edge through a function pointer works.
- TFO's queue bound and key are **not** per-socket options to inherit on accept;
  they belong to the listener's accept queue and the namespace.

## First command

    tools/issues.sh --count && gh pr list
