# Handoff — syscall Linux-compliance campaign COMPLETE

**Branch:** `main` (clean, builds both arches, boots to login — verified this session).
**Plan of record:** `syscall-compliance-ledger.md` (repo root, on main) — 21 rows,
all DONE. The campaign is finished.

## Status: 21/21 rows DONE + merged
A 4-reviewer audit found garbage stubs + a legacy "ghost" dispatcher. We removed
the ghost and fixed every routed syscall to full Linux semantics, one PR per row.
All 21 rows are merged; each new-behavior row is boot-verified with a `/bin/*_probe`.

Foundational: ghost-dispatcher removal (#2794), MM COW-invariant harness (#2792),
pmm free-while-mapped debug-gate (#2793).

Rows (PRs #2795–#2827): S1/S2 seccomp+landlock fork inheritance, D1 pwritev,
D2/D3 sync+syncfs, D4/G9 SysV shm + shmctl IPC_STAT, D5 ext4 chmod/chown/utimes
persist (#2809), F1 userfaultfd MISSING-mode (#2815, `uffd_probe`), F2 pkey ENOSYS,
F3 libaio (#2817, `aio_probe`), F4 quotactl faithful no-quota (#2819, `quota_probe`),
G1 kill(-1), G2 nanosleep EINTR, G3 per-task cputime getrusage/times (#2821,
`cputime_probe`), G4 robust-list crash-path recovery (#2824, `robust_probe`),
G5 seccomp arg[5], G6 process_madvise/mrelease (#2827, `pmadvise_probe`),
G7 mlock range, G8 signalfd mask-update + full siginfo (#2830?, `signalfd_probe`),
X1 drop NR_LISTNS.

## What's next (pick up here)
The syscall-compliance campaign is done. Next work is the master plan `00§3`
phase ladder — audit "what phase are we actually in" (lowest unfinished phase)
before starting. The kernel boots to a systemd login on both the syscall surface
and userspace; the natural next targets are whatever `00§3` marks as the current
phase gate. Read `docs/00§3` + `docs/MANIFEST.md` first.

## Gotchas / facts (keep)
- qemu MCP GOTCHA: `qemu_start paused=false` still leaves the CPU HALTED at the
  gdb stub (RIP stuck at 0xec1a, serial empty). You MUST call `qemu_continue`
  once to actually run it (it blocks ~120s w/ no stop event on a healthy boot —
  expected; then `qemu_serial` shows the full boot). Not a GRUB hang.
- Boot-verify pattern used all session: worktree branch → detach the MAIN tree to
  the commit (`git checkout <sha>` in /home/nd/oxide/kernel, NOT the worktree —
  qemu MCP builds from the main tree) → `qemu_start rebuild_rootfs=true` → login
  → run `/bin/<probe>`. Restore `git checkout main` after.
- `metadata/index.md` counter merges conflict on nearly every PR (parallel lanes
  advance F/B); resolve by taking origin's higher F and your own bumped B.
- ipc/mm-pmm reach sched-side exit hooks via fn-pointer hooks (set_*_hook in
  sched::live, installed by kmain) to avoid dep cycles — mirror for new exit work.
- Commits authored `Chris Watkins <chris@watkinslabs.com>`, never Co-Authored-By.
