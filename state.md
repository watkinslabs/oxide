# Handoff — syscall Linux-compliance campaign

**Branch:** `main` @ `da059511` (clean, builds both arches, boots to login — verified this session).
**Plan of record:** `syscall-compliance-ledger.md` (repo root, on main) — 21 rows,
each with Status | Branch | Fix. THIS is the campaign tracker; read it first.

## What this is
A 4-reviewer audit of the syscall surface found garbage stubs + a legacy "ghost"
dispatcher. We removed the ghost and are fixing every routed syscall to full
Linux semantics, one PR per row. **14 of 21 rows DONE + merged**
(PRs #2791–#2809). 7 rows remain, all subsystem work.

## Done + merged (do NOT redo)
Foundational: ghost-dispatcher removal (#2794 — legacy `syscall::dispatch` table
gone; ENOSYS is the only fallback now), MM COW-invariant harness restored (#2792,
`cargo test -p vmm` = 138/0), pmm free-while-mapped scan gated to debug-fwm (#2793).
Compliance rows: S1/S2 seccomp+landlock fork inheritance (#2795), D1 pwritev
offset (#2796), D2/D3 sync+syncfs (#2797), G1 kill(-1) (#2798), G5 seccomp
arg[5] (#2799), G7 mlock range (#2800), X1 drop NR_LISTNS (#2801), G2 nanosleep
EINTR (#2803), D4+G9 real SysV shm + shmctl IPC_STAT (#2804), F2 pkey ENOSYS (#2805),
D5 ext4 chmod/chown/utimes persist (#2809 — B641: syscall notify_change now routes
through VFS i_op->setattr; ext4_setattr journals mode/owner/times; ext4 inode decoder
+ iget now load timestamps so utimes round-trips. Boot-verified: systemd init's
chmod/chown traffic clean to login).

## OPEN — 7 rows, resume here (severity order)
- **F1** userfaultfd: fs/src/userfaultfd.rs records ranges but the VMM demand-
  fault path never consults them; read() returns 0 forever. Wire fault → uffd_msg.
- **F3** libaio io_setup/submit/getevents (206-210,333): ENOSYS in sched/compat.rs.
- **F4** quotactl (179/443): ENOSYS in compat.rs.
- **G3** getrusage/times (98/100): report wall-clock + zeroed counters; need
  real per-task CPU-time accounting (sched/cputime.rs exists).
- **G4** set_robust_list (273): registered but thread-exit never walks the
  robust list to wake futex waiters (ipc futex + exit path).
- **G6** process_madvise/mrelease (440/448): fake success; resolve pidfd →
  target AS and apply advice / reap.
- **G8** signalfd (282/289): mask-update on existing fd no-op; siginfo only
  fills ssi_signo.

## How to resume (literal)
1. `cd /home/nd/oxide/kernel && git fetch origin main && git switch main && git merge --ff-only origin/main`
2. Read `syscall-compliance-ledger.md`; pick the top TODO (F1 userfaultfd).
3. Branch: next B counter is `metadata/index.md` B line = **642**; make
   `B<NN>-<title>` from origin/main, BUMP the B line, commit that bump.
4. Implement → both-arch build via
   `cargo run -q -p xtask -- kernel --arch x86_64` and `--arch aarch64` → both exit 0.
5. Update the ledger row to DONE, commit, `SKIP_SMOKE=1 git push -u`,
   `gh pr create`, `gh pr merge --merge --delete-branch=true`, ff-merge main.

## Gotchas / facts
- ipc crate CANNOT reach tmpfs/InodeFileBacking (layering) — shm backing is
  built in a syscalls-crate shim (`029_shmget.rs`); mirror that pattern if a
  work-fn crate needs fs types.
- Boot verified on `da059511` (post-D5): reaches `oxide Linux on ttyS0`.
  qemu MCP GOTCHA: `qemu_start paused=false` still leaves the CPU HALTED at the
  gdb stub (RIP stuck at 0xec1a, serial empty). You MUST call `qemu_continue`
  once to actually run it (it blocks ~120s w/ no stop event on a healthy boot —
  that's expected; then `qemu_serial` shows the full boot). Don't mistake the
  halted-CPU empty serial for a GRUB hang.
- Big-subsystem rows: build a hosted test FIRST (verify-left, `cargo test`) —
  e.g. drove ext4 setattr over mini-j.img for D5 (`setattr_persist_image`) — don't boot-loop.
- Commits authored `Chris Watkins <chris@watkinslabs.com>`, never Co-Authored-By.
