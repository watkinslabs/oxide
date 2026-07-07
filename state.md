# Handoff — syscall Linux-compliance campaign

**Branch:** `main` (clean, builds both arches, boots to login — verified this session).
**Plan of record:** `syscall-compliance-ledger.md` (repo root, on main) — 21 rows,
each with Status | Branch | Fix. THIS is the campaign tracker; read it first.

## What this is
A 4-reviewer audit of the syscall surface found garbage stubs + a legacy "ghost"
dispatcher. We removed the ghost and are fixing every routed syscall to full
Linux semantics, one PR per row. **17 of 21 rows DONE + merged**
(PRs #2791–#2817). F4 in progress (B644). Remaining after F4: G3/G4/G6/G8.

## Done + merged (do NOT redo)
Foundational: ghost-dispatcher removal (#2794 — legacy `syscall::dispatch` table
gone; ENOSYS is the only fallback now), MM COW-invariant harness restored (#2792,
`cargo test -p vmm` = 138/0), pmm free-while-mapped scan gated to debug-fwm (#2793).
Compliance rows: S1/S2 seccomp+landlock fork inheritance (#2795), D1 pwritev
offset (#2796), D2/D3 sync+syncfs (#2797), G1 kill(-1) (#2798), G5 seccomp
arg[5] (#2799), G7 mlock range (#2800), X1 drop NR_LISTNS (#2801), G2 nanosleep
EINTR (#2803), D4+G9 real SysV shm + shmctl IPC_STAT (#2804), F2 pkey ENOSYS (#2805),
D5 ext4 chmod/chown/utimes persist (#2809), F1 userfaultfd MISSING-mode fully
wired (#2815 — B642: per-VMA UffdContext trait in mm-vmm, do_handle fault
intercept parks faulter, COPY/ZEROPAGE frame-install + wake, uffd_msg ABI fix;
boot-verified `/bin/uffd_probe` PASS), F3 libaio (#2817 — B643: aio.rs sync
context registry, io_submit runs iocbs inline via pread64/pwrite64 work fns,
io_getevents drains completions; boot-verified `/bin/aio_probe` PASS).

## OPEN — 4 rows (+ F4 in flight), resume here (severity order)
- **F4** quotactl (179/443): IN PROGRESS on B644 — faithful no-quota-active
  dispatcher (Q_SYNC→0, GET*/state→ESRCH, mutate→EPERM w/o CAP_SYS_ADMIN),
  NOT ENOSYS (Linux w/ CONFIG_QUOTA doesn't ENOSYS it). `/bin/quota_probe`.
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
2. Read `syscall-compliance-ledger.md`; pick the top TODO (G3 getrusage/times,
   after F4/B644 lands).
3. Branch: read the B `next` counter in `metadata/index.md` (do NOT guess — F1's
   bump was lost once in a merge, so verify); make `B<NN>-<title>` from
   origin/main, BUMP the line, commit that bump.
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
