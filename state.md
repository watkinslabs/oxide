# Handoff — syscall Linux-compliance campaign

**Branch:** `main` @ `4fc8b602` (clean, builds both arches, boots to login).
**Plan of record:** `syscall-compliance-ledger.md` (repo root, on main) — 21 rows,
each with Status | Branch | Fix. THIS is the campaign tracker; read it first.

## What this is
A 4-reviewer audit of the syscall surface found garbage stubs + a legacy "ghost"
dispatcher. We removed the ghost and are fixing every routed syscall to full
Linux semantics, one PR per row. **13 of 21 rows DONE + merged this session**
(PRs #2791–#2805). 8 rows remain, all big subsystem work.

## Done + merged (do NOT redo)
Foundational: ghost-dispatcher removal (#2794 — legacy `syscall::dispatch` table
gone; ENOSYS is the only fallback now), MM COW-invariant harness restored (#2792,
`cargo test -p vmm` = 138/0), pmm free-while-mapped scan gated to debug-fwm (#2793).
Compliance rows: S1/S2 seccomp+landlock fork inheritance (#2795), D1 pwritev
offset (#2796), D2/D3 sync+syncfs (#2797), G1 kill(-1) (#2798), G5 seccomp
arg[5] (#2799), G7 mlock range (#2800), X1 drop NR_LISTNS (#2801), G2 nanosleep
EINTR (#2803), D4+G9 real SysV shm + shmctl IPC_STAT (#2804), F2 pkey ENOSYS (#2805).

## OPEN — 8 rows, resume here (severity order)
- **D5** ext4 metadata persist: chmod/chown/utimes apply in-core (vfs
  inode/metadata.rs set_perm/set_owner/set_times) but ext4 has NO
  setattr/write_inode → lost on inode eviction/reboot. Needs ext4
  InodeOps::setattr (journal i_mode/uid/gid/times) + dirty/writeback hook. BIGGEST.
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
2. Read `syscall-compliance-ledger.md`; pick the top TODO (D5).
3. Branch: next B counter is `metadata/index.md` B line = **641**; make
   `B641-<title>` from origin/main, BUMP the B line to 642, commit that bump.
4. Implement → both-arch build via
   `cargo run -q -p xtask -- kernel --arch x86_64` and `--arch aarch64` → both exit 0.
5. Update the ledger row to DONE, commit, `SKIP_SMOKE=1 git push -u`,
   `gh pr create`, `gh pr merge --merge --delete-branch=true`, ff-merge main.

## Gotchas / facts
- ipc crate CANNOT reach tmpfs/InodeFileBacking (layering) — shm backing is
  built in a syscalls-crate shim (`029_shmget.rs`); mirror that pattern if a
  work-fn crate needs fs types.
- Boot re-verify OVERDUE for post-#2801 merges (D4/G2/F2). Do one boot on main
  before trusting the full set — qemu MCP `qemu_start arch=x86_64` reached
  `oxide Linux on ttyS0` login last time (on base 77b5b154).
- Big-subsystem rows: build a hosted test FIRST (verify-left, `cargo test`) —
  e.g. drive ext4 setattr over an image for D5 — don't boot-loop.
- Commits authored `Chris Watkins <chris@watkinslabs.com>`, never Co-Authored-By.
