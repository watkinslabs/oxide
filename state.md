# state.md — session hand-off

## Headline
Branch **F649-vfs-object-model**. Goal: VFS/FS/MM 100% Linux-compliant + bootable GNOME. Master checklist: **/home/nd/oxide/TASKS.md** (check-off + SHAs); audit ledger: /home/nd/oxide/fix-ledger.md; MM plan: /home/nd/oxide/fix-mm.md. Self-paced /loop drives parallel background Workflow passes (disjoint crates; one boot/QEMU at a time).

## Done & committed (F649; NO Co-Authored-By; ~28 SHAs)
- VFS object model PHASE B COMPLETE: super_block (45a4304a), inode i_sb+iget (fd4dad65), dcache hash/RCU/d_op/LRU (289495a3), namei Nameidata+mnt_root crossing (f4315239), intrusive mount tree+mnt_ns+propagation+POLLPRI (b4234591), struct file f_path+fdtable (598ceb63).
- MM: page _mapcount + MmuOps displaced-PTE (d554cdaa); PageAnonExclusive+rmap (ef258f8c); **cross-CPU TLB shootdown = the boot-corruption ROOT CAUSE (245dd00b)**; per-mm cpumask targeted shootdown (74da2658).
- Per-fs kernfs trees D1 a-d: kernfs::PseudoDir + tmpfs/chrdev-bdev (974fcd7e/b96448f6), sysfs/tracefs own roots (6b7efa4b), procfs PROC_REG + /etc overlay (f8ccd078). devfs registry reduced to /dev+/etc.
- Syscalls: D3 stat owner/times+errno+AT flags (1a369116); D3b rename EXCHANGE/byte-paths/legacy-getdents (eececd4b); D4 permission/cred enforcement live (82299937).
- Sched: wait4/waitid interruptible (95301ddb); pidfd_send_signal wake + SIG_DFL fatal-terminate (d5bbf604).
All committed work builds x86_64+aarch64 green; vfs/sched/mm hosted tests pass.

## Boot status
The long-standing non-deterministic boot corruption was ROOT-CAUSED: missing cross-CPU TLB shootdown on SMP (stale writable TLB on peer CPUs after fork-COW write-protect). Fixed (245dd00b+74da2658) -> journald 55s timeout gone. Remaining boot is blocked at **getty.target** (never reaches sysinit/basic/local-fs/multi-user/graphical) by:
- BOOT-C: journald executor RUNTIME_DIRECTORY ESRCH "No such process" (deterministic 4/4) — a process-mgmt syscall returns ESRCH during the executor /run setup (executor-spawn ESRCH family).
- BOOT-A: residual intermittent COW corruption -> random-process SEGV + sd-executor parked on a corrupted futex word (0 ctx switches). A source the TLB+cpumask passes missed (GAP-1 / wrong-frame copy); hosted harness is green so it's production-only — needs a runtime detector.

## In flight
- wbu3tpimn BOOT-C/A: capture-first on what kills journald's executor (ESRCH vs futex-corruption), fix. Owns boot.
- wzxn4gude D2: ext4 data-path completeness (extents/alloc/htree/truncate). ext4 crate.

## Open (TASKS.md): BOOT-A, BOOT-C, zombie-reap (PID1 not reaping zombies per BOOT-B2 verify), Phase C page-cache (MM5/6 shmem+inode pagecache), A5 fault-path split, D2 ext4, D4b idmap/getattr-setattr, E final verify (re-run 303-ledger; 4-boot graphical+greeter; aarch64 boot lockstep).

## First command next session
```
cd /home/nd/oxide/kernel && git branch --show-current   # F649-vfs-object-model
git log --oneline -12 ; cat /home/nd/oxide/TASKS.md | head -60
# check in-flight wbu3tpimn (BOOT-C/A) + wzxn4gude (D2); commit precisely (only that workflow's files), tick TASKS.md
```

## Gotchas
- Repo = /home/nd/oxide/**kernel** (parent not a git repo; TASKS.md/fix*.md live in parent; oxide-images/ has runboot.sh + boot logs).
- NO Co-Authored-By (CI lint). Author Chris Watkins <chris@watkinslabs.com>.
- Parallel workflows OK on DISJOINT crates; only ONE may boot/QEMU. Commit each workflow's files separately (others' may be mid-edit). NEVER `pkill -f qemu-system` (self-matches the shell) -> use `pgrep -f qemu-system-x86 | xargs -r kill -9`.
- Boot verify: cd oxide-images; cargo run -q -p imagectl -- build-boot --profile live-gnome --arch x86_64; timeout -k 10s 150s ./runboot.sh 135 <log>. debug-syscall/debug-mnt features can trigger the residual COW wedge.
- Invariant (keep): grep -rnE 'record_dentry|DENTRY_RESOLVER|resolve_dentry|fn lookup\(&self, path: ?&str' crates/kernel = empty (zero path->dentry resolver).
