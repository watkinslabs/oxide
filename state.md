# Handoff — ext4 Linux-compliance campaign (ext4fix.md)

## STATUS
Working through `scratch/ext4fix.md` (6-agent ext4-vs-Linux audit → prioritized
plan with Status/Branch tracker). Building the P0/P1 fixes, hosted-verified.

**Boot-smoke is blocked right now**: this dev box's cold KVM boots are hanging
in SeaBIOS (RIP pinned 0x6b85/CS f000, zero serial) — 3/3 this session. One was
a stale `greeter-2026...` qemu instance contending (reaped via qemu MCP); the
other two are the documented ~50% cold-boot BIOS stall. Retry the boot later
(re-run once per lesson §8) or `pkill -9 qemu-system` first. Do NOT push code
that touches kernel/ until a clean boot verifies it (pre-push hook runs smoke).

## LANDED (local, NOT pushed — awaiting batch boot-verify)
**B656-ext4-mtime-on-write** (A1, §7.1) — the frozen-1970 fix.
- vfs: CLOCK_REALTIME provider (`vfs::inode_times::set_realtime_provider` /
  `realtime_now_ns`), installed in syscalls `install_vfs_hooks`. `File::write`/
  `pwrite`/`write_iter` call `file_update_time` → `inode.update_time(
  S_MTIME|S_CTIME|S_VERSION)` for regular files after a successful write.
- ext4: `Ext4RegInodeOps::update_time` persists mtime/ctime to the journaled
  on-disk inode; `init_inode` stamps atime=ctime=mtime=crtime=current_time;
  `fallocate` advances mtime/ctime. Timestamp offsets + `enc_time` centralized
  in `extent_rw/meta.rs::stamp_new_inode_times` (+ crtime @0x90/0x94).
- Test `ext4/tests/mtime_on_write_image.rs`: create stamps now (not epoch 0),
  write advances mtime/ctime with atime held, all persist across remount.
- Verified: ext4 86 + vfs 98 hosted tests green; x86_64 + aarch64 kernel build.
- NOTE: the commit also swept pre-existing `scratch/*→scratch/done/` archival
  renames (harmless doc moves that were uncommitted in the tree).

## NEXT (in order, per ext4fix §9 Phase A)
- **A2** s_state lifecycle: mark dirty on `Mount::open`, clean on unmount; bump
  s_mnt_count/s_mtime. (§2.2 — journald "uncleanly shut down" cause.) NOT started.
- A3 rmdir: free victim dir blocks + persist parent nlink-- + used_dirs--.
- A4 extent descent bound (MAX_TREE_HEIGHT + strictly-decreasing depth) — DoS.
- A5 jbd2 durability (mark journal dirty before txn). A6 REVOKE emission.

## PLANS-IN-SCRATCH RULE (new, in CLAUDE.md)
All plans/ledgers live in `scratch/` with Status-first + Branch columns.
`scratch/ext4fix.md` is the tracker — flip rows TODO→CLAIMED→REVIEW→MERGED.

## FIRST COMMAND NEXT SESSION
Clean env then verify A1 boot, or continue A2:
  `pkill -9 qemu-system 2>/dev/null; git -C . log --oneline -1 B656-ext4-mtime-on-write`
