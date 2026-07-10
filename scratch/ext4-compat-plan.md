# ext4 100% Linux-compat plan

Status: DRAFT 2026-07-09. Source: `scratch/ext42.md` audit + boot findings.
Rule: each lane = one branch = one PR, Linux-faithful, hosted-tested before merge.
No stubs/subset. `docs/16` (VFS), ext4 on-disk = upstream `fs/ext4` + `fs/jbd2`.

## Status legend
TODO | CLAIMED <branch> | IN-REVIEW <pr> | DONE <pr>

## Lanes (execution order = ext42 §7 + boot-blocker concurrency)

| # | Lane | Priority | Status | Branch/PR |
|---|---|---|---|---|
| 1 | Batch-drain durability | P0 | DONE | B688/#TBD |
| 1b | Batch read-your-writes (shadow-aware lookup) | P0 | DONE | B689 |
| 2 | Batch clean-drop ordering | P0 | DONE | B690 |
| 3 | Concurrent-create allocator race (boot mkdir EIO) | P0-boot | DONE | B691 |
| 4 | jbd2 revoke | P0/P1 | N/A (single-txn checkpoint) | B698 |
| 5 | jbd2 checksums (gated) | P1 | N/A (no real journal uses it) + gate | B698 |
| 6 | htree leaf split | P1 | DONE | B696 |
| 7 | htree creation + root-grow + node-split | P1 | DONE | B696 |
| 8 | htree dx checksum | P1 | DONE | B696 |
| 9 | allocator run-length | P1 | SUPERSEDED (extent coalescing) | - |
| 10 | Lazy unwritten extents (fallocate) | P1 | DONE | B692 |
| 11 | backup SB/GDT | P1 | NON-ISSUE (Linux keeps primary authoritative) | - |
| 12 | POSIX ACL enforcement | P2 | DONE | B695 |
| 13 | fallocate PUNCH_HOLE | P2 | DONE | B697 |
| 14 | huge_file i_blocks units | P2 | DONE | B694 |

## Lane details (Linux-faithful spec per lane)

### 1. Batch-drain durability (P0) — ext42 §2.1, §5.3
Linux: `super_operations->sync_fs` is THE per-superblock durability drain
(`sync_filesystem` → `->sync_fs(wait)`); freeze calls `sync_fs(1)`.
- `Ext4SuperOps::sync_fs` → call `self.st.mount.commit_batch()` (not the no-op
  `flush_pending_tx`). Keep the frame-cache `flush_all_dirty()` file-data pass first.
- Make `flush_pending_tx()` delegate to `commit_batch()` (or delete + fix callers).
- `commit_rootfs_journal()` stays as root helper but sync_fs becomes authoritative
  so non-root ext4 (`/home`) drains through the generic path.
- Test `batch_syncfs_persists_image`: begin_batch, create via VFS, `sync_filesystem`,
  remount, assert present. Extend to a non-root mount.

### 2. Batch clean-drop ordering (P0) — ext42 §2.2
Linux umount: `sync_filesystem` then clear `s_state` NEEDS_RECOVERY / mark clean,
each durable.
- `Ext4Mount::Drop`: `commit_batch()` → `mark_state_clean()` → `commit_batch()` so the
  clean bit is its own durable commit, not staged behind data in the same shadow.
- Test `batch_drop_clean_persists_image`: batch + mutate + drop → remount asserts both
  the mutation AND clean superblock.

### 3. Concurrent-create allocator race (P0-boot) — boot `mkdir err=5`
Boot only; every single-thread hosted path passes. Linux serializes bitmap/GDT
mutation per block-group (`ext4_lock_group` / bitmap buffer locks) + `s_inode_lock`.
- Audit `alloc_inode`/`alloc_block`/`try_alloc_in_group`/GDT counter RMW: any
  read-modify-write of a group bitmap or GDT slot NOT covered by a held lock across the
  RMW is the race (two creates in different parent dirs race the shared allocator →
  double-alloc/corrupt → Dir/Block/Inode err → EIO).
- Fix: hold the mount allocation lock (or a per-group lock) across bitmap read→set→write
  and the matching GDT/superblock counter update, Linux `ext4_lock_group` scope.
- Hosted repro: multi-thread `Arc<Mount>` create in distinct dirs; assert no error + no
  double-allocated inode/block + e2fsck clean. Then boot-verify `mkdir` EIO gone.

### 4. jbd2 revoke emission + sequence-aware replay (P0/P1) — ext42 §2.3
Linux jbd2: a freed metadata block gets a REVOKE record so replay of an older txn
cannot resurrect it. Batching keeps multiple ops per txn → revoke back in scope.
- Track blocks freed within a running txn; emit revoke blocks (`jbd2/emit.rs`) in the
  commit alongside descriptor/data/commit.
- Replay: honor revoke with txn sequence ordering (already parsed; make writer emit +
  replay sequence-aware).
- Crash-injection harness: free→reuse a metadata block in one batch, write journal, drop
  before targets, remount+replay, assert no stale resurrection.

### 5. jbd2 commit + descriptor-tag checksums (P1) — ext42 §2.4
Linux `JBD2_FEATURE_INCOMPAT_CSUM_V3`: commit block h_chksum + per-tag csum.
- Stamp commit-block checksum + descriptor tag checksum for the advertised feature set.
- Reject/҂gate journal csum feature bits we don't implement.
- Negative tests: corrupted commit/tag rejected on replay.

### 6. htree leaf split (P1) — ext42 §3.1
Linux `ext4_dx_add_entry` splits a full leaf: alloc new block, redistribute by hash,
insert dx entry, restamp dirent tail + dx csum.
- Implement in `htree.rs`; on `DirError::Full` split instead of returning DirFull.
- Test on a real htree image where the target leaf is full → insert must split; e2fsck.

### 7. htree creation / linear→indexed (P1) — ext42 §3.2
Linux converts a linear dir to indexed at the 2-block threshold (`make_indexed_dir`).
- Add dx_root creation when a linear dir crosses threshold; conservative until split
  solid. e2fsck clean after conversion.

### 8. htree dx checksum verify (P1) — ext42 §3.3
Linux `ext4_dx_csum_verify` for dx_root/dx_node (dx_tail, not dir_entry_tail).
- Add block-role-aware verify in htree lookup/insert.

### 9. Block allocator run-length + goal/locality (P1) — ext42 §4.1
Linux mballoc/goal-block: allocate runs near a goal, per-group locality.
- Run-length alloc with goal block; keep counter/csum updates in one journaled op.
- Stress test: extent count stays bounded for sequential large writes.

### 10. Lazy unwritten extents (P1) — ext42 §4.2
Linux: fallocate creates UNWRITTEN extents (no zeroing); a write splits the extent and
converts only the written subrange.
- Lazy fallocate (no eager zero); split unwritten extent around written subrange in
  `convert_unwritten_at`. FIEMAP `FIEMAP_EXTENT_UNWRITTEN` transition tests.

### 11. Backup superblock/GDT mirroring (P1) — ext42 §4.3
Linux sparse_super: mirror SB+GDT to backup groups (powers of 3/5/7).
- Mirror SB/GDT changes to sparse-super backups after primary updates.
- Test: primary vs backup descriptors match after alloc/free.

### 12. POSIX ACL enforcement (P2) — ext42 §5.2
Linux `posix_acl_permission` in `generic_permission` via `get_acl`.
- VFS ACL retrieval hook; ext4 parses `system.posix_acl_access/default`; integrate into
  `generic_permission`. Tests: ACL grant/deny beyond mode bits.

### 13. fallocate range ops (P2) — ext42 §6
Linux PUNCH_HOLE/COLLAPSE_RANGE/INSERT_RANGE/ZERO_RANGE.
- Implement the extent-tree edits; currently EOPNOTSUPP. FIEMAP + data tests.

### 14. huge_file i_blocks units audit (P2) — ext42 §6
Linux: with huge_file, `i_blocks` is in fs-blocks when `EXT4_HUGE_FILE_FL` + unit flag.
- Confirm st_blocks reporting; fix if 512-vs-fsblock unit wrong. stat tests.

## Cross-cutting
- Every lane: `e2fsck -fn` clean where on-disk layout changes (harness already runs it).
- Route ALL ext4 op errors through `vfs_error_from_mount` (ext42 §5.1) as lanes touch
  read/write paths.
- Non-`OXIDE_ROOTFS_IMG` fixtures for anything a CI gate needs.
