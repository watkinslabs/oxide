# ext42 - current VFS/ext4 failure analysis

Status: DRAFT 2026-07-09. Scope: current `crates/kernel/ext4`, `crates/kernel/vfs`, and syscall integration.
Method: local code audit against current HEAD plus `scratch/ext4fix.md` history. No broad test run in this pass.

## 1. Executive read

The original ext4 audit is not the current state. Most old P0/P1 on-disk corruption items have landed: mtime/ctime writeback, s_state lifecycle, rmdir reclaim, bounded extent descent, metadata_csum read verification, feature gating, 64-bit superblock fields, jbd2 WAL lead, FIEMAP, FS_IOC flags, msync EIO, orphan truncate resume, cross-parent rename `..`, external xattr block writes, buffered writeback, and rootfs symlink following.

The remaining failures now cluster around four newer or still-incomplete areas:

| Rank | Area | Current symptom risk | Main files |
|---|---|---|---|
| P0 | Batched journal drain semantics | metadata visible in memory but not durable on `sync_fs`; clean bit can race uncommitted shadow | `mount/core.rs`, `rootfs/ops/mountfs.rs`, `rootfs/mod.rs` |
| P0/P1 | Batched transaction crash semantics | batching reopens revoke/sequence concerns that were previously N/A under per-op checkpointing | `journal.rs`, `jbd2/emit.rs`, `jbd2/replay.rs` |
| P1 | Large / indexed directory writes | htree insert cannot split full leaves or create htree dirs; simple `mkdir` can become ENOSPC/DirFull on normal Linux-scale dirs | `htree.rs`, `mount/dirs.rs` |
| P1 | Alloc/writeback scaling | single-block allocator plus eager zero extension/fallocate causes high latency and fragmentation under boot workloads | `balloc.rs`, `extent_rw/write.rs`, `mount/blocks.rs` |

Bottom line: the core "can read/write ext4" path is much stronger than the old audit implied, but the performance fixes introduced cross-operation batching. That batching is now the highest-risk correctness boundary and should be stabilized before chasing lower-level ext4 features.

## 2. Current high-confidence defects

### 2.1 Batched root metadata is not drained by `SuperOps::sync_fs`

Evidence:
- Rootfs enables batching in `crates/kernel/ext4/src/rootfs/mod.rs:80` via `st.mount.begin_batch()`.
- `Mount::commit_batch()` is the real drain in `crates/kernel/ext4/src/mount/core.rs:212`.
- `Mount::flush_pending_tx()` is now explicitly a no-op in `crates/kernel/ext4/src/mount/core.rs:300`.
- `Ext4SuperOps::sync_fs()` still calls `flush_pending_tx()` instead of `commit_batch()` in `crates/kernel/ext4/src/rootfs/ops/mountfs.rs:37`.
- `sys_sync` and `sys_syncfs` call `ext4::commit_rootfs_journal()` after `sb.sync_filesystem()`, but that only covers the singleton root mount. Non-root ext4 mounts, such as `/home`, do not get a per-mount batch commit through `sync_fs`.

Impact:
- `syncfs(fd)` on a non-root ext4 mount can return success while batched metadata remains only in `MountState.shadow`.
- VFS `sync_filesystem()` semantics are wrong for ext4 mounts with batching enabled.
- `freeze_fs()` calls `sync_fs(true)`, so freeze can also miss a running batch if batching is later enabled outside root.

Fix plan:
1. Replace `flush_pending_tx()` use in `Ext4SuperOps::sync_fs()` with `commit_batch()`.
2. Either delete `flush_pending_tx()` or make it call `commit_batch()` when batching is active.
3. Add a hosted test: open `Ext4Mount`, call `begin_batch()`, create a file through VFS, call `sb.sync_filesystem()`, remount, assert file exists.

### 2.2 Clean-unmount write can be staged behind earlier batched metadata

Evidence:
- `Ext4Mount::Drop` reaps orphans and then calls `mark_state_clean()` in `rootfs/ops/mountfs.rs:125`.
- `mark_state_clean()` goes through `run_journaled()` in `mount/lifecycle.rs:45`.
- In batch mode, `run_journaled()` joins the existing running shadow instead of committing by itself (`mount/core.rs:163`).

Impact:
- On a batched mount, teardown can stage "filesystem clean" into the same uncommitted shadow as prior metadata and never drain it unless some other path calls `commit_batch()`.
- If clean state reaches disk without earlier intended metadata, or if neither reaches disk, fsck/journald signals become misleading.

Fix plan:
1. In `Drop`, call `commit_batch()` before `mark_state_clean()`.
2. Call `mark_state_clean()`, then commit again so the clean bit itself is durable.
3. Add an ignored or hosted remount test that starts a batch, mutates metadata, drops the mount, and validates both the mutation and clean superblock state.

### 2.3 Batching makes jbd2 revoke no longer optional

Evidence:
- Old `scratch/ext4fix.md` reclassified REVOKE emission as N/A because each op checkpointed and cleared `s_start=0`.
- Current code adds cross-operation batching in `MountState.batch` and keeps multiple operations in one shadow before `commit_batch()`.
- `jbd2/emit.rs` still only emits descriptor, data, and commit blocks. There is no revoke block emission.
- `journal.rs` writes one combined transaction at commit time; replay parses revokes but writer does not generate them.

Impact:
- Freed-then-reused metadata blocks inside one running batch can be represented ambiguously in a crash image.
- The current shadow map deduplicates by final target LBA, which is good for steady state, but it does not preserve "block was freed, then reused for different metadata role" intent for journal replay semantics.
- If batching grows toward Linux jbd2 running transactions, revoke emission and sequence-aware replay are back in scope.

Fix plan:
1. Add a crash-injection harness around one batched transaction that frees a metadata block, reallocates it for a different role, writes journal but drops before targets, then remounts and replays.
2. If the harness can produce stale resurrection, implement revoke emission.
3. Make replay revoke tracking sequence-aware before allowing multiple uncheckpointed transactions.

### 2.4 jbd2 checksums are still missing

Evidence:
- `jbd2/emit.rs:63` builds a zero-body commit block.
- Comments state real JBD2 commit timestamp/checksum are future work.
- No tag or commit checksum is stamped; replay accepts blocks by header/sequence shape.

Impact:
- Torn or stale journal blocks can be replayed as valid.
- Real Linux/e2fsck interop remains weaker than metadata_csum coverage on ext4 metadata proper.

Fix plan:
1. Implement commit block checksum and descriptor tag checksum for the supported journal feature set.
2. Gate or reject journal checksum feature bits that are advertised but not implemented.
3. Add corrupted commit/tag negative tests.

## 3. Directory path: simple operations can still fail at Linux scale

### 3.1 htree leaf split is absent

Evidence:
- `htree_insert()` descends to the covering leaf and returns `MountError::DirFull` on `dir::DirError::Full` (`htree.rs:181` onward).
- Comments explicitly say split/rebalance is not implemented.

Impact:
- `mkdir`, `create`, `link`, and `symlink` in a populated indexed directory can fail with ENOSPC even when the filesystem has free space.
- This maps directly to "simple things fail" under systemd, journald, package-manager, or large `/usr/bin` style directories.

Fix plan:
1. Implement htree leaf split: allocate a new dir block, redistribute dirents by hash, update dx entries, restamp dirent/dx checksums.
2. Add tests using a real htree image where the target leaf is full and insertion must split.

### 3.2 htree creation is absent

Evidence:
- Linear directories grow by appending blocks in `mount/dirs.rs:36`.
- No linear-to-indexed conversion exists when directory size crosses ext4's indexing threshold.

Impact:
- Oxide-created directories remain linear forever, giving O(N) lookup and large boot-time cost.
- Directories made under Oxide can diverge structurally from Linux-created ext4 directories.

Fix plan:
1. Add dx_root creation for growing directories.
2. Keep a fallback threshold conservative until split is correct.
3. Test Linux `e2fsck -fn` cleanliness after conversion.

### 3.3 htree checksum verification is incomplete

Evidence:
- `lookup_in_dir()` verifies dirent tails only when `EXT4_INDEX_FL` is not set (`mount/dirs.rs:113`).
- Comment notes htree dx_root/dx_node use `dx_tail`, not `ext4_dir_entry_tail`.

Impact:
- Linear dirs get read-time checksum protection; indexed dirs do not.
- Corrupt htree index blocks can misroute lookup or insert without being rejected early.

Fix plan:
1. Implement `ext4_dx_csum_verify` for dx_root and dx_node blocks.
2. Add block-role-aware verification in htree lookup/insert.

## 4. Allocation and writeback path

### 4.1 Block allocator is still one-block-at-a-time

Evidence:
- `alloc_block()` loops groups and `try_alloc_in_group()` returns one block (`balloc.rs:19`).
- Multi-block write/fallocate paths repeatedly call single-block append/alloc.

Impact:
- Severe fragmentation.
- High journal metadata volume.
- Boot workloads that write many small files or grow large files pay avoidable latency.

Fix plan:
1. Add run-length allocation with a goal block and per-group locality.
2. Preserve current atomic counter/csum updates in one journaled operation.
3. Add stress tests that assert extent count stays bounded for sequential large writes.

### 4.2 Fallocate is eager and unwritten conversion is whole-extent

Evidence:
- `fallocate_inode()` writes zero blocks across the range (`extent_rw/write.rs:28`).
- `convert_unwritten_at()` zeros the whole unwritten extent and clears the flag (`mount/blocks.rs:216`).

Impact:
- Correct data results, but O(range) fallocate and high write amplification.
- A small write into a large preallocated journal file can zero far more data than Linux would.

Fix plan:
1. Implement lazy unwritten extents for fallocate.
2. Split unwritten extents around the written subrange instead of converting the whole extent.
3. Pair with FIEMAP tests that verify `FIEMAP_EXTENT_UNWRITTEN` transitions.

### 4.3 Backup superblocks/GDTs are not maintained

Evidence:
- Primary counters and GDT slots are persisted in `balloc.rs` and `ialloc.rs`.
- No sparse-super backup update path is visible in allocation/free lifecycle.

Impact:
- Primary filesystem is usable, but recovery via backup superblocks/GDTs diverges after mutations.
- `e2fsck -b` disaster recovery quality is poor.

Fix plan:
1. Identify sparse-super backup groups from superblock features.
2. Mirror superblock/GDT changes to backups after primary metadata updates.
3. Add image test comparing primary and backup descriptors after alloc/free.

## 5. VFS integration gaps

### 5.1 Error mapping is improving but still risky

Evidence:
- `vfs_error_from_mount()` now maps `NoSpace` and `DirFull` to `ENOSPC` instead of blanket `EIO`.
- The dirty worktree adds a real-rootfs stress reproducer that treats capacity errors as expected and panics on checksum/Dir/Inode/Gdt faults.

Impact:
- Better observability, but several paths still collapse backend causes to `EIO`, especially regular read/write paths that use `map_err(|_| VfsError::Eio)`.

Fix plan:
1. Route all ext4 operation errors through a single mapper.
2. Add assertions in stress tests that expected capacity maps to ENOSPC and corruption maps to EIO.

### 5.2 POSIX ACLs are stored but not enforced

Evidence:
- xattr storage exists, including external blocks.
- VFS permission path uses generic DAC checks; no ACL lookup/enforcement path is visible in `namei/permission.rs`.

Impact:
- Filesystems carrying `system.posix_acl_*` xattrs will report/store ACLs but not enforce them.
- Security semantics differ from Linux.

Fix plan:
1. Add generic VFS ACL retrieval hook.
2. Have ext4 parse ACL xattrs into that hook.
3. Integrate ACL checks into `generic_permission`.

### 5.3 Non-root ext4 mounts are second-class for batching and sync

Evidence:
- `commit_rootfs_journal()` only reaches the published root mount (`rootfs/mod.rs:89`).
- Syscalls call that root helper after fsync/sync/syncfs.
- `Ext4Mount::open()` for `/home` does not enable batching today, but if enabled later, generic sync paths will miss it unless `SuperOps::sync_fs` owns the drain.

Impact:
- Correctness depends on batching staying root-only.
- Future ext4 mounts can silently lose durability semantics.

Fix plan:
1. Make per-superblock `sync_fs` authoritative.
2. Keep root helper only as a transitional compatibility hook, then remove it.

## 6. Feature gaps that should clean-fail or be planned

| Feature | Current state | Risk |
|---|---|---|
| inline_data | Unsupported and gated at mount | clean failure, but blocks images using inline_data |
| bigalloc/meta_bg/encrypt/project/verity/casefold | Unsupported and gated | clean failure |
| PUNCH_HOLE/COLLAPSE_RANGE/INSERT_RANGE | `sys_fallocate` returns `EOPNOTSUPP` | tools may degrade or fail |
| huge_file `i_blocks` units | listed as remaining in prior audit; not confirmed fixed | stat/st_blocks can be wrong |
| htree dx checksum | not implemented | corruption acceptance in indexed dirs |
| jbd2 checksum/revoke | not implemented | crash-only corruption class |
| mballoc/flex_bg/Orlov | not implemented | fragmentation/perf |

## 7. Recommended fix order

1. **Drain correctness first**: make `sync_fs`, freeze, drop, fsync/syncfs all call the real per-mount `commit_batch()` path. Add remount tests.
2. **Batch crash model**: either constrain batching to final-state-safe transactions with tests, or implement revoke emission and sequence-aware replay.
3. **Real-rootfs reproducer**: keep the dirty `real_rootfs_metadata_stress_then_journal_mkdir` style harness, but make a smaller non-ignored fixture version that does not require `OXIDE_ROOTFS_IMG`.
4. **htree split/create**: this is the most likely remaining reason normal creates/mkdirs hit ENOSPC/DirFull in non-full directories.
5. **allocator/fallocate**: run allocation and unwritten extents as a performance + tree-shape lane after correctness is stable.
6. **ACL and remaining ioctl/fallocate features**: fill Linux compatibility gaps once basic boot workloads stop tripping directory/batch behavior.

## 8. Suggested immediate tests

| Test | Purpose |
|---|---|
| `cargo test -p ext4 --test batch_mode_image -- --nocapture` | baseline batch create/rollback |
| `cargo test -p ext4 --test real_rootfs_mkdir_repro -- --ignored --nocapture` with `OXIDE_ROOTFS_IMG` | reproduce boot rootfs mkdir failures |
| New `batch_syncfs_persists_image` | prove `SuperOps::sync_fs` drains `commit_batch()` |
| New `batch_drop_clean_persists_image` | prove Drop commits pending metadata before/after clean bit |
| New `htree_insert_split_image` | prove large indexed dir insertion does not return false ENOSPC |
| New `journal_revoke_crash_image` | prove batched free/reuse replay cannot resurrect stale metadata |

## 9. Files to touch first

| Lane | Files |
|---|---|
| Batch drain | `crates/kernel/ext4/src/rootfs/ops/mountfs.rs`, `crates/kernel/ext4/src/mount/core.rs`, `crates/kernel/ext4/tests/batch_mode_image.rs` |
| Clean drop | `crates/kernel/ext4/src/rootfs/ops/mountfs.rs`, `crates/kernel/ext4/tests/sstate_lifecycle_image.rs` |
| htree split | `crates/kernel/ext4/src/htree.rs`, `crates/kernel/ext4/src/mount/dirs.rs`, new htree image tests |
| jbd2 checksum/revoke | `crates/kernel/ext4/src/jbd2/emit.rs`, `crates/kernel/ext4/src/jbd2/replay.rs`, `crates/kernel/ext4/src/journal.rs` |
| allocator | `crates/kernel/ext4/src/balloc.rs`, `crates/kernel/ext4/src/extent_rw/insert.rs`, `crates/kernel/ext4/src/extent_rw/write.rs` |

## 10. Notes on current worktree

`crates/kernel/ext4/tests/real_rootfs_mkdir_repro.rs` is already modified before this report. The diff adds a useful ignored metadata-stress reproducer for the real boot rootfs. Keep it as diagnostic input, but do not rely on it as the only gate because it needs an external image path.
