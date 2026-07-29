# ext4fix — Linux-compliance plan for the oxide ext4 driver

Status line: DRAFT 2026-07-08. Scope: `crates/kernel/ext4/` (8.6k LoC) vs Linux `fs/ext4` + `fs/jbd2`.
Method: 6-agent code audit (superblock/features, extents, directories/htree, allocation, jbd2, inode/xattr/ioctl/VFS).

## 0. Why this exists

Goal per project charter: a **full Linux-compatible** ext4 — no stubs, no "v1 subset". The driver
today mounts + reads + writes real images and boots glibc userspace, but the audit found a set of
**correctness / on-disk-interop / crash-safety** gaps that (a) let a real-Linux `e2fsck` see a
diverged filesystem after an oxide session, and (b) directly explain live bugs seen this session
(systemd-journald's journal stuck at 0 objects; file mtimes frozen at epoch 1970).

Classification in every table: **EXT4** = belongs in `crates/kernel/ext4/`; **VFS** = generic
concern that belongs in `crates/kernel/vfs/` (or the syscall layer) and that ext4 merely plugs into.
Several gaps are **split**: the generic dispatch/primitive is VFS, the on-disk semantics are ext4.

Severity: **P0** = corruption / data-loss / DoS / interop-breaking. **P1** = correctness gap that
diverges on-disk state from real ext4 (fsck-visible). **P2** = missing feature (clean failure today).
**P3** = perf / cosmetic / latent-only.

## 1. Likely root cause of the two live bugs

Both trace to **write-path metadata not being maintained**, not to the block layer (verified:
plain write, fallocate, mmap MAP_SHARED writeback, and cross-process writeback all persist correctly).

1. **mtime/ctime frozen at 1970** (`system.journal` showed mtime 0). `write(2)` / `write_at` /
   `fallocate` / `truncate` never call any `update_time`, and `init_inode` zero-fills a new inode's
   timestamps. So a file that is written but never `utimes`'d stays at epoch 0 forever. → **§7 item 1 (P0)**.
2. **journald journal stuck at 0 objects.** journald declares the prebuilt `system.journal`
   "corrupted or uncleanly shut down" and tries to rotate it; the rotation never yields a written
   journal. Two audit findings feed this: (a) **`s_state` is never marked dirty-on-mount / clean-on-unmount**
   (§2 item 2) so the on-disk state journald/fsck inspect never reflects the actual oxide session;
   (b) journald's rotate uses `FS_IOC_SETFLAGS` (chattr +C / NOCOW) which returns **ENOTTY** (§7 item 3).
   journald *tolerates* ENOTTY, so the decisive factor is most likely the stale `s_state` +
   frozen mtime making its integrity/rotation logic loop. **Fastest unblock: ship an empty
   `/var/log/journal` in the image** (images repo) so journald creates a fresh journal; the kernel
   fixes below make oxide-written journals durable/valid for a subsequent real-Linux boot.

## 2. Superblock / features / checksums / mount lifecycle

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **No metadata_csum VERIFICATION on read** (sb, GDT, bitmap, inode, extent-tail, dirent-tail all stamped on write but never checked on read) → silent corruption acceptance | `csum.rs` (verify fns absent); `mount/core.rs:14-32`; `mount/blocks.rs:12` | P0 | EXT4 |
| 2 | **`s_state` / `s_mnt_count` / `s_mtime` never read or written** — mount never marks fs not-clean, unmount never marks it clean. Direct interop breakage (fsck/journald see stale state) | absent repo-wide; `mount/core.rs:14-32` | P0 | EXT4 (hook fires from VFS mount/unmount) |
| 3 | **No unknown-feature gating**: INCOMPAT/RO_COMPAT bits are never masked against a SUPPORTED set; unsupported layouts (`inline_data`, `bigalloc`, `meta_bg`, `mmp`, `encrypt`, `project`) mount silently and get misinterpreted instead of refused (or RO-fallback) | `superblock.rs:14-23`; `mount.rs:29-55` (no `UnsupportedFeature` variant); `mount/core.rs:14-32` | P0 | EXT4 |
| 4 | `s_blocks_count_hi` (0x158) never merged → total block count truncates on >2³² block (>16 TiB) 64bit filesystems | `superblock.rs:49,128,163-166` | P1 (blocker >16TiB) | EXT4 |
| 5 | `flex_bg` (`s_log_groups_per_flex`) + `EXT4_BG_INODE_ZEROED` never parsed/tracked | `gdt.rs`, `superblock.rs` (absent) | P2 | EXT4 |
| 6 | `s_first_ino` (0x54) + `s_desc_size` (0xFE) hardcoded (10 / 64) instead of read | `superblock.rs:47-78`; `gdt.rs:15-17` | P2 | EXT4 |
| 7 | `write_descriptor_counters` unconditionally zeroes `bg_checksum` (relies on caller restamp; no guard) | `gdt.rs:89-112` | P3 | EXT4 |
| 8 | `s_default_mount_opts`, `s_lastcheck`, `s_kbytes_written` never read/written | `superblock.rs` (absent) | P3 | EXT4 |

**Structural fix:** items 1–3 are one root cause — `Mount::open` has no pre-flight stage. Add a single
`open()` prologue: (a) verify sb + GDT checksums (if metadata_csum), (b) mask features against
`SUPPORTED_INCOMPAT`/`SUPPORTED_RO_COMPAT`, hard-fail on unknown INCOMPAT and RO-fallback on unknown
RO_COMPAT, (c) mark `s_state` dirty + bump `s_mnt_count`/`s_mtime`; add an unmount hook that marks
`s_state` clean. Verify checksums on read at each `read_inode`/GDT-load/bitmap-load/dir-block/extent-block site.

## 3. Extent tree RW

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **Unbounded / no-cycle-guard tree descent** — `resolve_pblock` loops on on-disk `depth` with no `EXT4_MAX_TREE_HEIGHT` cap, no visited set, no per-block header validation; a corrupt/cyclic tree spins forever doing I/O (DoS on every read/write/append/truncate). Same in `insert.rs`, `collect.rs` (recursive → stack overflow), `truncate.rs`, `convert_unwritten_at` | `mount/blocks.rs:44-61` (+ `insert.rs:88-151,211-287`, `collect.rs:35-54`, `truncate.rs`) | P0 | EXT4 |
| 2 | Extent-tail checksum **stamped on write but never verified on read** (compounds #1; would have caught cyclic trees) | `extent_rw/inode_io.rs:56-63`, `csum.rs:228-240`; `inode.rs:263-272` only checks magic | P1 | EXT4 |
| 3 | `fallocate` always **eager** (writes real zero blocks) — never creates unwritten extents; O(len) I/O per fallocate vs O(1) metadata; introspection tools see eager writes | `extent_rw/write.rs:28-52` | P1 | EXT4 |
| 4 | Unwritten→written conversion **zeros the whole extent + flips the flag, no per-block split** (B655) — I/O-amplifying (1-block write into a 128 MB extent zeros 128 MB) and produces wrong extent-tree shape vs Linux `ext4_split_extent` | `mount/blocks.rs:177-252` | P1 | EXT4 |
| 5 | `PUNCH_HOLE` / `COLLAPSE_RANGE` / `INSERT_RANGE` / `UNSHARE` all `EOPNOTSUPP`; no middle-range remove/shift op exists | `sched/src/falloc.rs:33-38`; `rootfs/inode/regular.rs` | P2 | VFS (arg gate) + EXT4 (op) |
| 6 | **FIEMAP** not implemented — returns a *misleadingly empty* success, not an error (`filefrag`/backup/dedup tools get wrong layout) | `vfs/src/inode_ops.rs:208-212` default; no ext4 override | P2 | EXT4 (VFS scaffold present) |

**Verified good (don't regress):** multi-level tree WRITE + depth-grow (`insert.rs:73-85`),
extent merge (`records.rs:46-75`), unwritten-reads-as-zero, write-beyond-EOF append, full truncate
(shrink frees extents + prunes interior nodes + recomputes `i_blocks`).

## 4. Directories / htree

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **rmdir leaks the victim dir's data blocks** — `free_inode` only clears the inode bit; no extent-walk/free of the dir's blocks (unlike file `unlink`) | `rootfs/inode/special.rs:104-105`; `rootfs/ops.rs:204-212`; `ialloc.rs:112-113` | P0 | EXT4 |
| 2 | **rmdir doesn't decrement parent on-disk `i_links_count` nor `bg_used_dirs_count`** — parent nlink only ever grows; metadata drifts every mkdir/rmdir cycle | `rootfs/inode/special.rs:104-109` (in-memory `drop_nlink` only); cf. `ialloc.rs:356-360` | P0 | EXT4 |
| 3 | Cross-parent **directory rename doesn't rewrite `..`** nor adjust either parent's nlink (self-acknowledged in comments) — moved subtree's `..` points at the old parent | `rootfs/ops.rs:231-284` | P1 | EXT4 (+VFS) |
| 4 | htree **insert has no leaf split/rebalance** — a full leaf returns `DirFull`/ENOSPC even with free space (large-dir creates spuriously fail). (Correctly a hard error, not corruption) | `htree.rs:181-222` | P1 | EXT4 |
| 5 | htree is **never CREATED** — no linear→indexed conversion at the growth threshold; oxide-made dirs stay linear O(N) forever | `mount/dirs.rs:36-68`; `EXT4_INDEX_FL` only read | P2 | EXT4 |
| 6 | `INCOMPAT_FILETYPE` never checked before writing the `file_type` byte | `superblock.rs:15` (unused); `dir.rs:120-156` | P3 | EXT4 |
| 7 | `dir_nlink` (>65000 subdirs) not modeled — saturates u16 instead of pinning nlink=1 | `extent_rw/nlink.rs:6-18` | P3 | EXT4 |
| 8 | `RootfsState::read_dir` reads **block 0 only** (truncates multi-block dirs); readdir cursor re-scans by count not block+offset cookie | `rootfs/state.rs:113-124`; `rootfs/inode/special.rs:222-260` | P3 | VFS (helper) |

**Verified good:** linear dirent parse/layout, dir-block tail checksum, all 3 htree hash algos
(legacy/half_md4/TEA, e2fsprogs-vector-tested), `s_hash_seed`/`def_hash_version` threading,
lookup/create/mkdir/unlink/rename(+NOREPLACE/EXCHANGE/WHITEOUT)/link/symlink(fast+slow), `.`/`..`
creation + parent-nlink bump on mkdir, d_type end-to-end, linear-dir growth.

## 5. Block / inode allocation

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **Single-block-only allocator** (no mballoc / run-length search) — every multi-block write is a loop of independent journaled 1-block transactions; guarantees fragmentation + severe journal overhead | `balloc.rs:24-36,181-198`; loop callers `append.rs:63`, `insert.rs` | P1 (perf/shape) | EXT4 |
| 2 | **Orphan cleanup doesn't resume interrupted truncates** — a crash mid-truncate (nlink>0, size shrunk, blocks past i_size not freed) leaks those blocks; Linux truncates orphans to recorded size | `ialloc.rs:271-292` | P1 | EXT4 |
| 3 | **Backup superblocks / GDTs never updated** (sparse_super) — primary and backups drift every alloc/free, degrading `e2fsck -b` disaster recovery | `balloc.rs:138-168`, `ialloc.rs:151-158` (primary only) | P1 | EXT4 |
| 4 | No `flex_bg`-aware placement; no goal-block/in-group locality (only a group hint); no Orlov dir spread | `balloc.rs:24`, `ialloc.rs:53`; `create.rs:29,54` | P2 | EXT4 |
| 5 | `bigalloc` unsupported AND not rejected at mount — a bigalloc image's 1-bit-per-cluster bitmap is misread as 1-bit-per-block (silent corruption) | `balloc.rs:5-8`; no incompat gate | P1 (if encountered) | EXT4 |
| 6 | `s_first_ino` hardcoded to 10 instead of read from sb | `ialloc.rs:79-89` | P2 | EXT4 |
| 7 | No persistent prealloc / reservation windows (mballoc PA) — full bitmap re-scan per block | `balloc.rs` | P3 | EXT4 |
| 8 | No `s_reserved_gdt_blocks` / resize-inode awareness (needed only if online-resize is ever added) | `gdt.rs` (absent) | P3 | EXT4 |

**Verified good:** block free path (bitmap + counts + csum), inode-alloc counters +
`itable_unused`/`INODE_UNINIT`/`BLOCK_UNINIT` handling, orphan list (add/del/cleanup, O_TMPFILE +
unlink-while-open), and **per-group↔superblock free-count consistency maintained atomically on
every alloc/free** — do NOT regress this atomicity when adding multi-block allocation (#1).

## 6. jbd2 journaling

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **Journal never durably marks itself dirty before writing a transaction.** On-disk `s_start` reads 0 ("nothing to recover") for the entire `commit_metadata` window; a crash after the commit block but before target writes finish → recovery is **skipped**, violating the write-ahead guarantee | `journal.rs:73-121`; `superblock.rs:58` | P0 | EXT4 |
| 2 | **No REVOKE record emission** (replay parses+honors them, but nothing writes them). Freed-then-reused metadata block + crash → replay resurrects stale bytes over new content (classic jbd2 corruption class) | `emit.rs` (absent), `journal.rs:73` | P0 | EXT4 |
| 3 | **No checksums anywhere** (commit block, per-tag, journal sb) — a torn commit block is indistinguishable from a valid one; `CSUM_V2/V3` bits defined but never enforced | `emit.rs:62-70`, `descriptor.rs`, `superblock.rs:65-66` | P1 | EXT4 |
| 4 | File **data blocks bypass the journal**; ordered-mode is only implicitly approximated (no barrier/flush between data write and commit, no ordered-data tracking, no data=journal/writeback modes) | `extent_rw/insert.rs:64`, `append.rs`; `mount/core.rs:54-92` | P1 | EXT4 |
| 5 | Revoke matching not sequence-aware (flat `BTreeSet<u64>`) — will drop legitimate post-revoke rewrites once #2 exists | `replay.rs:154` | P1 (with #2) | EXT4 |
| 6 | One synchronous transaction per scope — no running/committing separation, no batching, no checkpoint list (fsync-latency on every metadata op) | `mount/core.rs:120-140`; `journal.rs:73-121` | P2 | EXT4 |
| 7 | Descriptor tags never carry a real UUID (always `SAME_UUID`) — self-consistent but real-Linux `jbd2`/e2fsck may reject | `emit.rs:47` | P2 | EXT4 |
| 8 | Journal sb missing fields; parsed `JBD2_INCOMPAT_REVOKE` bit read into `_revoke_on` and never used | `superblock.rs:8-23,57,65-66` | P3 | EXT4 |

**Verified good:** re-entrant nested scopes, mid-scope error → shadow discarded cleanly (in-memory,
no partial on-disk state). **Caveat:** confirm `alloc_block`/`free_block` bitmap+GDT+counter
mutations all route through the shadow (audit couldn't confirm); a direct device write inside a
failing scope would not roll back.

## 7. Inode metadata / xattr / ioctl / VFS integration

| # | Gap | file:line | Sev | Layer |
|---|-----|-----------|-----|-------|
| 1 | **write(2) never updates mtime/ctime**; `init_inode` zero-fills a new inode's timestamps → files stuck at epoch 1970 (the live bug) | `extent_rw/write.rs:21-106`; `rootfs/inode/regular.rs:114-124`; `ialloc.rs:392-397`; persist only via `meta.rs:36-61` called from setattr | P0 | EXT4 (VFS primitive `generic_update_time` already exists) |
| 2 | rmdir doesn't persist parent nlink decrement (dup of §4 item 2 — same fix) | `rootfs/inode/special.rs:85-107` | P0 | EXT4 |
| 3 | **`FS_IOC_GETFLAGS`/`SETFLAGS`, `FS_IOC_GETVERSION`, `FS_IOC_FIEMAP`, `EXT4_IOC_*`, `FITRIM` all unwired → ENOTTY** (chattr/lsattr/filefrag/e2fsprogs break). On-disk `i_flags` (0x20) never decoded — IMMUTABLE/APPEND/NOATIME decorative even where VFS enforces them | `syscalls/016_ioctl/core.rs:155`; `rootfs/inode/regular.rs:31-99` (no `fileattr_get/set`/`fiemap` override); `inode.rs:97-138` (no i_flags) | P1 | VFS (dispatch) + EXT4 (semantics) |
| 4 | **msync swallows writeback errors** (`let _ = writeback()`) and returns 0 — fsync correctly returns EIO; msync must too | `syscalls/026_msync.rs:23-32`; `rootfs/framecache.rs:419-429` | P1 | VFS/syscall (thin) + EXT4 (return real Result) |
| 5 | xattr **external block is read-only** — `store_ibody_xattrs` returns NoSpace on overflow (no external-block alloc/write/refcount/csum). **POSIX ACLs stored but never ENFORCED** (no `get_acl`/acl permission check anywhere) | `xattr.rs:246-270`; no `posix_acl` in `vfs::namei` | P1 | EXT4 (storage) + VFS (ACL enforcement) |
| 6 | `INCOMPAT_INLINE_DATA` unrecognized + no mount gate — small-file/dir inodes misparsed as extent headers | `superblock.rs:14-18`; `inode.rs:97-138` | P1 | EXT4 |
| 7 | `i_crtime` never decoded → `statx STATX_BTIME` always empty | `inode.rs`; `rootfs/inode/regular.rs:215-236` | P3 | EXT4 |
| 8 | `RO_COMPAT_HUGE_FILE` `i_blocks`-in-fs-blocks not handled → `st_blocks` off by blocksize/512 | `inode.rs:103-106` | P3 | EXT4 |
| 9 | statfs real+correct, but a stale hardcoded "32 MiB rootfs" fallback in `fill_usage` can mask a resolve failure; `f_fsid` hardcoded 0 | `syscalls/statfs_common.rs:89-106` | P3 | VFS |

**Verified good:** IBODY xattr round-trip incl `system.posix_acl_*` + `security.*`, statfs live
accounting, i_size 64-bit + partial-last-block, symlink fast/slow.

## 8. VFS-layer extractions (generic concerns to move/build in `crates/kernel/vfs`)

These are Linux-generic; ext4 should plug in, not own them:
- **`update_time` on write**: `File::write` (`vfs/src/file/io.rs`) should invoke
  `InodeOps::update_time`/`generic_update_time` (already exists, unreferenced) — then every fs gets
  mtime/ctime-on-write for free. (ext4 still must persist via its inode writeback.) — fixes §7 item 1 generically.
- **`FS_IOC_*` ioctl dispatch**: decode `GETFLAGS/SETFLAGS/FS_IOC_FIEMAP/GETVERSION/FITRIM` once in the
  syscall/VFS ioctl path and route to `InodeOps::fileattr_get/fileattr_set/fiemap` (traits already
  declared). ext4 supplies the semantics. — §7 item 3.
- **msync error propagation**: `flush_all_dirty()` returns an aggregate Result; `sys_msync` maps it
  to EIO like `sys_fsync`. — §7 item 4.
- **POSIX ACL enforcement**: a generic `get_acl` + `acl_permission_check` in `vfs::namei`; ext4 hands
  over the xattr bytes it already stores. — §7 item 5.
- **Page-cache / mmap writeback** (`Ext4FrameStore`): currently ext4-private but architecturally a
  shared mm/VFS address_space concern (tmpfs duplicates the same per-inode frame model). Candidate
  to hoist into a shared address_space so writeback error-surfacing + dirty tracking live once.

## 9. Sequenced implementation plan (status tracker — one focused PR per row)

Status legend: **TODO** unclaimed · **CLAIMED** branch cut, in progress · **REVIEW** PR open ·
**MERGED** on main · **PARTIAL** landed but incomplete (see note) · **WONTFIX** deliberate (see §10).
Update Status + Branch on every lane transition (per the claim-before-start HARD RULE).

**Phase A — stop corruption & the live bugs (P0):**

| Status | Branch | # | Item | Refs |
|--------|--------|---|------|------|
| VERIFIED-LOCAL | B656-ext4-mtime-on-write | A1 | write/fallocate/truncate → update mtime/ctime; create stamps atime/mtime/ctime/crtime; wire VFS `update_time` | §7.1 — *fixes frozen-1970* — hosted+2-arch green; boot-smoke pending clean env |
| VERIFIED-LOCAL | B657-ext4-sstate-lifecycle | A2 | Mount lifecycle: mark `s_state` dirty on open, clean on unmount; bump `s_mnt_count`/`s_mtime` | §2.2 — hosted+2-arch green |
| VERIFIED-LOCAL | B659-ext4-rmdir-reclaim | A3 | rmdir: free victim dir data blocks + persist parent nlink-- + `bg_used_dirs_count`-- | §4.1, §4.2, §7.2 |
| VERIFIED-LOCAL | B658-ext4-extent-descent-bound | A4 | Extent descent: `EXT4_MAX_TREE_HEIGHT` cap + strictly-decreasing-depth + bad-header reject (kills DoS) | §3.1 |
| TODO | — | A5 | jbd2 durability: write journal tail (`s_start`/`s_sequence`) BEFORE txn body | §6.1 |
| TODO | — | A6 | jbd2 REVOKE emission + sequence-aware replay | §6.2, §6.5 |

**Phase B — on-disk interop / fsck-clean (P1):**

| Status | Branch | # | Item | Refs |
|--------|--------|---|------|------|
| TODO | — | B1 | Feature gating + csum verification in `Mount::open` (mask INCOMPAT/RO_COMPAT; verify all csums on read; RO-fallback) | §2.1, §2.3, §3.2 |
| VERIFIED-LOCAL | B662-ext4-fs-ioc-flags | B2 | `FS_IOC_GETFLAGS/SETFLAGS` + `i_flags` decode/encode; VFS ioctl dispatch + ext4 `fileattr_get/set` | §7.3 |
| VERIFIED-LOCAL | B660-ext4-msync-eio | B3 | msync EIO propagation | §7.4 |
| VERIFIED-LOCAL | B662-ext4-fs-ioc-flags | B4 | Orphan cleanup resumes interrupted truncates | §5.2 |
| PARTIAL | B655 (merged) | B5 | True unwritten-extent split on write (replace whole-extent-zero); lazy-unwritten `fallocate` | §3.4, §3.3 |
| TODO | — | B6 | jbd2 commit/tag/journal-sb checksums + real descriptor UUID | §6.3, §6.7 |
| VERIFIED-LOCAL | B662-ext4-fs-ioc-flags | B7 | Cross-parent dir rename fixes `..` + parent nlinks | §4.3 |
| TODO | — | B8 | Backup superblock/GDT sync | §5.3 |
| VERIFIED-LOCAL | B666-ext4-xattr-external | B9 | xattr external-block write + csum (e2fsck-clean); ACL enforcement split to own VFS lane | §7.5 |
| TODO | — | B10 | inline_data read/write support (+ mount gate) | §7.6 |

**Phase C — features & perf (P2/P3):**

| Status | Branch | # | Item | Refs |
|--------|--------|---|------|------|
| VERIFIED-LOCAL | B665-ext4-fiemap | C1 | FIEMAP (physical extent map + FS_IOC_FIEMAP ioctl; 5 hosted tests) | §3.6 |
| TODO | — | C2 | `PUNCH_HOLE`/`COLLAPSE_RANGE`/`INSERT_RANGE` | §3.5 |
| TODO | — | C3 | htree create (linear→indexed) + leaf split on insert | §4.4, §4.5 |
| TODO | — | C4 | Multi-block allocator (mballoc-lite: run search + goal locality + flex_bg), preserving free-count atomicity | §5.1, §5.4 |
| PARTIAL | B667-ext4-crtime-btime | C5 | **crtime→statx STATX_BTIME DONE** (B667, 3 tests); remaining: 64bit `s_blocks_count_hi`, `s_first_ino`, `s_desc_size`, huge_file `i_blocks`, flex_bg | §2.4, §2.6, §5.6, §7.7, §7.8 |
| TODO | — | C6 | jbd2 batching/checkpoint (running vs committing txn) | §6.6 |

**Test discipline (every phase):** each fix ships with a hosted `cargo test -p ext4` against a real
`mke2fs` image fixture asserting the on-disk bytes; crash-safety items (§6.1/§6.2) need a
crash-injection test (write-then-drop-before-commit) — the audit noted `tests/journal_image.rs` only
covers happy paths. Boot-verify on both arches per the lockstep rule after any write-path change.

## 10. Not-in-scope (explicit)

- Online resize / `resize2fs` (`s_reserved_gdt_blocks`, resize inode) — no runtime need yet.
- `bigalloc`, `meta_bg`, `mmp`, `encrypt`, `project`, `verity`, `casefold` — **reject at mount** (Phase B item 7)
  rather than implement, until a concrete image needs them. Rejecting cleanly IS the compliant behavior.

---
## Session status update (2026-07-08) — correctness P0/P1 landed

DONE this session (all merged to main, hosted-tested + boot-verified):
- §4/§5 deep-tree extent leak on unlink/orphan-free → truncate_inode (B673).
- §2.1 metadata_csum VERIFY on read — superblock + every GDT descriptor + every
  inode (read_inode), MountError::BadChecksum→EIO (F695).
- §2.3 feature gating at Mount::open — refuse unknown INCOMPAT / unwritable
  RO_COMPAT (bigalloc etc.), MountError::UnsupportedFeature→EINVAL (B674).
- §2.4+§2.6 read s_blocks_count_hi (64-bit) / s_first_ino / s_desc_size (B675).
- §6.1 jbd2 write-ahead barrier: journal SB s_start=desc_at durable (flush) BEFORE
  target writes; crash mid-apply now replays (B676).
- (earlier) A1 mtime B656, buffered write-back B669, symlink-follow lookup B668.

RECLASSIFIED:
- §6.2 REVOKE emission — **N/A in the current single-transaction model**:
  commit_metadata checkpoints + cleans the journal (s_start=0) after EVERY txn,
  so there is never >1 un-checkpointed txn; the freed-then-reused-block
  resurrection revokes guard against cannot occur without txn batching (§6.6).
  Becomes required only if/when §6.6 (running-vs-committing batching) is added.

DONE (2026-07-09, F696 — read-verify completion, hosted-tested + x86 boot-verified
0 false BadChecksum through journal-flush; arm builds, arm lite image not built here):
- §2.1/§3.2 read-verify completed: external extent-block et_checksum
  (resolve_pblock, now reads interior nodes via the shadow-coherent
  read_metadata_block path so in-flight journal scopes don't false-reject),
  linear-dir dirent-tail (lookup_in_dir; htree dirs skipped — see backlog),
  block + inode alloc bitmaps (balloc/ialloc, uninit-group-aware via
  verify_{block,inode}_bitmap_csum_at). ino/gen now carried on Inode + stamped
  by read_inode. Negative test corrupt_external_extent_block_tail_is_rejected.

REMAINING (tracked backlog; normal-use fs correctness is now solid — these are
rare-corruption / crash-only / perf / feature / cosmetic):
- htree dir-block read-verify: dx_root / dx index blocks carry a `dx_tail`
  (ext4_dx_csum), NOT an ext4_dir_entry_tail, so the linear dirent-tail verify
  skips htree dirs. Needs a dx_csum verify + block-role awareness in the reader.
- §6.3 jbd2 commit/tag/sb checksums (torn-commit detection) — crash-only.
- §6.4 data-block ordered-mode journaling — crash-only.
- §3.3 lazy (unwritten) fallocate + §3.4 true per-block unwritten split — perf +
  tree-shape (data already correct: unwritten reads as zero). Do together.
- §4.4 htree leaf split + §4.5 htree create — large-dir write functionality.
- §5.1 mballoc multi-block allocator + §5.3 backup SB/GDT + §5.4 flex_bg/Orlov
  placement — perf/recovery.
- §7.6 inline_data, §7.5 POSIX ACL enforcement, §3.5 PUNCH/COLLAPSE/INSERT —
  features (clean-fail today, gated by feature-gating for inline_data).
- P3: §2.5 flex_bg parse, §2.8 sb misc fields, §4.6/4.7/4.8, §7.3 more ioctls,
  §7.8 huge_file i_blocks units.
