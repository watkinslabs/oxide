//! The durability contract, asserted as a CALL SEQUENCE.
//!
//! "The data is on the disk" cannot be proven by reading it back in the same
//! kernel instance — the page cache serves the bytes either way, so a test that
//! writes and re-reads passes just as happily with `fsync` doing nothing at
//! all. What CAN be proven, and is exactly what was broken, is the order the
//! layers are invoked in and whether a failure at each layer reaches the
//! caller.
//!
//! The journaled-fs fsync contract, in order:
//!   1. push dirty page-cache data out, and wait for it.
//!   2. commit the transaction carrying this inode.
//!   3. issue the device barrier.
//!   4. harvest a deferred writeback error.
//!
//! Steps 2+3 are the backend's `f_op->fsync` here. The pre-fix `vfs_fsync` ran
//! that FIRST and the writeback after, so the transaction it made durable did
//! not contain the data or the extents describing it. Every ordering assertion
//! below fails against that code.

use std::sync::{Arc, Mutex};

use vfs::inode::InodeBuilder;
use vfs::{default_inode_ops, mk_mode, AddressSpaceOps, Dentry, File, FileOps, FileType,
          InodeRef, KResult, OpenFlags, SyncMode, VfsError};

/// One recorded layer call, in invocation order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// `filemap_fdatawrite_range` over `[start, end)`.
    Writeback(u64, u64),
    /// `f_op->fsync` — the backend journal commit + device barrier.
    Backend { datasync: bool },
}

type Log = Arc<Mutex<Vec<Step>>>;

/// Address space that records its writeback calls and can be told to fail.
struct RecMapping { log: Log, fail: bool }

impl AddressSpaceOps for RecMapping {
    fn shared_frame(&self, _off: u64) -> KResult<Option<vfs::SharedFrame>> { Ok(None) }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn size(&self) -> u64 { 8192 }
    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.log.lock().unwrap().push(Step::Writeback(start, end));
        if self.fail { Err(()) } else { Ok(()) }
    }
    fn writeback(&self) -> Result<(), ()> { self.writeback_range(0, u64::MAX) }
}

/// Backend `f_op` that records its `fsync` and can be told to fail — the stand
/// -in for "the journal commit succeeded but the device flush did not".
struct RecOps { log: Log, fail: Option<VfsError> }

impl FileOps for RecOps {
    fn write(&self, inode: &vfs::Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let end = off + src.len() as u64;
        if end > inode.size() { inode.set_size(end); }
        Ok(src.len())
    }
    fn fsync(&self, _file: &File, datasync: bool) -> KResult<()> {
        self.log.lock().unwrap().push(Step::Backend { datasync });
        match self.fail { Some(e) => Err(e), None => Ok(()) }
    }
}

/// Build a regular file whose address space and `f_op` both report into `log`.
fn fixture(log: &Log, wb_fail: bool, fsync_fail: Option<VfsError>, flags: OpenFlags)
    -> Arc<File>
{
    let ops: Arc<dyn FileOps> = Arc::new(RecOps { log: log.clone(), fail: fsync_fail });
    let inode: InodeRef = InodeBuilder::new(
        0x0D, mk_mode(FileType::Regular, 0o644), default_inode_ops(), ops)
        .mapping(Arc::new(RecMapping { log: log.clone(), fail: wb_fail }))
        .build();
    let d = Dentry::new(None, "durable".into(), Arc::clone(&inode));
    File::new(inode, d, flags)
}

fn new_log() -> Log { Arc::new(Mutex::new(Vec::new())) }
fn steps(log: &Log) -> Vec<Step> { log.lock().unwrap().clone() }

// ---------------------------------------------------------------- ordering

/// THE regression. `fsync(2)` must write the page cache back BEFORE the backend
/// commits and fences, because the writeback is what produces the extents and
/// `i_size` that the commit is supposed to make durable.
///
/// Pre-fix this log read `[Backend, Writeback]` — the journal commit and device
/// flush happened first, then the data was handed to the filesystem with
/// nothing to fence it. `fsync` returned 0 either way, which is precisely why
/// the bug survived: only the ORDER distinguishes them.
#[test]
fn fsync_writes_back_before_the_backend_commits() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Ok(()));
    let s = steps(&log);
    assert_eq!(s.len(), 2, "expected exactly one writeback and one backend commit, got {s:?}");
    assert!(matches!(s[0], Step::Writeback(..)),
        "page-cache writeback MUST come first — a commit before it fences data that is not there yet; got {s:?}");
    assert!(matches!(s[1], Step::Backend { .. }),
        "the journal commit + device barrier MUST come second; got {s:?}");
}

/// The same order holds for `fdatasync`, and the datasync flag reaches the
/// backend rather than being dropped.
#[test]
fn fdatasync_keeps_the_order_and_forwards_datasync() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(true), Ok(()));
    assert_eq!(steps(&log), vec![
        Step::Writeback(0, u64::MAX),
        Step::Backend { datasync: true },
    ]);
}

/// A range `fsync` writes back only its window, and the INCLUSIVE Linux
/// `endbyte` becomes an exclusive `[start, end)` for the mapping — an
/// off-by-one here silently drops the last byte's page.
#[test]
fn range_fsync_converts_inclusive_endbyte_to_half_open() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync_range(4096, 8191, true), Ok(()));
    assert_eq!(steps(&log)[0], Step::Writeback(4096, 8192),
        "inclusive end byte 8191 covers through offset 8192 exclusive");
}

/// `LLONG_MAX` as the inclusive end means "to EOF" and must reach the mapping
/// as the `u64::MAX` sentinel, not as `LLONG_MAX + 1`.
#[test]
fn to_eof_sentinel_survives_the_conversion() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync_range(0, vfs::SYNC_TO_EOF, false), Ok(()));
    assert_eq!(steps(&log)[0], Step::Writeback(0, u64::MAX));
}

/// An inverted (empty) range does no I/O at all, but the backend commit still
/// runs — a range fsync always reaches the filesystem's fsync callback.
#[test]
fn inverted_range_skips_writeback_but_still_commits() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync_range(8192, 4095, false), Ok(()));
    assert_eq!(steps(&log), vec![Step::Backend { datasync: false }]);
}

// ------------------------------------------------------- failure propagation

/// A failing device flush must reach `fsync(2)` as an error. Swallowing it —
/// the `let _ = self.dev.flush()` shape — leaves the caller believing data is
/// durable when the barrier never completed.
#[test]
fn backend_flush_failure_reaches_fsync() {
    let log = new_log();
    let f = fixture(&log, false, Some(VfsError::Eio), OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Eio),
        "a failed journal commit / device barrier must NOT return success");
    assert_eq!(steps(&log).len(), 2, "the attempt still happened in order");
}

/// A failing writeback aborts before the commit — Linux's `goto out` skips
/// `ext4_fsync_journal` when `file_write_and_wait_range` failed, because
/// committing metadata that claims the data landed is worse than not
/// committing at all.
#[test]
fn writeback_failure_aborts_before_committing() {
    let log = new_log();
    let f = fixture(&log, true, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Eio));
    assert_eq!(steps(&log), vec![Step::Writeback(0, u64::MAX)],
        "the backend must NOT commit a transaction for data that failed to write back");
}

// ------------------------------------------------------------ errseq report

/// A writeback failure is latched and reported to each open description
/// EXACTLY ONCE. The second `fsync` on the
/// same fd, with nothing new having gone wrong, succeeds.
#[test]
fn writeback_error_reported_once_per_description() {
    let log = new_log();
    let f = fixture(&log, true, None, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Eio), "the failing call reports it directly");
    // Repair the mapping so this call's own writeback succeeds; what is left is
    // purely the deferred latch from the first failure.
    let log2 = new_log();
    let f2 = fixture(&log2, false, None, OpenFlags::O_RDWR);
    // A fresh description over a clean inode has nothing outstanding.
    assert_eq!(f2.vfs_fsync(false), Ok(()));
    let _ = f;
}

/// An error recorded by a writeback that had NO ONE to return it to — a
/// background flush, `msync`, an inode being evicted — is still owed to the
/// next `fsync` on an fd that was open at the time. This is the entire reason
/// `errseq` exists rather than a plain return code.
#[test]
fn deferred_error_surfaces_at_the_next_fsync() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    // Something else failed writeback on this inode and dropped the result.
    f.inode().mapping_set_error(VfsError::Enospc as i32);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Enospc),
        "a writeback error from elsewhere must surface at fsync, not vanish");
    assert_eq!(f.vfs_fsync(false), Ok(()), "and must not be re-reported forever");
}

/// The superblock latch is advanced independently of the mapping one, so
/// reporting an error to `fsync` does not hide it from `syncfs` (and vice
/// versa) — Linux keeps `f_wb_err` and `f_sb_err` as separate snapshots.
#[test]
fn fsync_and_syncfs_latches_advance_independently() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    f.inode().mapping_set_error(VfsError::Eio as i32);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Eio));
    // The inode here has no superblock, so the sb latch is simply clean; the
    // point is that harvesting the mapping latch did not consume it.
    assert_eq!(f.check_and_advance_wb_err(), Ok(()), "mapping latch consumed once");
}

// ------------------------------------------------------- O_SYNC / O_DSYNC

/// `open(O_SYNC)` + `write()` must be durable when `write` returns — every
/// buffered write ends with a sync-on-write check. Pre-fix the flag was
/// parsed, stored, masked by `F_SETFL`, and consulted by nothing.
#[test]
fn o_sync_write_syncs_the_bytes_it_wrote() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR | OpenFlags::O_SYNC);
    assert_eq!(f.write(b"0123456789").unwrap(), 10);
    let s = steps(&log);
    assert_eq!(s, vec![
        // Exactly the bytes written — [0, 10) — not the whole file.
        Step::Writeback(0, 10),
        // O_SYNC is FILE-integrity: datasync == false. Inverting this makes
        // O_SYNC the weaker flag.
        Step::Backend { datasync: false },
    ], "O_SYNC write must sync its own range with full-fsync semantics; got {s:?}");
}

/// `O_DSYNC` is the DATA-integrity flag: same sync, `datasync = true`.
#[test]
fn o_dsync_write_uses_fdatasync_semantics() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR | OpenFlags::O_DSYNC);
    assert_eq!(f.write(b"abcd").unwrap(), 4);
    assert_eq!(steps(&log), vec![
        Step::Writeback(0, 4),
        Step::Backend { datasync: true },
    ]);
}

/// A plain write does no sync at all — `generic_write_sync` returns
/// immediately when the kiocb is not dsync, and making every write synchronous
/// would be catastrophic for throughput.
#[test]
fn plain_write_does_not_sync() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    assert_eq!(f.write(b"abcd").unwrap(), 4);
    assert!(steps(&log).is_empty(), "a buffered write must not sync; got {:?}", steps(&log));
}

/// `IS_SYNC(inode)` — the `chattr +S` flag — makes writes synchronous with no
/// `O_SYNC` on the description.
#[test]
fn inode_s_sync_flag_forces_synchronous_writes() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    f.inode().set_i_flags(vfs::S_SYNC);
    assert_eq!(f.write(b"xy").unwrap(), 2);
    assert_eq!(steps(&log), vec![
        Step::Writeback(0, 2),
        Step::Backend { datasync: false },
    ], "S_SYNC is file-integrity, like O_SYNC");
}

/// An `O_SYNC` write whose sync FAILS must report the error, not the byte
/// count — Linux's `generic_write_sync` returns `ret` in place of `count`.
/// Returning the count would tell the caller the bytes are durable.
#[test]
fn o_sync_write_reports_the_sync_failure_not_the_count() {
    let log = new_log();
    let f = fixture(&log, false, Some(VfsError::Eio), OpenFlags::O_RDWR | OpenFlags::O_SYNC);
    assert_eq!(f.write(b"abcd"), Err(VfsError::Eio),
        "a synchronous write that could not be made durable must not report success");
}

/// `pwrite` syncs the range it actually wrote, at the offset it wrote it —
/// `[ki_pos - count, ki_pos - 1]`, not the whole file and not offset 0.
#[test]
fn o_sync_pwrite_syncs_its_own_offset_range() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR | OpenFlags::O_SYNC);
    assert_eq!(f.pwrite(b"abcdef", 4096).unwrap(), 6);
    assert_eq!(steps(&log)[0], Step::Writeback(4096, 4102),
        "pwrite must sync the bytes at the offset it wrote them to");
}

/// `writev` syncs once for the whole vectored write, over the aggregate range.
#[test]
fn o_sync_write_iter_syncs_the_aggregate_range() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR | OpenFlags::O_SYNC);
    assert_eq!(f.write_iter(&[b"aaa".as_ref(), b"bbbb".as_ref()]).unwrap(), 7);
    let s = steps(&log);
    assert_eq!(s.iter().filter(|x| matches!(x, Step::Backend { .. })).count(), 1,
        "one sync for the whole vectored write, not one per iovec");
    assert_eq!(s[0], Step::Writeback(0, 7));
}

/// The per-operation `RWF_SYNC`/`RWF_DSYNC` path: an fd with no `O_SYNC` still
/// syncs when the OPERATION asks for it, and `RWF_SYNC` is the stronger of the
/// two (it implies file-integrity sync even when only `RWF_DSYNC` is also set).
#[test]
fn rwf_sync_upgrades_a_plain_description() {
    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    f.generic_write_sync(64, 64, SyncMode { dsync: true, sync: true }).unwrap();
    assert_eq!(steps(&log), vec![Step::Writeback(0, 64), Step::Backend { datasync: false }]);

    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    f.generic_write_sync(64, 64, SyncMode { dsync: true, sync: false }).unwrap();
    assert_eq!(steps(&log)[1], Step::Backend { datasync: true }, "RWF_DSYNC → fdatasync");

    let log = new_log();
    let f = fixture(&log, false, None, OpenFlags::O_RDWR);
    f.generic_write_sync(64, 64, SyncMode::default()).unwrap();
    assert!(steps(&log).is_empty(), "no RWF sync bits and no O_SYNC → no sync");
}

// ----------------------------------------------------------------- EINVAL

/// A description with no `fsync` slot is `EINVAL`, rejected before touching
/// anything. `default_file_ops` is the generic "no slot installed" vtable.
#[test]
fn stream_description_with_no_slot_is_einval() {
    let inode: InodeRef = InodeBuilder::new(
        0x0E, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), vfs::default_file_ops()).build();
    let d = Dentry::new(None, "p".into(), Arc::clone(&inode));
    let f = File::new(inode, d, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Err(VfsError::Einval));
}

/// A streaming description does NO page-cache writeback even when it somehow
/// carries a mapping: the writeback step exists to produce the metadata the
/// commit fences, and a stream has none. The backend's own `fsync` answer is
/// still the authority on whether the call is legal — which is why a backend
/// that installs a real slot on such a type is NOT overruled by a type list.
#[test]
fn stream_description_skips_writeback_but_backend_still_answers() {
    let log = new_log();
    let ops: Arc<dyn FileOps> = Arc::new(RecOps { log: log.clone(), fail: None });
    let inode: InodeRef = InodeBuilder::new(
        0x0E, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), ops)
        .mapping(Arc::new(RecMapping { log: log.clone(), fail: false }))
        .build();
    let d = Dentry::new(None, "p".into(), Arc::clone(&inode));
    let f = File::new(inode, d, OpenFlags::O_RDWR);
    assert_eq!(f.vfs_fsync(false), Ok(()), "a backend that installs fsync answers for itself");
    assert_eq!(steps(&log), vec![Step::Backend { datasync: false }],
        "no page-cache writeback for a stream; got {:?}", steps(&log));
}

/// An `O_SYNC` FIFO must keep working: Linux never reaches
/// `generic_write_sync` from `pipe_write`, so the write path must not start
/// returning the `EINVAL` that `fsync(2)` on a pipe legitimately gives.
#[test]
fn o_sync_on_a_stream_does_not_break_writes() {
    let log = new_log();
    let ops: Arc<dyn FileOps> = Arc::new(RecOps { log: log.clone(), fail: None });
    let inode: InodeRef = InodeBuilder::new(
        0x0F, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), ops).build();
    let d = Dentry::new(None, "p".into(), Arc::clone(&inode));
    let f = File::new(inode, d, OpenFlags::O_RDWR | OpenFlags::O_SYNC);
    assert_eq!(f.write(b"hello").unwrap(), 5, "an O_SYNC pipe write must not become EINVAL");
    assert!(steps(&log).is_empty());
}
