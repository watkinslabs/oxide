//! `File::f_pos_lock` (FMODE_ATOMIC_POS) — the pos-read -> I/O -> pos-update
//! region in `File::read`/`File::write` is serialized so concurrent ops on a
//! shared (dup / CLONE_FILES) open file description cannot interleave the
//! offset (file-D9). Linux holds `f_pos_lock` in `__fdget_pos` for seekable
//! files (regular/dir, FMODE_ATOMIC_POS) before `vfs_read`/`vfs_write`.
//!
//! Race shape (pre-fix): every concurrent writer reads `pos` (= 0), then the
//! inode I/O runs, THEN `pos` is stored — so all writers see the same stale
//! offset and clobber each other. The injected per-op delay widens that
//! window so the lost-update is deterministic without serialization. With the
//! lock, each op's offset pick + I/O + pos-store is atomic, yielding distinct
//! contiguous offsets (0, L, 2L, …) and a final pos == total bytes.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, Ino, InodeRef, KResult, OpenFlags, VfsError};

/// Per-op record of the (offset, len) the inode saw, plus a delay injected
/// inside each I/O call to widen the pos-update race window. `ft` lets the
/// same recorder pose as a seekable (Regular) or non-seekable (Fifo) inode.
struct Recorder {
    ops:   Mutex<Vec<(u64, usize)>>,
    delay: Duration,
    ft:    FileType,
}

impl Recorder {
    fn new(delay: Duration, ft: FileType) -> Arc<Self> {
        Arc::new(Self { ops: Mutex::new(Vec::new()), delay, ft })
    }
}

impl Inode for Recorder {
    fn ino(&self) -> Ino { 0xD9 }
    fn file_type(&self) -> FileType { self.ft }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        thread::sleep(self.delay);
        self.ops.lock().unwrap().push((off, buf.len()));
        Ok(buf.len())
    }
    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        thread::sleep(self.delay);
        self.ops.lock().unwrap().push((off, buf.len()));
        Ok(buf.len())
    }
}

fn file_for(rec: &Arc<Recorder>) -> Arc<File> {
    let ino: InodeRef = Arc::clone(rec) as InodeRef;
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

const N: u64 = 8;
const L: usize = 4;

/// Concurrent writers on ONE shared `Arc<File>` must produce N distinct,
/// contiguous offsets and advance pos by exactly N*L. Pre-fix this fails:
/// the widened window makes every writer record offset 0 (lost updates).
#[test]
fn concurrent_writes_do_not_interleave_pos() {
    let rec = Recorder::new(Duration::from_millis(3), FileType::Regular);
    let f = file_for(&rec);
    let mut hs = Vec::new();
    for _ in 0..N {
        let f = Arc::clone(&f);
        hs.push(thread::spawn(move || { f.write(&[0u8; L]).unwrap(); }));
    }
    for h in hs { h.join().unwrap(); }

    let mut offs: Vec<u64> = rec.ops.lock().unwrap().iter().map(|&(o, _)| o).collect();
    offs.sort_unstable();
    let want: Vec<u64> = (0..N).map(|i| i * L as u64).collect();
    assert_eq!(offs, want, "writers must see distinct contiguous offsets, not a clobbered cursor");
    assert_eq!(f.pos(), N * L as u64, "final pos must account for every write");
}

/// Same invariant for the read path: concurrent readers advance the shared
/// cursor without two reads landing on the same offset.
#[test]
fn concurrent_reads_do_not_interleave_pos() {
    let rec = Recorder::new(Duration::from_millis(3), FileType::Regular);
    let f = file_for(&rec);
    let mut hs = Vec::new();
    for _ in 0..N {
        let f = Arc::clone(&f);
        hs.push(thread::spawn(move || { let mut b = [0u8; L]; f.read(&mut b).unwrap(); }));
    }
    for h in hs { h.join().unwrap(); }

    let mut offs: Vec<u64> = rec.ops.lock().unwrap().iter().map(|&(o, _)| o).collect();
    offs.sort_unstable();
    let want: Vec<u64> = (0..N).map(|i| i * L as u64).collect();
    assert_eq!(offs, want, "readers must see distinct contiguous offsets");
    assert_eq!(f.pos(), N * L as u64, "final pos must account for every read");
}

/// Single-threaded sanity: the lock is transparent — sequential writes still
/// advance the cursor by the byte count each time.
#[test]
fn sequential_writes_advance_pos() {
    let rec = Recorder::new(Duration::from_millis(0), FileType::Regular);
    let f = file_for(&rec);
    for i in 0..N {
        assert_eq!(f.write(&[0u8; L]).unwrap(), L);
        assert_eq!(f.pos(), (i + 1) * L as u64);
    }
}

/// Non-seekable inodes (FMODE_ATOMIC_POS NOT set) skip the pos lock and still
/// complete — their I/O may park, so taking a non-sleeping lock across it
/// would be wrong. This proves the gate doesn't deadlock concurrent ops on a
/// fifo and that every op still runs to completion.
#[test]
fn non_seekable_skips_pos_lock() {
    let rec = Recorder::new(Duration::from_millis(1), FileType::Fifo);
    let f = file_for(&rec);
    let mut hs = Vec::new();
    for _ in 0..N {
        let f = Arc::clone(&f);
        hs.push(thread::spawn(move || { f.write(&[0u8; L]).unwrap(); }));
    }
    for h in hs { h.join().unwrap(); }
    assert_eq!(rec.ops.lock().unwrap().len() as u64, N, "every fifo write must complete");
}
