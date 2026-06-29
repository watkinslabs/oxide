//! `File` lifecycle: `f_count` / `get_file` / `fput` (Linux `__fput`).
//! A `File` is one open file description; its refcount IS the `Arc<File>`
//! strong count. `get_file` bumps it, `fput` drops one reference, and the
//! LAST `fput` runs the backend release hook (`inode->on_release`, Linux
//! `file_operations->release`) EXACTLY ONCE — never per intermediate fput,
//! never twice. This is the contract a dup'd / CLONE_FILES-shared description
//! relies on: pty master hangs up the slave once, a pipe's last writer fires
//! POLL_HUP once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vfs::file::{fput, get_file};
use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, InodeRef, KResult, OpenFlags, VfsError};

/// Serializes tests in this binary: every `File` drop runs through `dput`,
/// which touches the GLOBAL dentry hashtable / LRU. Holding this across each
/// test keeps a sibling test's File drop from interleaving on that shared
/// state.
static SERIAL: Mutex<()> = Mutex::new(());

/// Inode that counts `on_release` (last-ref) and `on_flush` (per-close) hook
/// fires, so the test can assert release-once. The counters live behind
/// `Arc` shared with the test body, since the inode itself is consumed by the
/// `File`.
struct RelCounter {
    releases: Arc<AtomicUsize>,
    flushes:  Arc<AtomicUsize>,
}
impl Inode for RelCounter {
    fn ino(&self) -> vfs::Ino { 0x5151 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
    fn on_release(&self) { self.releases.fetch_add(1, Ordering::SeqCst); }
    fn on_flush(&self) { self.flushes.fetch_add(1, Ordering::SeqCst); }
}

/// Build a `File` over a fresh `RelCounter`, returning the file plus the
/// shared release/flush counters.
fn file() -> (Arc<File>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let releases = Arc::new(AtomicUsize::new(0));
    let flushes  = Arc::new(AtomicUsize::new(0));
    let ino: InodeRef = Arc::new(RelCounter { releases: releases.clone(), flushes: flushes.clone() });
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    let f = File::new(ino, dentry, OpenFlags::O_RDWR);
    (f, releases, flushes)
}

/// A sole reference has `f_count == 1`; `get_file` raises it; `fput` of the
/// extra lowers it back. The release hook does NOT fire while a reference
/// remains.
#[test]
fn get_file_bumps_count_no_early_release() {
    let _g = SERIAL.lock().unwrap();
    let (f, releases, _flushes) = file();
    assert_eq!(f.f_count(), 1, "sole open file description has f_count 1");

    let dup = get_file(&f); // Linux get_file: f_count++
    assert_eq!(f.f_count(), 2, "get_file must bump f_count");
    assert_eq!(releases.load(Ordering::SeqCst), 0, "no release while refs remain");

    fput(dup); // drop the extra ref: f_count 2 -> 1, NOT the last
    assert_eq!(f.f_count(), 1, "fput of extra ref returns f_count to 1");
    assert_eq!(releases.load(Ordering::SeqCst), 0, "release must NOT fire on non-last fput");

    fput(f); // last ref: runs on_release exactly once
    assert_eq!(releases.load(Ordering::SeqCst), 1, "last fput runs release exactly once");
}

/// The crux: with two references, ONLY the second `fput` releases, and it
/// releases exactly once regardless of how many references existed. Pre-API
/// (no explicit fput) this same shape is what `Drop` guarantees; the test
/// pins it against any future refactor that might double-run or skip the
/// release hook.
#[test]
fn release_runs_once_on_last_fput() {
    let _g = SERIAL.lock().unwrap();
    let (f, releases, _flushes) = file();
    let a = get_file(&f);
    let b = get_file(&f);
    assert_eq!(f.f_count(), 3, "original + two get_file = f_count 3");

    fput(a);
    fput(b);
    assert_eq!(releases.load(Ordering::SeqCst), 0, "still one ref (original) held");

    fput(f);
    assert_eq!(releases.load(Ordering::SeqCst), 1, "release fires once, on the final fput");
}

/// `fput` is the release path, NOT the per-close flush path: dropping the
/// last reference runs `on_release` but never `on_flush` (that is
/// `FdTable::close`/`filp_close`). Guards against conflating the two hooks.
#[test]
fn fput_releases_but_does_not_flush() {
    let _g = SERIAL.lock().unwrap();
    let (f, releases, flushes) = file();
    fput(f);
    assert_eq!(releases.load(Ordering::SeqCst), 1, "fput runs release");
    assert_eq!(flushes.load(Ordering::SeqCst), 0, "fput must not run the per-close flush");
}
