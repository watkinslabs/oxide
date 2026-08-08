// The MORE-DATA write hint's channel: from `WriteIocb.more` on the
// description-cursor write ladder down to the backend's `f_op->write` entry.
//
// The hint is only worth carrying if it ARRIVES, so these tests record what
// the backend was handed rather than what the caller asked for.

use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering as O};

use crate::file::WriteIocb;

/// What one backend write was told.
#[derive(Default)]
struct Seen {
    calls:    AtomicUsize,
    more:     AtomicBool,
    nonblock: AtomicBool,
    bytes:    AtomicUsize,
}

/// Backend that overrides the hint-carrying entry and records it.
struct HintOps(Arc<Seen>);
impl FileOps for HintOps {
    fn write_more_file(&self, _file: &File, _off: u64, buf: &[u8], nonblock: bool, more: bool)
        -> KResult<usize>
    {
        self.0.calls.fetch_add(1, O::Relaxed);
        self.0.more.store(more, O::Relaxed);
        self.0.nonblock.store(nonblock, O::Relaxed);
        self.0.bytes.fetch_add(buf.len(), O::Relaxed);
        Ok(buf.len())
    }
}

/// Backend that knows nothing of the hint and implements only the plain
/// blocking/non-blocking entries — every backend in the tree before the hint
/// existed. It must keep receiving writes unchanged.
struct LegacyOps(Arc<Seen>);
impl FileOps for LegacyOps {
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        self.0.calls.fetch_add(1, O::Relaxed);
        self.0.bytes.fetch_add(buf.len(), O::Relaxed);
        Ok(buf.len())
    }
    fn write_nonblock(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        self.0.nonblock.store(true, O::Relaxed);
        self.0.calls.fetch_add(1, O::Relaxed);
        self.0.bytes.fetch_add(buf.len(), O::Relaxed);
        Ok(buf.len())
    }
}

fn mk(ops: Arc<dyn FileOps>, flags: OpenFlags) -> Arc<File> {
    let i: InodeRef = InodeBuilder::new(1, mk_mode(FileType::Socket, 0o644), default_inode_ops(), ops)
        .private(Arc::new(())).build();
    let d = Dentry::new_root(Arc::clone(&i));
    File::new(i, d, flags)
}

/// A plain `write(2)` carries NO hint: nothing about an ordinary write says
/// more data follows, so a segment-forming backend must not hold the bytes.
/// # C: O(1)
#[test]
fn plain_write_carries_no_hint() {
    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(HintOps(Arc::clone(&seen))), OpenFlags::O_RDWR);
    assert_eq!(f.write(b"hello"), Ok(5));
    assert_eq!(seen.calls.load(O::Relaxed), 1);
    assert!(!seen.more.load(O::Relaxed), "an ordinary write is not a hinted one");
    assert!(!seen.nonblock.load(O::Relaxed));
}

/// The hint set on the iocb REACHES the backend. This is the whole point of
/// the channel: before it existed the flag was accepted at the syscall
/// boundary and had nowhere to go. # C: O(1)
#[test]
fn iocb_hint_reaches_the_backend() {
    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(HintOps(Arc::clone(&seen))), OpenFlags::O_RDWR);
    let iocb = WriteIocb { append: false, nowait: false, more: true };
    assert_eq!(f.write_iocb(b"hello", iocb), Ok(5));
    assert_eq!(seen.calls.load(O::Relaxed), 1);
    assert!(seen.more.load(O::Relaxed), "the hint must arrive, not be dropped in the ladder");
    assert_eq!(seen.bytes.load(O::Relaxed), 5);
    assert_eq!(f.pos(), 5, "a hinted write advances the cursor like any other");
}

/// The hint is independent of the blocking mode: an `O_NONBLOCK` description
/// hands the backend BOTH facts, because "do not wait" and "more is coming"
/// answer different questions. # C: O(1)
#[test]
fn hint_and_nonblock_are_independent() {
    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(HintOps(Arc::clone(&seen))),
               OpenFlags::O_RDWR | OpenFlags::O_NONBLOCK);
    let iocb = WriteIocb { append: false, nowait: false, more: true };
    assert_eq!(f.write_iocb(b"abc", iocb), Ok(3));
    assert!(seen.more.load(O::Relaxed));
    assert!(seen.nonblock.load(O::Relaxed));
}

/// A backend that never heard of the hint still gets its writes, on both the
/// blocking and the non-blocking entry — routing every cursor write through
/// the hint-carrying entry must not strand the backends that predate it.
/// # C: O(1)
#[test]
fn hintless_backend_still_receives_writes() {
    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(LegacyOps(Arc::clone(&seen))), OpenFlags::O_RDWR);
    assert_eq!(f.write(b"hello"), Ok(5));
    assert_eq!(f.write_iocb(b"!", WriteIocb { append: false, nowait: false, more: true }), Ok(1));
    assert_eq!(seen.calls.load(O::Relaxed), 2, "both writes landed");
    assert_eq!(seen.bytes.load(O::Relaxed), 6);
    assert!(!seen.nonblock.load(O::Relaxed), "a blocking description took the blocking entry");

    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(LegacyOps(Arc::clone(&seen))),
               OpenFlags::O_RDWR | OpenFlags::O_NONBLOCK);
    assert_eq!(f.write(b"xy"), Ok(2));
    assert!(seen.nonblock.load(O::Relaxed), "O_NONBLOCK still selects the non-blocking entry");
}

/// The gate order the cursor-write ladder owes every caller is unchanged by
/// the hint: an unwritable description is `EBADF` before the backend is
/// reached at all, hinted or not. # C: O(1)
#[test]
fn hinted_write_still_gated_on_fmode_write() {
    let seen = Arc::new(Seen::default());
    let f = mk(Arc::new(HintOps(Arc::clone(&seen))), OpenFlags::O_RDONLY);
    let iocb = WriteIocb { append: false, nowait: false, more: true };
    assert_eq!(f.write_iocb(b"nope", iocb), Err(VfsError::Ebadf));
    assert_eq!(seen.calls.load(O::Relaxed), 0);
}
