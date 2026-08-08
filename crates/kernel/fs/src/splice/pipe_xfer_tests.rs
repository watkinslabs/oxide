// The pipe→output leg driven over a REAL pipe ring and a real open file
// description, so the MORE-DATA hint is observed where it has to arrive — at
// the output backend — rather than where it is computed.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use vfs::{Dentry, File, FileOps, Inode, InodeRef, KResult, OpenFlags};

use super::pipe_to_file;
use crate::pipe::{self, PipeData};

/// Per-batch record of what the output backend was handed. Kept as atomics —
/// one bit of `hints` per batch, in order — so the recorder needs no lock of
/// its own inside a `FileOps` impl.
#[derive(Default)]
struct Recorder {
    batches: AtomicUsize,
    hints:   AtomicU32,
    bytes:   AtomicUsize,
}

impl Recorder {
    fn new() -> Arc<Self> { Arc::new(Recorder::default()) }
    /// Record one batch and return its accepted byte count. # C: O(1)
    fn note(&self, more: bool, n: usize) {
        let i = self.batches.fetch_add(1, Ordering::Relaxed);
        if more { self.hints.fetch_or(1u32 << i.min(31), Ordering::Relaxed); }
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
    fn hints(&self) -> Vec<bool> {
        let mask = self.hints.load(Ordering::Relaxed);
        (0..self.batches.load(Ordering::Relaxed)).map(|i| mask & (1u32 << i.min(31)) != 0).collect()
    }
    fn bytes(&self) -> usize { self.bytes.load(Ordering::Relaxed) }
}

/// Output backend that accepts every batch whole.
struct RecorderOps(Arc<Recorder>);
impl FileOps for RecorderOps {
    fn write_more_file(&self, _f: &File, _off: u64, buf: &[u8], _nonblock: bool, more: bool)
        -> KResult<usize>
    {
        self.0.note(more, buf.len());
        Ok(buf.len())
    }
    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Output that takes at most `1` byte-count cap per batch, exercising the
/// partial-write bookkeeping alongside the hint.
struct ShortOps(Arc<Recorder>, usize);
impl FileOps for ShortOps {
    fn write_more_file(&self, _f: &File, _off: u64, buf: &[u8], _nonblock: bool, more: bool)
        -> KResult<usize>
    {
        let n = buf.len().min(self.1);
        self.0.note(more, n);
        Ok(n)
    }
    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Unique inode numbers for the synthetic output descriptions.
static NEXT_INO: AtomicUsize = AtomicUsize::new(0x5011_0000);

fn out_file(ops: Arc<dyn FileOps>) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed) as u64;
    let i: InodeRef = vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
                                             vfs::default_inode_ops(), ops).build();
    let d = Dentry::new_root(Arc::clone(&i));
    File::new(i, d, OpenFlags::O_RDWR)
}

/// A pipe holding `n` bytes, with a live writer and reader so neither side of
/// the leg reads EOF.
fn loaded_pipe(n: usize) -> (InodeRef, Arc<File>) {
    let i: InodeRef = pipe::make_pipe_inode().expect("pipe inode");
    let d = Dentry::new_root(Arc::clone(&i));
    let f = File::new(Arc::clone(&i), d, OpenFlags::O_RDWR);
    let p: &PipeData = pipe::pipe_data(&i).expect("pipe ring");
    p.writers.store(1, Ordering::Release);
    p.readers.store(1, Ordering::Release);
    let body = alloc::vec![b'x'; n];
    assert_eq!(pipe::fill(p, &body), n, "the ring took the whole fixture");
    (i, f)
}

fn ring(i: &InodeRef) -> &PipeData { pipe::pipe_data(i).expect("pipe ring") }

/// A batch that satisfies the whole request and empties the pipe carries NO
/// hint: nothing more is coming, so the output must emit it now. # C: O(1)
#[test]
fn final_batch_carries_no_hint() {
    let (pi, pf) = loaded_pipe(64);
    let rec = Recorder::new();
    let out = out_file(Arc::new(RecorderOps(Arc::clone(&rec))));
    let mut pos = 0u64;
    let n = pipe_to_file(ring(&pi), &pf, &out, &mut pos, false, 64, true, false).unwrap();
    assert_eq!(n, 64);
    assert_eq!(rec.hints(), alloc::vec![false]);
}

/// `SPLICE_F_MORE` from the caller marks even that final batch — the caller is
/// promising data beyond this whole call, which the transfer cannot see.
/// # C: O(1)
#[test]
fn user_more_marks_the_final_batch() {
    let (pi, pf) = loaded_pipe(64);
    let rec = Recorder::new();
    let out = out_file(Arc::new(RecorderOps(Arc::clone(&rec))));
    let mut pos = 0u64;
    let n = pipe_to_file(ring(&pi), &pf, &out, &mut pos, false, 64, true, true).unwrap();
    assert_eq!(n, 64);
    assert_eq!(rec.hints(), alloc::vec![true], "the caller's flag reaches the output");
}

/// A batch that leaves BOTH request bytes and queued pipe bytes behind is
/// hinted without the caller asking, because another batch of this same
/// transfer follows immediately. Driving the loop to completion pins the
/// boundary: every batch but the last is hinted. # C: O(bytes)
#[test]
fn derived_hint_marks_every_batch_but_the_last() {
    // More than one staging window's worth, so the leg runs repeatedly.
    const N: usize = 8192;
    let (pi, pf) = loaded_pipe(N);
    let rec = Recorder::new();
    let out = out_file(Arc::new(RecorderOps(Arc::clone(&rec))));
    let mut pos = 0u64;
    let mut total = 0usize;
    while total < N {
        let w = pipe_to_file(ring(&pi), &pf, &out, &mut pos, false, N - total, true, false).unwrap();
        if w == 0 { break; }
        total += w;
    }
    assert_eq!(total, N);
    assert_eq!(rec.bytes(), N);
    let h = rec.hints();
    assert!(h.len() >= 2, "the fixture must span more than one batch");
    assert!(h[..h.len() - 1].iter().all(|m| *m), "every non-final batch is hinted");
    assert!(!h[h.len() - 1], "the final batch is not");
}

/// The request bound, not the pipe, can be what ends the transfer: with more
/// bytes queued than asked for, the batch that completes the REQUEST is
/// unhinted even though the pipe is still full. # C: O(1)
#[test]
fn request_satisfied_ends_the_hint_though_the_pipe_holds_more() {
    let (pi, pf) = loaded_pipe(8192);
    let rec = Recorder::new();
    let out = out_file(Arc::new(RecorderOps(Arc::clone(&rec))));
    let mut pos = 0u64;
    let n = pipe_to_file(ring(&pi), &pf, &out, &mut pos, false, 100, true, false).unwrap();
    assert_eq!(n, 100);
    assert_eq!(rec.hints(), alloc::vec![false]);
    assert_eq!(pipe::queued(ring(&pi)), 8092, "only the written bytes left the ring");
}

/// A SHORT output leaves the unwritten bytes queued, and the batch it
/// partially took is judged by what the batch was, not by what the output
/// accepted. # C: O(1)
#[test]
fn short_output_keeps_the_unwritten_bytes() {
    let (pi, pf) = loaded_pipe(4096);
    let rec = Recorder::new();
    let out = out_file(Arc::new(ShortOps(Arc::clone(&rec), 10)));
    let mut pos = 0u64;
    let n = pipe_to_file(ring(&pi), &pf, &out, &mut pos, false, 4096, true, false).unwrap();
    assert_eq!(n, 10, "the output took 10 of the batch");
    assert_eq!(pipe::queued(ring(&pi)), 4086, "the rest stayed queued");
    assert_eq!(rec.hints(), alloc::vec![false], "one batch covered the whole request");
}
