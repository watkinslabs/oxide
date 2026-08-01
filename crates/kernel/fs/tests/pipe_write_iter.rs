extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

use fs::pipe::limits::PIPE_BUF;
use vfs::{Dentry, File, OpenFlags, VfsError};

const FIFO_INO: u64 = 0xf1f0_1000;

/// Both ends of a fresh anonymous pipe, plus its capacity. Every room
/// calculation below is derived from that capacity: `PIPE_BUF` is the atomic
/// unit, never the size of the ring, and a test that assumes the two are equal
/// stops testing what its name says the moment the default size moves.
fn pipe(flags: OpenFlags) -> (Arc<File>, Arc<File>, usize) {
    let ino = fs::pipe::make_pipe_inode();
    let p = fs::pipe::pipe_data(&ino).expect("pipe data");
    p.readers.store(1, Ordering::Release);
    p.writers.store(1, Ordering::Release);
    let cap = p.capacity();
    let rf = File::new(Arc::clone(&ino), Dentry::new_root(Arc::clone(&ino)),
        OpenFlags::O_RDONLY | (flags & OpenFlags::O_NONBLOCK));
    let wf = File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_WRONLY | flags);
    (rf, wf, cap)
}

#[test]
fn nonblock_pipe_buf_vector_is_all_or_nothing() {
    let (rf, wf, cap) = pipe(OpenFlags::O_NONBLOCK);
    // One byte short of the room a PIPE_BUF-sized write needs, whatever the
    // capacity happens to be.
    let fill = alloc::vec![b'x'; cap - (PIPE_BUF - 1)];
    assert_eq!(wf.write(&fill), Ok(fill.len()));

    let half = alloc::vec![b'a'; PIPE_BUF / 2];
    let bufs: [&[u8]; 2] = [&half, &half];
    assert_eq!(wf.write_iter(&bufs), Err(VfsError::Eagain));

    // Refused whole: not one byte of the vector was committed, so what comes
    // back out is exactly the fill and nothing else.
    let mut got = alloc::vec![0u8; cap];
    assert_eq!(rf.read(&mut got), Ok(fill.len()));
    assert_eq!(&got[..fill.len()], &fill[..]);
    assert_eq!(rf.read(&mut got), Err(VfsError::Eagain));
}

#[test]
fn direct_pipe_vector_is_one_packet() {
    let (rf, wf, _cap) = pipe(OpenFlags::O_NONBLOCK | OpenFlags::O_DIRECT);
    assert_eq!(wf.write_iter(&[b"ab", b"cd"]), Ok(4));

    let mut head = [0u8; 2];
    assert_eq!(rf.read(&mut head), Ok(2));
    assert_eq!(head, *b"ab");
    let mut tail = [0u8; 4];
    assert_eq!(rf.read(&mut tail), Err(VfsError::Eagain));
}

#[test]
fn direct_fifo_vector_is_one_packet() {
    let ino = vfs::make_fifo_inode(FIFO_INO, 0o600, Weak::new());
    let flags = OpenFlags::O_RDWR | OpenFlags::O_NONBLOCK | OpenFlags::O_DIRECT;
    let fop = fs::pipe::fifo_open(&ino, flags.bits()).expect("fifo open");
    let file = File::new_at_fop(Arc::clone(&ino), Dentry::new_root(ino), flags, 0, vfs::FileCred::root(), fop);
    assert_eq!(file.write_iter(&[b"ab", b"cd"]), Ok(4));

    let mut head = [0u8; 2];
    assert_eq!(file.read(&mut head), Ok(2));
    assert_eq!(head, *b"ab");
    let mut tail = [0u8; 4];
    assert_eq!(file.read(&mut tail), Err(VfsError::Eagain));
}

#[test]
fn large_nonblock_vector_reports_cross_iovec_partial() {
    let (rf, wf, cap) = pipe(OpenFlags::O_NONBLOCK);
    let first = alloc::vec![b'a'; PIPE_BUF];
    let second = alloc::vec![b'b'; PIPE_BUF];
    // Room for the whole first iovec plus part of the second, so the short
    // count has to fall MID-iovec. The total exceeds PIPE_BUF, so the write
    // carries no atomicity guarantee and may be split.
    let room = first.len() + PIPE_BUF / 2;
    let fill = alloc::vec![b'x'; cap - room];
    assert_eq!(wf.write(&fill), Ok(fill.len()));

    let bufs: [&[u8]; 2] = [&first, &second];
    assert_eq!(wf.write_iter(&bufs), Ok(room));

    let mut got = alloc::vec![0u8; cap];
    assert_eq!(rf.read(&mut got), Ok(fill.len() + room));
    let tail = &got[fill.len()..fill.len() + room];
    assert_eq!(&tail[..first.len()], &first[..]);
    assert_eq!(&tail[first.len()..], &second[..PIPE_BUF / 2]);
}
