extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

use vfs::{Cred, Dentry, File, OpenFlags, VfsError};

const PIPE_BUF: usize = 4096;
const FIFO_INO: u64 = 0xf1f0_1000;

fn pipe(flags: OpenFlags) -> (Arc<File>, Arc<File>) {
    let ino = fs::pipe::make_pipe_inode();
    let p = fs::pipe::pipe_data(&ino).expect("pipe data");
    p.readers.store(1, Ordering::Release);
    p.writers.store(1, Ordering::Release);
    let rf = File::new(Arc::clone(&ino), Dentry::new_root(Arc::clone(&ino)),
        OpenFlags::O_RDONLY | (flags & OpenFlags::O_NONBLOCK));
    let wf = File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_WRONLY | flags);
    (rf, wf)
}

#[test]
fn nonblock_pipe_buf_vector_is_all_or_nothing() {
    let (rf, wf) = pipe(OpenFlags::O_NONBLOCK);
    let fill = [b'x'; PIPE_BUF - 2];
    assert_eq!(wf.write(&fill), Ok(fill.len()));

    assert_eq!(wf.write_iter(&[b"ab", b"cd"]), Err(VfsError::Eagain));

    let mut got = [0u8; PIPE_BUF];
    assert_eq!(rf.read(&mut got), Ok(fill.len()));
    assert_eq!(&got[..fill.len()], &fill);
    assert_eq!(rf.read(&mut got), Err(VfsError::Eagain));
}

#[test]
fn direct_pipe_vector_is_one_packet() {
    let (rf, wf) = pipe(OpenFlags::O_NONBLOCK | OpenFlags::O_DIRECT);
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
    let file = File::new_at_fop(Arc::clone(&ino), Dentry::new_root(ino), flags, 0, Cred::root(), fop);
    assert_eq!(file.write_iter(&[b"ab", b"cd"]), Ok(4));

    let mut head = [0u8; 2];
    assert_eq!(file.read(&mut head), Ok(2));
    assert_eq!(head, *b"ab");
    let mut tail = [0u8; 4];
    assert_eq!(file.read(&mut tail), Err(VfsError::Eagain));
}

#[test]
fn large_nonblock_vector_reports_cross_iovec_partial() {
    let (rf, wf) = pipe(OpenFlags::O_NONBLOCK);
    let first = [b'a'; PIPE_BUF - 1];
    let bufs: [&[u8]; 2] = [&first, b"bc"];
    assert_eq!(wf.write_iter(&bufs), Ok(PIPE_BUF));

    let mut got = [0u8; PIPE_BUF];
    assert_eq!(rf.read(&mut got), Ok(got.len()));
    assert_eq!(&got[..PIPE_BUF - 1], &first);
    assert_eq!(got[PIPE_BUF - 1], b'b');
}
