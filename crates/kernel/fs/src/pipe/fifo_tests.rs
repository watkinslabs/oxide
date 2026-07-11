// Hosted unit tests for the named-FIFO (S_IFIFO) open path — Linux
// `fs/pipe.c` `fifo_open` + `pipefifo_fops`. These drive the REAL fifo code
// (`fifo_open` → shared ring → `FifoFileOps`) on a genuine `vfs::make_fifo_inode`
// inode, so they reproduce the systemd-initctl EIO symptom and prove the fix and
// the reader/writer/O_NONBLOCK/EOF behaviour matrix. The blocking rendezvous is
// scheduler-only (`oxide-kernel`-gated), so these exercise the never-blocking /
// O_NONBLOCK matrix; a live blocking-unblock case needs the kernel harness.

use alloc::sync::Weak;

use vfs::VfsError;

use super::{fifo_open, fifo_release, is_named_fifo, make_eventfd_inode, make_pipe_inode};

// open(2) access-mode + O_NONBLOCK bits (asm-generic, both arches).
const O_WRONLY:   u32 = 0o1;
const O_RDWR:     u32 = 0o2;
const O_NONBLOCK: u32 = 0o4000;

/// A fresh named-FIFO inode with a unique inode number (no superblock needed —
/// `make_fifo_inode` builds the in-core inode directly).
fn fifo(ino: u64) -> vfs::InodeRef {
    vfs::make_fifo_inode(ino, 0o600, Weak::new())
}

// Reproduces + fixes the systemd-initctl symptom: open a FIFO O_RDWR, write
// bytes, read them back — bytes match and NOTHING returns EIO (the pre-fix
// tmpfs `TmpfsErrFileOps` stub returned EIO here).
#[test]
fn rdwr_round_trip_no_eio() {
    let inode = fifo(0xF1F0_0001);
    assert!(is_named_fifo(&inode), "make_fifo_inode is a named FIFO");
    let fop = fifo_open(&inode, O_RDWR).expect("O_RDWR fifo_open never blocks");
    let n = fop.write(&inode, 0, b"initctl").expect("fifo write");
    assert_eq!(n, 7);
    let mut buf = [0u8; 16];
    let n = fop.read(&inode, 0, &mut buf).expect("fifo read (NOT EIO)");
    assert_eq!(&buf[..n], b"initctl");
    // Balance the O_RDWR open (drops both ends) so the ring is GC'd.
    fifo_release(&inode, true, true);
}

// O_WRONLY | O_NONBLOCK with no reader → ENXIO (Linux fifo_open quirk), and NO
// writer count is taken (the ring is GC'd back to empty).
#[test]
fn wronly_nonblock_no_reader_enxio() {
    let inode = fifo(0xF1F0_0002);
    let r = fifo_open(&inode, O_WRONLY | O_NONBLOCK);
    assert!(matches!(r, Err(VfsError::Enxio)), "O_WRONLY|O_NONBLOCK no reader = ENXIO");
}

// O_RDONLY | O_NONBLOCK with no writer → succeeds immediately (no block, and it
// is legal to have a reader with no writer yet).
#[test]
fn rdonly_nonblock_no_writer_ok() {
    let inode = fifo(0xF1F0_0003);
    let fop = fifo_open(&inode, O_NONBLOCK).expect("O_RDONLY|O_NONBLOCK succeeds w/o writer");
    // A non-blocking read of the empty pipe that has NO writer reads EOF (0) —
    // Linux `pipe_read` returns 0 when `writers == 0` (not EAGAIN). The point of
    // this case is that the OPEN did not block; the read confirms no writer yet.
    let mut buf = [0u8; 8];
    assert_eq!(fop.read_nonblock(&inode, 0, &mut buf).expect("nonblock read"), 0);
    fifo_release(&inode, true, false);
}

// After the LAST writer closes, a reader sees EOF (read → 0), not a block/error.
#[test]
fn reader_sees_eof_after_last_writer_closes() {
    let inode = fifo(0xF1F0_0004);
    // Reader opens first (non-blocking so it does not wait for a writer).
    let rfop = fifo_open(&inode, O_NONBLOCK).expect("reader open");
    // Writer opens: a reader already exists so O_WRONLY neither ENXIOs nor blocks.
    let wfop = fifo_open(&inode, O_WRONLY).expect("writer open");
    assert_eq!(wfop.write(&inode, 0, b"hi").expect("write"), 2);
    let mut buf = [0u8; 8];
    assert_eq!(rfop.read(&inode, 0, &mut buf).expect("read data"), 2);
    assert_eq!(&buf[..2], b"hi");
    // Last writer closes → reader now reads EOF (0), not EAGAIN/block.
    fifo_release(&inode, false, true);
    assert_eq!(rfop.read(&inode, 0, &mut buf).expect("read EOF"), 0);
    fifo_release(&inode, true, false);
}

// After the LAST reader closes, a writer's write → EPIPE (Linux; caller also
// gets SIGPIPE at the syscall layer).
#[test]
fn writer_sees_epipe_after_last_reader_closes() {
    let inode = fifo(0xF1F0_0005);
    let _rfop = fifo_open(&inode, O_NONBLOCK).expect("reader open");
    let wfop = fifo_open(&inode, O_WRONLY).expect("writer open");
    // Reader closes → no readers left.
    fifo_release(&inode, true, false);
    assert!(matches!(wfop.write(&inode, 0, b"x"), Err(VfsError::Epipe)), "write w/o readers = EPIPE");
    fifo_release(&inode, false, true);
}

// Two independent opens of the SAME inode share ONE ring: a writer opened by one
// call and a reader opened by another rendezvous and exchange bytes (the reader-
// process / writer-process case that a per-open ring would break).
#[test]
fn independent_opens_share_one_ring() {
    let inode = fifo(0xF1F0_0006);
    let rfop = fifo_open(&inode, O_NONBLOCK).expect("reader open");
    let wfop = fifo_open(&inode, O_WRONLY).expect("writer open");
    assert_eq!(wfop.write(&inode, 0, b"shared").expect("write"), 6);
    let mut buf = [0u8; 8];
    assert_eq!(rfop.read(&inode, 0, &mut buf).expect("read"), 6);
    assert_eq!(&buf[..6], b"shared");
    fifo_release(&inode, true, false);
    fifo_release(&inode, false, true);
}

// The named-FIFO detector must REJECT anonymous pipes (pipe2) and eventfds —
// both are `FileType::Fifo` but are born with their ring/counter already bound
// and must not be re-bound by `fifo_open`.
#[test]
fn is_named_fifo_rejects_anon_pipe_and_eventfd() {
    assert!(!is_named_fifo(&make_pipe_inode()), "anon pipe is not a named FIFO");
    assert!(!is_named_fifo(&make_eventfd_inode(0, false)), "eventfd is not a named FIFO");
    assert!(is_named_fifo(&fifo(0xF1F0_0007)), "mknod FIFO IS a named FIFO");
}
