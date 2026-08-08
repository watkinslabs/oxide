// Hosted unit tests for the named-FIFO (S_IFIFO) open path. These drive the REAL fifo code
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
    assert!(!is_named_fifo(&make_pipe_inode().expect("pipe inode")), "anon pipe is not a named FIFO");
    assert!(!is_named_fifo(&make_eventfd_inode(0, false)), "eventfd is not a named FIFO");
    assert!(is_named_fifo(&fifo(0xF1F0_0007)), "mknod FIFO IS a named FIFO");
}

// --- readiness edges -------------------------------------------------------
//
// The FIFO data paths publish every readiness transition through
// `inode.poll_subscribers()`, and every one of those call sites is
// `if let Some(s) = subs`. An `S_IFIFO` inode built WITHOUT a subscriber list
// therefore takes the silent no-op branch on every write, read and last-close:
// blocking I/O still works, but `poll`/`select`/`epoll_wait` on the FIFO
// subscribes to nothing and parks with no deadline and no source. That is
// exactly the shape ext4-backed FIFOs had (`build_stat_inode` never called
// `poll_subs`) while devnode and tmpfs FIFOs were fine.

struct CountingWaiter { hits: core::sync::atomic::AtomicU32 }

impl vfs::EpollNotify for CountingWaiter {
    fn notify(&self) { self.hits.fetch_add(1, core::sync::atomic::Ordering::AcqRel); }
}

/// Subscribe a counter to `inode`'s wait queue the way `sys_poll`'s
/// `PollWaiter` and an epitem do. Returns `None` when the inode carries no
/// queue at all — the defect under test.
fn watch(inode: &vfs::InodeRef) -> Option<alloc::sync::Arc<CountingWaiter>> {
    let subs = inode.poll_subscribers()?;
    let waiter = alloc::sync::Arc::new(CountingWaiter {
        hits: core::sync::atomic::AtomicU32::new(0) });
    let weak: Weak<dyn vfs::EpollNotify> =
        alloc::sync::Arc::downgrade(&(waiter.clone() as alloc::sync::Arc<dyn vfs::EpollNotify>));
    subs.subscribe(1, weak);
    Some(waiter)
}

#[test]
fn fifo_inode_carries_a_wait_queue() {
    let inode = fifo(0xF1F0_0100);
    assert!(inode.poll_subscribers().is_some(),
        "an S_IFIFO inode with no PollSubscribers makes every notify site a no-op");
}

#[test]
fn every_fifo_filesystem_decides_the_same_way() {
    // The one decision the devnode, tmpfs and ext4 constructors all consult,
    // so a fourth filesystem cannot quietly disagree.
    assert!(vfs::special_inode_needs_poll_subs(vfs::FileType::Fifo));
    assert!(!vfs::special_inode_needs_poll_subs(vfs::FileType::Regular));
}

#[test]
fn write_wakes_a_subscribed_waiter() {
    let inode = fifo(0xF1F0_0101);
    let fop = fifo_open(&inode, O_RDWR).expect("O_RDWR fifo_open never blocks");
    let waiter = watch(&inode).expect("fifo inode has a wait queue");
    assert_eq!(waiter.hits.load(core::sync::atomic::Ordering::Acquire), 0);
    fop.write(&inode, 0, b"wake").expect("fifo write");
    assert_ne!(waiter.hits.load(core::sync::atomic::Ordering::Acquire), 0,
        "a write that flips POLLIN must notify the FIFO's poll waiters");
    fifo_release(&inode, true, true);
}

#[test]
fn read_wakes_a_subscribed_waiter() {
    let inode = fifo(0xF1F0_0102);
    let fop = fifo_open(&inode, O_RDWR).expect("O_RDWR fifo_open never blocks");
    fop.write(&inode, 0, b"drain").expect("fifo write");
    let waiter = watch(&inode).expect("fifo inode has a wait queue");
    let mut buf = [0u8; 16];
    fop.read(&inode, 0, &mut buf).expect("fifo read");
    assert_ne!(waiter.hits.load(core::sync::atomic::Ordering::Acquire), 0,
        "a read that frees ring space must notify the FIFO's poll waiters");
    fifo_release(&inode, true, true);
}

#[test]
fn last_close_wakes_a_subscribed_waiter() {
    // Writer EOF / reader EPIPE is the transition an event loop parks on.
    let inode = fifo(0xF1F0_0103);
    let _fop = fifo_open(&inode, O_RDWR).expect("O_RDWR fifo_open never blocks");
    let waiter = watch(&inode).expect("fifo inode has a wait queue");
    fifo_release(&inode, true, true);
    assert_ne!(waiter.hits.load(core::sync::atomic::Ordering::Acquire), 0,
        "last close must notify so a parked poller sees POLLHUP/EOF");
}
