// An interest whose readiness arrives on a deadline — a timerfd — has no
// source callback to announce it. `epoll_wait` handles that by bounding its
// sleep with the earliest such deadline and materializing due ones before it
// scans. An epoll file reached through ANOTHER readiness wait must answer the
// same two questions about itself, or the deadline is invisible: the outer
// waiter parks past it and the readiness surfaces only on the next unrelated
// wakeup.
//
// A compositor reaches every input device through exactly that shape — one
// wait on the epoll descriptor an input library owns, with the library's own
// timer inside it. The library holds a button release back behind a short
// debounce timer, so when the deadline does not propagate the release is
// stranded until some later event happens to wake the loop; the press then
// stands alone and the click is promoted to a long press.

use alloc::sync::Arc;
use vfs::{
    default_inode_ops, mk_mode, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef,
    KResult, VfsError,
};

use super::fileops::EpollFileOps;
use super::{epoll_data_of_inode, monotonic_ns, EpItem, EpollData};

const MEMBER_INO: Ino = 0x7f00_0042;
const MEMBER_FD: i32 = 9;
const MEMBER_SUB_ID: u32 = 0;
/// Far enough ahead that the test cannot reach it while running.
const NEVER_NS: u64 = 3_600_000_000_000;

/// A member whose readiness is produced by a deadline and by nothing else: it
/// reports unready until the clock reaches its deadline, and no callback ever
/// fires on its behalf.
struct DeadlineOps { deadline_ns: u64 }

impl FileOps for DeadlineOps {
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Einval) }
    fn can_poll(&self, _f: &File) -> bool { true }
    fn poll(&self, _i: &Inode) -> u32 {
        if monotonic_ns() >= self.deadline_ns { vfs::POLL_IN } else { 0 }
    }
    fn poll_deadline_ns(&self, _f: &File) -> Option<u64> { Some(self.deadline_ns) }
}

fn member_inode(deadline_ns: u64) -> InodeRef {
    InodeBuilder::new(MEMBER_INO, mk_mode(FileType::CharDev, 0), default_inode_ops(),
        Arc::new(DeadlineOps { deadline_ns }) as Arc<dyn FileOps>)
        .build()
}

/// One epoll instance watching one deadline-backed member. The member file is
/// returned because the interest holds it weakly.
fn watching(deadline_ns: u64) -> (InodeRef, Arc<EpollData>, Arc<File>) {
    let ep_inode = make_epoll();
    let ep = epoll_data_of_inode(&ep_inode).expect("fresh epoll inode carries its state");
    let inode = member_inode(deadline_ns);
    let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
    let file = File::new(inode, dentry, vfs::OpenFlags::O_RDONLY);
    let item = EpItem::new(&ep, MEMBER_FD, MEMBER_SUB_ID, vfs::POLL_IN, 0,
        Arc::clone(&file), None);
    ep.entries.lock().push(item);
    (ep_inode, ep, file)
}

fn make_epoll() -> InodeRef { super::make_epoll_inode() }

fn epoll_file(ep_inode: &InodeRef) -> Arc<File> {
    let dentry = vfs::Dentry::new_root(Arc::clone(ep_inode));
    File::new(Arc::clone(ep_inode), dentry, vfs::OpenFlags::O_RDONLY)
}

/// The deadline an outer waiter must bound its sleep by is its member's own.
#[test]
fn an_epoll_file_reports_its_earliest_member_deadline() {
    let deadline = monotonic_ns() + NEVER_NS;
    let (ep_inode, _ep, _file) = watching(deadline);
    let ep_file = epoll_file(&ep_inode);

    assert_eq!(EpollFileOps.poll_deadline_ns(&ep_file), Some(deadline));
    // Through the accessor `poll`, `select` and a containing `epoll_wait` all
    // reach, not just the operations table directly.
    assert_eq!(ep_file.poll_deadline_ns(), Some(deadline));
}

/// Reading the epoll file's readiness is the only thing an outer waiter does
/// once it wakes, so a deadline that has come due has to be visible there.
/// Nothing else will have enqueued it.
#[test]
fn an_epoll_file_reports_a_member_whose_deadline_came_due() {
    let (due_inode, _ep, _file) = watching(monotonic_ns());
    assert_eq!(EpollFileOps.poll(&due_inode), vfs::POLL_IN,
        "a due deadline must be visible without any other event arriving");
}

/// Before the deadline the epoll file is not readable: propagating the
/// deadline must not turn into reporting readiness early.
#[test]
fn an_epoll_file_is_unready_until_the_member_deadline_arrives() {
    let (pending_inode, _ep, _file) = watching(monotonic_ns() + NEVER_NS);
    assert_eq!(EpollFileOps.poll(&pending_inode), 0);
}

/// An epoll with nothing timer-backed in it imposes no deadline, so an outer
/// waiter still sleeps until a source callback wakes it.
#[test]
fn an_epoll_file_with_no_timer_backed_member_reports_no_deadline() {
    let ep_inode = make_epoll();
    assert_eq!(EpollFileOps.poll_deadline_ns(&epoll_file(&ep_inode)), None);
}
