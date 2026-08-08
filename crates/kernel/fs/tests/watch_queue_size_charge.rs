// `IOC_WATCH_QUEUE_SET_SIZE` reserves MEMORY, not a bare count: the depth a
// notification pipe is given is charged against its owner's pipe page account,
// so a local user cannot hold more notification memory than pipe pages.

use fs::watch_queue::{attach, handle_watch_queue_ioctl, IOC_WATCH_QUEUE_SET_SIZE,
    WATCH_QUEUE_NOTES_PER_PAGE};
use fs::pipe::make_pipe_inode;
use vfs::pipe_limits::{account, charged, set_user_pages_hard, set_user_pages_soft,
    user_pages_hard, user_pages_soft};
use vfs::{File, OpenFlags};
use syscall::errno::Errno;

/// Bytes per accounted page.
const PAGE: usize = vfs::pipe_limits::PIPE_PAGE_BYTES as usize;

/// The tunables are process-global and the harness runs cases in parallel.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Restore { soft: i64, hard: i64, before: i64 }
fn save() -> Restore { Restore { soft: user_pages_soft(), hard: user_pages_hard(), before: charged(0) } }
impl Drop for Restore {
    fn drop(&mut self) {
        set_user_pages_soft(self.soft);
        set_user_pages_hard(self.hard);
        account(0, charged(0), self.before);
    }
}

fn notification_pipe() -> (vfs::InodeRef, alloc::sync::Arc<File>) {
    let inode = make_pipe_inode().expect("a pipe");
    attach(&inode);
    let dentry = vfs::dcache::d_alloc_pseudo("pipe", inode.clone(), &fs::anon_dname::PIPE_OPS);
    (inode.clone(), File::new(inode, dentry, OpenFlags::O_RDONLY))
}

extern crate alloc;

#[test]
fn a_depth_is_charged_against_the_owners_pipe_pages() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let before = charged(0);
    let (_inode, file) = notification_pipe();
    let with_ring = charged(0);
    assert!(with_ring > before, "the pipe's own ring is charged first");
    let notes = (WATCH_QUEUE_NOTES_PER_PAGE * 2) as u64;
    assert_eq!(handle_watch_queue_ioctl(&file, IOC_WATCH_QUEUE_SET_SIZE, notes), Some(0));
    assert_eq!(charged(0), before + 2,
        "the account now holds the queue's two pages, not the ring's and the queue's");
}

#[test]
fn a_depth_past_a_user_limit_is_refused_and_charges_nothing() {
    let _serial = SERIAL.lock().unwrap();
    let _restore = save();
    set_user_pages_soft(0);
    set_user_pages_hard(0);
    let (inode, file) = notification_pipe();
    // A reservation is only a GROWTH — and so only limit-checked — past what
    // the pipe already holds, so shrink the ring first, exactly as a caller
    // that sized its pipe down would have.
    fs::pipe::set_pipe_size(&inode, PAGE).expect("a one-page ring");
    let held = charged(0);
    set_user_pages_hard(held);
    let notes = (WATCH_QUEUE_NOTES_PER_PAGE * 8) as u64;
    assert_eq!(handle_watch_queue_ioctl(&file, IOC_WATCH_QUEUE_SET_SIZE, notes),
        Some(-(Errno::Eperm.as_i32() as i64)));
    assert_eq!(charged(0), held, "a refused reservation leaves the account alone");
    // And the depth was not published either: the queue is still unsized, so
    // the SAME command can succeed once the limit is lifted.
    set_user_pages_hard(0);
    assert_eq!(handle_watch_queue_ioctl(&file, IOC_WATCH_QUEUE_SET_SIZE, notes), Some(0));
}
