use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use std::boxed::Box;
use std::sync::{Arc as StdArc, Barrier, Mutex, MutexGuard};

use syscall::SyscallArgs;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, OpenFlags,
          default_inode_ops, mk_mode};

mod poll {
    pub mod poll_common {
        use alloc::sync::Arc;

        /// Return the hosted schedule clock. # C: O(1)
        pub fn monotonic_ns() -> u64 { 0 }

        pub struct PollWaiter;
        impl PollWaiter {
            /// Allocate the hosted waiter adapter. # C: O(1)
            pub fn new() -> Arc<Self> { Arc::new(Self) }
            /// Accept one hosted subscription. # C: O(1)
            pub fn subscribe(self: &Arc<Self>, _subs: &vfs::PollSubscribers) {}
            /// Remove one hosted subscription. # C: O(1)
            pub fn unsubscribe(&self, _subs: &vfs::PollSubscribers) {}
            /// Return the hosted waiter generation. # C: O(1)
            pub fn generation(&self) -> u64 { 0 }
            /// Reject unexpected parking in this deterministic schedule. # C: O(1)
            pub unsafe fn park_until(&self, _observed: u64, _deadline_ns: u64) {
                panic!("ownership schedule unexpectedly parked");
            }
        }
    }
}

mod userbuf {
    use syscall::errno::Errno;

    fn validate(ptr: u64, len: u64) -> Result<(), i64> {
        if len != 0 && (ptr == 0 || ptr.checked_add(len).is_none()) {
            Err(-(Errno::Efault.as_i32() as i64))
        } else { Ok(()) }
    }

    /// Validate the hosted readable range. # C: O(1)
    pub fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        validate(ptr, len)
    }

    /// Validate the hosted writable range. # C: O(1)
    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        validate(ptr, len)
    }
}

#[path = "007_poll.rs"]
mod production_poll;

struct PollOps { mask: AtomicU32 }

impl FileOps for PollOps {
    fn poll(&self, _inode: &vfs::inode::Inode) -> u32 {
        self.mask.load(Ordering::Acquire)
    }
}

fn file(ino: u64, mask: u32) -> Arc<File> {
    let inode = InodeBuilder::new(
        ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(),
        Arc::new(PollOps { mask: AtomicU32::new(mask) }),
    ).build();
    let dentry = Dentry::new(None, alloc::string::String::from("poll"), inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[repr(C)]
struct UserPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static GATES: Mutex<Option<(StdArc<Barrier>, StdArc<Barrier>)>> = Mutex::new(None);

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    production_poll::set_post_snapshot_hook(None);
    production_poll::set_test_current(None);
    *GATES.lock().unwrap() = None;
    guard
}

fn close_and_reuse() {
    let (snapshot, reused) = GATES.lock().unwrap().as_ref().unwrap().clone();
    snapshot.wait();
    reused.wait();
}

fn install_current(fdt: Arc<FdTable>) {
    let task = Box::leak(Box::new(sched::Task::new(
        0x7007, "poll-ownership", sched::SchedClass::Normal { weight: 1024 },
    )));
    // SAFETY: test owns this leaked task and installs its fd table before publishing the pointer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    production_poll::set_test_current(Some(task));
}

#[test]
fn production_poll_retains_file_across_close_and_exact_reuse() {
    let _guard = begin_test();
    let fdt = Arc::new(FdTable::new());
    let original = file(0x7001, vfs::POLL_IN);
    let replacement = file(0x7002, vfs::POLL_OUT);
    let fd = fdt.alloc(original.clone()).unwrap();
    install_current(fdt.clone());
    let snapshot = StdArc::new(Barrier::new(2));
    let reused = StdArc::new(Barrier::new(2));
    *GATES.lock().unwrap() = Some((snapshot.clone(), reused.clone()));
    let closer_fdt = fdt.clone();
    let closer_replacement = replacement.clone();
    let closer = std::thread::spawn(move || {
        snapshot.wait();
        closer_fdt.close(fd).unwrap();
        assert_eq!(closer_fdt.alloc(closer_replacement), Ok(fd));
        reused.wait();
    });
    production_poll::set_post_snapshot_hook(Some(close_and_reuse));

    let mut pfd = UserPollFd { fd, events: vfs::POLL_IN as i16, revents: 0 };
    let args = SyscallArgs {
        a0: &mut pfd as *mut UserPollFd as u64,
        a1: 1,
        a2: 0,
        ..SyscallArgs::default()
    };
    assert_eq!(production_poll::sys_poll(&args), 1);
    closer.join().unwrap();
    assert_eq!(pfd.revents, vfs::POLL_IN as i16);
    assert!(Arc::ptr_eq(&fdt.get(fd).unwrap(), &replacement));
    assert!(!Arc::ptr_eq(&fdt.get(fd).unwrap(), &original));

    production_poll::set_test_current(None);
    *GATES.lock().unwrap() = None;
}

#[test]
fn poll_snapshot_preserves_invalid_negative_and_duplicate_entries() {
    let src = include_str!("007_poll.rs");

    assert!(src.contains("if pfd.fd < 0 { None } else { fdt.get(pfd.fd).ok() }"));
    assert!(src.contains("} else if pfd.fd >= 0 {\n                revents = POLLNVAL;"));
    assert!(src.contains("pfds.iter().map(|pfd|"));
    assert!(!src.contains("dedup"));
}
