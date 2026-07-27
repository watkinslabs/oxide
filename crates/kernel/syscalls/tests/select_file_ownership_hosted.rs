//! Production `select` ownership schedules across close and exact fd reuse.

use std::boxed::Box;
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use syscall::SyscallArgs;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, OpenFlags,
          default_inode_ops, mk_mode};

macro_rules! debug_ssh { ($($t:tt)*) => {} }

mod userbuf {
    use syscall::errno::Errno;

    pub(crate) fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        if ptr == 0 && len != 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub(crate) fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        validate_user_buf_readable(ptr, len, 1)
    }
}

mod poll {
    pub(crate) mod poll_common {
        use std::sync::Arc;

        pub(crate) fn monotonic_ns() -> u64 { 0 }

        pub(crate) struct PollWaiter;

        impl PollWaiter {
            pub(crate) fn new() -> Arc<Self> { Arc::new(Self) }
            pub(crate) fn subscribe(self: &Arc<Self>, _subs: &vfs::PollSubscribers) {}
            pub(crate) fn unsubscribe(&self, _subs: &vfs::PollSubscribers) {}
            pub(crate) fn generation(&self) -> u64 { 0 }
            pub(crate) unsafe fn park_until(&self, _observed: u64, _deadline_ns: u64) {
                panic!("hosted ownership test attempted to park");
            }
        }
    }
}

#[path = "../src/pselect_ppoll.rs"]
mod pselect_ppoll;

#[path = "../src/023_select.rs"]
mod production_select;

struct PollOps { mask: u32 }

impl FileOps for PollOps {
    fn poll(&self, _inode: &vfs::inode::Inode) -> u32 { self.mask }
}

fn file(ino: u64, mask: u32) -> Arc<File> {
    let inode = InodeBuilder::new(
        ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(),
        Arc::new(PollOps { mask }),
    ).build();
    let dentry = Dentry::new(None, "select".into(), inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static GATES: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>> = Mutex::new(None);

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    production_select::set_post_snapshot_hook(None);
    production_select::set_test_current(None);
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
        0x7023, "select-ownership", sched::SchedClass::Normal { weight: 1024 },
    )));
    // SAFETY: test owns this leaked task and installs its fd table before publishing the pointer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    production_select::set_test_current(Some(task));
}

#[test]
fn production_select_retains_file_across_close_and_exact_reuse() {
    let _guard = begin_test();
    let fdt = Arc::new(FdTable::new());
    let original = file(0x7101, vfs::POLL_IN);
    let replacement = file(0x7102, vfs::POLL_OUT);
    let fd = fdt.alloc(original.clone()).unwrap();
    install_current(fdt.clone());
    let snapshot = Arc::new(Barrier::new(2));
    let reused = Arc::new(Barrier::new(2));
    *GATES.lock().unwrap() = Some((snapshot.clone(), reused.clone()));
    let closer_fdt = fdt.clone();
    let closer_replacement = replacement.clone();
    let closer = std::thread::spawn(move || {
        snapshot.wait();
        closer_fdt.close(fd).unwrap();
        assert_eq!(closer_fdt.alloc(closer_replacement), Ok(fd));
        reused.wait();
    });
    production_select::set_post_snapshot_hook(Some(close_and_reuse));

    let mut readfds = [0u8; 8];
    let mut timeout = [0i64; 2];
    readfds[(fd / 8) as usize] |= 1u8 << (fd & 7);
    let args = SyscallArgs {
        a0: (fd + 1) as u64,
        a1: readfds.as_mut_ptr() as u64,
        a4: timeout.as_mut_ptr() as u64,
        ..SyscallArgs::default()
    };
    assert_eq!(production_select::sys_select(&args), 1);
    closer.join().unwrap();
    assert_ne!(readfds[(fd / 8) as usize] & (1u8 << (fd & 7)), 0);
    assert!(Arc::ptr_eq(&fdt.get(fd).unwrap(), &replacement));
    assert!(!Arc::ptr_eq(&fdt.get(fd).unwrap(), &original));

    production_select::set_test_current(None);
    *GATES.lock().unwrap() = None;
}

#[test]
fn production_select_rejects_initially_invalid_selected_fd() {
    let _guard = begin_test();
    let fdt = Arc::new(FdTable::new());
    install_current(fdt);
    let mut readfds = [1u8; 8];
    let args = SyscallArgs {
        a0: 1,
        a1: readfds.as_mut_ptr() as u64,
        ..SyscallArgs::default()
    };

    assert_eq!(
        production_select::sys_select_with_deadline(&args, Some(0)),
        -(syscall::errno::Errno::Ebadf.as_i32() as i64),
    );
    production_select::set_test_current(None);
}

#[test]
fn pselect6_delegates_to_corrected_select_engine() {
    let pselect = include_str!("../src/270_pselect6.rs");
    assert!(pselect.contains("sys_select_with_deadline(&inner, deadline_ns)"));
}
