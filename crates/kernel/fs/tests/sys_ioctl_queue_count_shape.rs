extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

use syscall::errno::Errno;
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, KResult, OpenFlags,
          default_inode_ops, default_file_ops, mk_mode};

mod userbuf {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static WRITABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub fn reset() {
        WRITABLE_CALLS.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(_ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        unreachable!("queue-count ioctl does not read user input")
    }

    pub fn validate_user_buf_writable(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
        WRITABLE_CALLS.fetch_add(1, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/016_ioctl/uapi.rs"]
mod uapi;
#[path = "../../syscalls/src/016_ioctl/fileattr.rs"]
mod fileattr;
#[path = "../../syscalls/src/016_ioctl/remap.rs"]
mod remap;
#[path = "../../syscalls/src/016_ioctl/common.rs"]
mod ioctl_common;

#[derive(Default)]
struct QueueOps {
    inq: AtomicU32,
    outq: AtomicU32,
    calls: AtomicUsize,
}

impl FileOps for QueueOps {
    fn poll(&self, _inode: &vfs::Inode) -> u32 { vfs::POLL_IN | vfs::POLL_OUT }

    fn ioctl_int(&self, _file: &File, cmd: vfs::IoctlIntCmd) -> KResult<u32> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(match cmd {
            vfs::IoctlIntCmd::Fionread => self.inq.load(Ordering::SeqCst),
            vfs::IoctlIntCmd::Siocoutq => self.outq.load(Ordering::SeqCst),
            vfs::IoctlIntCmd::Siocoutqnsd => return Err(VfsError::Enotty),
            vfs::IoctlIntCmd::Siocatmark => 0,
        })
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x7690);

fn reset() {
    userbuf::reset();
}

fn mk_queue_file(ops: Arc<QueueOps>) -> Arc<File> {
    let f_op: Arc<dyn FileOps> = ops;
    let ino = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Socket, 0o600), default_inode_ops(), f_op).build();
    File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_RDWR)
}

fn mk_default_socket_file() -> Arc<File> {
    let ino = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Socket, 0o600), default_inode_ops(), default_file_ops()).build();
    File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_RDWR)
}

#[test]
fn fionread_uses_backend_byte_count_not_poll_boolean() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(QueueOps::default());
    ops.inq.store(37, Ordering::SeqCst);
    let file = mk_queue_file(Arc::clone(&ops));
    let mut out = 0u32;

    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, &mut out as *mut u32 as u64), Some(0));

    assert_eq!(out, 37);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn siocoutq_uses_backend_outgoing_count() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(QueueOps::default());
    ops.outq.store(12, Ordering::SeqCst);
    let file = mk_queue_file(Arc::clone(&ops));
    let mut out = 0u32;

    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::SIOCOUTQ, &mut out as *mut u32 as u64), Some(0));

    assert_eq!(out, 12);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn linux_queue_count_aliases_route_to_same_backend_commands() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(QueueOps::default());
    ops.inq.store(37, Ordering::SeqCst);
    ops.outq.store(12, Ordering::SeqCst);
    let file = mk_queue_file(Arc::clone(&ops));
    let mut tiocinq = 0u32;
    let mut siocinq = 0u32;
    let mut tiocoutq = 0u32;

    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::TIOCINQ, &mut tiocinq as *mut u32 as u64), Some(0));
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::SIOCINQ, &mut siocinq as *mut u32 as u64), Some(0));
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::TIOCOUTQ, &mut tiocoutq as *mut u32 as u64), Some(0));

    assert_eq!(tiocinq, 37);
    assert_eq!(siocinq, 37);
    assert_eq!(tiocoutq, 12);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 3);
    reset();
}

#[test]
fn unsupported_queue_ioctl_returns_enotty_without_user_copyout() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let file = mk_default_socket_file();
    let mut out = 0xfeed_u32;

    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, &mut out as *mut u32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));

    assert_eq!(out, 0xfeed);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn backend_count_precedes_bad_user_pointer_fault() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ops = Arc::new(QueueOps::default());
    ops.inq.store(99, Ordering::SeqCst);
    let file = mk_queue_file(Arc::clone(&ops));

    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, 0),
        Some(-(Errno::Efault.as_i32() as i64)));

    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn real_pipe_fionread_reports_queued_bytes() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let ino = fs::pipe::make_pipe_inode();
    let p = fs::pipe::pipe_data(&ino).expect("pipe data");
    p.readers.store(1, Ordering::Release);
    p.writers.store(1, Ordering::Release);
    let rf = File::new(Arc::clone(&ino), Dentry::new_root(Arc::clone(&ino)), OpenFlags::O_RDONLY);
    let wf = File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_WRONLY);
    let mut out = 0u32;

    assert_eq!(wf.write(b"abcdef"), Ok(6));
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&rf, uapi::FIONREAD, &mut out as *mut u32 as u64), Some(0));

    assert_eq!(out, 6);
    reset();
}
