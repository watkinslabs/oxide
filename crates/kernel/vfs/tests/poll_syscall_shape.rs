//! `poll(2)` syscall result-shaping over the real fd table.
//! Linux ignores negative fds, reports `POLLNVAL` for non-negative bad fds, and
//! always reports `POLLERR|POLLHUP|POLLNVAL` even when not requested.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, default_inode_ops, mk_mode};

const POLLIN:  i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR:  i16 = 0x0008;
const POLLHUP:  i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const POLL_ALWAYS: i16 = POLLERR | POLLHUP | POLLNVAL;

struct PollOps(u32);
impl FileOps for PollOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
    fn poll(&self, _inode: &Inode) -> u32 { self.0 }
}

fn file(mask: u32) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x7011, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(PollOps(mask)))
        .size(1).build();
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, d, OpenFlags::O_RDWR)
}

fn model_pollfd(fdt: &FdTable, fd: i32, events: i16) -> i16 {
    let mut revents = 0;
    if let Ok(f) = fdt.get(fd) {
        revents = (f.poll() as i16) & (events | POLL_ALWAYS);
    } else if fd >= 0 {
        revents = POLLNVAL;
    }
    revents
}

#[test]
fn negative_fd_is_ignored_but_positive_bad_fd_is_pollnval() {
    let fdt = FdTable::new();
    assert_eq!(model_pollfd(&fdt, -1, POLLIN), 0);
    assert_eq!(model_pollfd(&fdt, 42, 0), POLLNVAL);
}

#[test]
fn ready_mask_filters_requested_bits_but_always_reports_hup_err_nval() {
    let fdt = FdTable::new();
    let fd = fdt.alloc(file((POLLIN | POLLOUT | POLLHUP) as u32)).expect("fd");
    assert_eq!(model_pollfd(&fdt, fd, POLLIN), POLLIN | POLLHUP);
    assert_eq!(model_pollfd(&fdt, fd, 0), POLLHUP);
}
