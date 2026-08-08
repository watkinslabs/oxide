// sys_io_uring_setup (NR_IO_URING_SETUP=425) per docs/53§0 — ABI shim only:
// copy the params in, admit them (`io_uring_abi::layout::prepare`), build the
// ring, copy the params back, install the fd. Every decision — the flag mask,
// the entries ladder, the region geometry, the reported feature bits — lives
// in `crate::io_uring_abi`, which the hosted suite compiles and tests.
//
// Linux shape: the syscall entry validates params, then creates the ring.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::io_uring::{make_io_uring_inode, IoUringInode};
use crate::io_uring_abi::allowed::allowed;
use crate::io_uring_abi::layout::{prepare, REPORTED_FEATURES};
use crate::io_uring_abi::uapi::{Params, PARAMS_SIZE};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the caller's credential state and put it through the ring-creation
/// admission ladder (`io_uring_abi::allowed`). Runs BEFORE the params copy, so
/// an administratively closed kernel answers EPERM rather than EFAULT.
/// # C: O(N_groups)
fn creation_allowed() -> Result<(), Errno> {
    use core::sync::atomic::Ordering;
    let disabled = syscall::io_uring_ctl::disabled();
    let group    = syscall::io_uring_ctl::group();
    let Some(cur) = sched::live::current() else { return Ok(()) };
    let egid = cur.creds.egid.load(Ordering::Acquire);
    let cap  = cur.has_cap(sched::cap::SYS_ADMIN);
    let groups = cur.creds.groups.lock().clone();
    match groups {
        Some(g) => allowed(disabled, group, cap, egid, &g),
        None    => allowed(disabled, group, cap, egid, &[]),
    }
}

/// `sys_io_uring_setup(entries, *params)` — slot 425.
/// # C: O(1)
pub fn sys_io_uring_setup(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    let entries  = args.a0 as u32;
    let params_p = args.a1;

    // Administrative admission outranks argument validation.
    if let Err(e) = creation_allowed() { return err(e); }

    // Linux io_uring_setup(): the WHOLE struct is copied in first, so a bad
    // pointer — including NULL — is EFAULT before anything is validated or
    // allocated. Skipping the copy for a NULL pointer returned a usable fd
    // whose ring geometry the caller never learned.
    let mut buf = [0u8; PARAMS_SIZE];
    if uaccess::copy_from_user(&mut buf, params_p).is_err() { return err(Errno::Efault); }
    let mut p = Params::from_bytes(&buf);

    // resv[] zero check, flag mask, flag combinations, entries ladder, region
    // sizing, sq_off/cq_off writeback.
    let geom = match prepare(&mut p, entries) { Ok(g) => g, Err(e) => return err(e) };

    let inode = match IoUringInode::new(&geom) { Some(i) => i, None => return err(Errno::Enomem) };

    // Linux io_uring_create() sets p->features only once the rings exist, then
    // copies the params back BEFORE installing the fd, so a failed copy-back
    // never leaks a descriptor.
    p.features = REPORTED_FEATURES;
    if uaccess::copy_to_user(params_p, &p.to_bytes()).is_err() { return err(Errno::Efault); }

    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return err(Errno::Ebadf) };
    crate::io_uring::ring::install_release_hook();
    let inode_ref: vfs::InodeRef = make_io_uring_inode(inode);
    let dentry = vfs::dcache::d_alloc_pseudo("[io_uring]", inode_ref.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode_ref, dentry, OpenFlags::O_RDWR);
    match fdt.alloc_limit(file, cur.nofile_soft()) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}
