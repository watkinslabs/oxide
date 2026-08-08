// `SECCOMP_IOCTL_NOTIF_ADDFD`: hand one of the supervisor's open files to the
// task whose syscall it intercepted.
//
// The INSTALL is performed by the notified task, in its own context, when it
// wakes: the supervisor only queues the request and waits for the answer.
// That is what makes "put this descriptor in another process" need no writer
// into a descriptor table that is not the running task's.

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{OpenFlags, VfsError};

use super::listener::Listener;
use super::state::{self, AddFd};
use super::uapi::*;
use super::wait::{self, Woke};

/// Queue an injection and block until the notified task has performed it.
/// Returns the descriptor number installed IN THE TARGET.
/// # C: O(N_notifications) + wait
pub fn addfd(l: &Arc<Listener>, arg: u64, size: u32) -> Result<i64, Errno> {
    state::validate_addfd_size(size)?;
    let req = AddfdReq::decode(&read_extensible(arg, size)?);
    state::validate_addfd(&req)?;

    let file = source_file(req.srcfd)?;
    let seq = l.inner.lock().addfd_queue(req.id, file, &req)?;
    l.wake();

    loop {
        if let Some(ret) = l.inner.lock().addfd_collect(seq) { return Ok(ret); }
        // SAFETY: syscall process context on the running task's own CPU; the listener lock is not held across the park.
        let w = unsafe { wait::wait_until(&l.wq, false, || l.inner.lock().addfd_settled(seq)) };
        if w == Woke::Interrupted {
            // The injection may have completed in the same instant the signal
            // arrived; a completed one is reported, never discarded.
            let mut g = l.inner.lock();
            if let Some(ret) = g.addfd_collect(seq) { return Ok(ret); }
            g.addfd_cancel(req.id, seq);
            return Ok(syscall::restart::restart_sys());
        }
    }
}

/// `copy_struct_from_user` for the addfd request: members past the caller's
/// declared size read as zero, and a caller declaring MORE than this kernel
/// knows must have left the excess zero — otherwise it is asking for something
/// that would silently not happen.
/// # C: O(size)
fn read_extensible(arg: u64, size: u32) -> Result<[u8; ADDFD_SIZE_VER0 as usize], Errno> {
    let mut buf = [0u8; ADDFD_SIZE_VER0 as usize];
    let head = core::cmp::min(size, ADDFD_SIZE_VER0) as usize;
    uaccess::copy_from_user(&mut buf[..head], arg)?;
    let mut off = ADDFD_SIZE_VER0;
    let mut tail = [0u8; 64];
    while off < size {
        let n = core::cmp::min((size - off) as usize, tail.len());
        uaccess::copy_from_user(&mut tail[..n], arg + off as u64)?;
        if tail[..n].iter().any(|b| *b != 0) { return Err(Errno::E2big); }
        off += n as u32;
    }
    Ok(buf)
}

/// The supervisor's descriptor being handed over.
/// # C: O(1)
fn source_file(srcfd: u32) -> Result<Arc<vfs::File>, Errno> {
    let cur = sched::current().ok_or(Errno::Esrch)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of its own fd table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    fdt.get(srcfd as i32).map_err(|_| Errno::Ebadf)
}

/// Perform one queued injection. Runs on the NOTIFIED task, so the descriptor
/// lands in the table of the process the supervisor is acting on.
/// # C: O(1)
pub fn perform(a: &AddFd) -> i64 {
    let Some(cur) = sched::current() else { return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole writer of its own fd table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else {
        return -(Errno::Ebadf.as_i32() as i64);
    };
    let flags = if a.newfd_flags & O_CLOEXEC != 0 { OpenFlags::O_CLOEXEC }
                else { OpenFlags::empty() };
    let limit = cur.nofile_soft();
    let r = if a.setfd { fdt.replace_fd(a.newfd, a.file.clone(), flags, limit) }
            else { fdt.install_limit(a.file.clone(), flags, limit) };
    match r { Ok(fd) => fd as i64, Err(e) => -(install_errno(e).as_i32() as i64) }
}

/// Descriptor-table failure as the supervisor's `ADDFD` errno.
/// # C: O(1)
fn install_errno(e: VfsError) -> Errno {
    match e {
        VfsError::Emfile => Errno::Emfile,
        VfsError::Ebadf  => Errno::Ebadf,
        VfsError::Ebusy  => Errno::Ebusy,
        VfsError::Einval => Errno::Einval,
        _ => Errno::Einval,
    }
}

#[cfg(test)]
#[path = "tests/addfd.rs"]
mod tests;
