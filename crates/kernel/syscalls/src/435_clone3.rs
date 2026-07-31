// 435 clone3 — one syscall, one file (docs/53 §0). ABI shim only: copy the
// versioned `struct clone_args`, run the ladders in `clone_abi`, resolve the
// `CLONE_INTO_CGROUP` descriptor, hand off to the shared clone core.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::clone_abi::{
    self, CloneArgs, CLONE_ARGS_SIZE_VER2, CLONE_INTO_CGROUP, CLONE_PIDFD,
};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Copy the caller's `struct clone_args` into a full-size, zero-extended
/// buffer. A caller-declared size shorter than this kernel's struct leaves the
/// unknown fields zero; a longer one has its unknown tail checked for zero, and
/// the verdict is returned so the field ladder can turn it into `E2BIG` in the
/// right order. A fault anywhere is `EFAULT` and outranks both.
/// # C: O(size)
fn copy_clone_args(uptr: u64, size: usize) -> Result<(CloneArgs, bool), Errno> {
    let mut raw = [0u8; CLONE_ARGS_SIZE_VER2];
    let known = core::cmp::min(size, CLONE_ARGS_SIZE_VER2);
    uaccess::copy_from_user(&mut raw[..known], uptr)?;
    let mut tail_zero = true;
    if size > CLONE_ARGS_SIZE_VER2 {
        let mut off = CLONE_ARGS_SIZE_VER2;
        let mut chunk = [0u8; 64];
        while off < size {
            let n = core::cmp::min(chunk.len(), size - off);
            uaccess::copy_from_user(&mut chunk[..n], uptr + off as u64)?;
            if chunk[..n].iter().any(|b| *b != 0) { tail_zero = false; break; }
            off += n;
        }
    }
    let mut words = [0u64; CLONE_ARGS_SIZE_VER2 / 8];
    for (i, w) in words.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&raw[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    Ok((CloneArgs::from_slots(&words), tail_zero))
}

/// Resolve `clone_args::cgroup` to the cgroup the child is created inside.
/// # C: O(1)
fn resolve_cgroup(fd: i32) -> Result<u64, Errno> {
    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?;
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let inode = file.inode();
    if inode.file_type() != vfs::FileType::Directory { return Err(Errno::Einval); }
    cgroup::cgid_from_dir_inode(&inode).ok_or(Errno::Einval)
}

/// `sys_clone3(cl_args, size)` — slot 435. Returns the child's pid in the
/// parent and 0 in the child.
/// # C: O(parent VMAs) | O(1) for CLONE_VM
pub fn sys_clone3(args: &SyscallArgs) -> i64 {
    let uptr = args.a0;
    let size = args.a1 as usize;
    if let Err(e) = clone_abi::clone3_size_ok(size) { return errno(e); }
    let (cl, tail_zero) = match copy_clone_args(uptr, size) {
        Ok(v) => v,
        Err(e) => return errno(e),
    };
    if let Err(e) = clone_abi::clone3_fields_ok(&cl, size, tail_zero) { return errno(e); }
    let mut requested = [0u32; clone_abi::MAX_PID_NS_LEVEL];
    let requested_len = cl.set_tid_size as usize;
    if requested_len != 0 {
        let n = requested_len;
        let mut bytes = [0u8; clone_abi::MAX_PID_NS_LEVEL * 4];
        if let Err(e) = uaccess::copy_from_user(&mut bytes[..n * 4], cl.set_tid) { return errno(e); }
        for i in 0..n {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
            requested[i] = u32::from_le_bytes(b);
        }
        if let Err(e) = crate::clone::set_requested_pids_ok(&requested[..n]) { return errno(e); }
    }
    let stack_ok = cl.stack == 0
        || uaccess::access_ok(cl.stack, cl.stack_size as usize);
    if let Err(e) = clone_abi::clone3_flags_ok(&cl, stack_ok) { return errno(e); }
    let into_cgid = if (cl.flags & CLONE_INTO_CGROUP) != 0 {
        match resolve_cgroup(cl.cgroup as i32) {
            Ok(id) => Some(id),
            Err(e) => return errno(e),
        }
    } else {
        None
    };
    if (cl.flags & CLONE_PIDFD) != 0 && !uaccess::access_ok(cl.pidfd, core::mem::size_of::<i32>()) {
        return errno(Errno::Efault);
    }
    crate::clone::sys_clone_dispatch(clone_abi::CloneRequest {
        flags: cl.flags,
        exit_signal: cl.exit_signal as u32,
        child_stack: clone_abi::clone3_child_sp(&cl),
        parent_tid: cl.parent_tid,
        pidfd: cl.pidfd,
        child_tid: cl.child_tid,
        tls: cl.tls,
        into_cgroup: into_cgid,
        set_tid: &requested[..requested_len],
    })
}
