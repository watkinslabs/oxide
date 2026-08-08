// `mq_open(2)` (slot `NR_MQ_OPEN`) and `mq_unlink(2)` (slot `NR_MQ_UNLINK`).

use alloc::string::String;
use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{File, InodeRef, OpenFlags};

use crate::mqueue_policy::attr::validate_attr;
use crate::mqueue_policy::limits::{
    MQ_ATTR_BYTES, MQ_ATTR_MAXMSG_OFF, MQ_ATTR_MSGSIZE_OFF, PATH_MAX,
};
use crate::mqueue_policy::name::check_name;
use crate::mqueue_policy::open::{prepare_open, OpenAction, O_ACCMODE, O_NONBLOCK};

use super::model;
use super::user::{current_cred, errno, ipc_ns, read_user_i64};

/// Read the queue name with `getname()`'s length contract: a string that does
/// not fit in `PATH_MAX` bytes including its NUL is `ENAMETOOLONG`, and an
/// unreadable pointer is `EFAULT`. The empty-string and component rules are
/// `check_name`'s.
/// # C: O(PATH_MAX)
fn read_name(uptr: u64) -> Result<String, Errno> {
    if uptr == 0 || uptr >= hal::USER_VA_END { return Err(Errno::Efault); }
    let bytes = devfs::read_user_cstr(uptr, PATH_MAX).ok_or(Errno::Efault)?;
    if bytes.len() >= PATH_MAX { return Err(Errno::Enametoolong); }
    let s = core::str::from_utf8(&bytes).map_err(|_| Errno::Einval)?;
    Ok(String::from(s))
}

/// The syscall entry copies the WHOLE `struct mq_attr` before
/// the open logic runs, so a bad `u_attr` is `EFAULT`
/// ahead of every name and existence error. Only `mq_maxmsg`/`mq_msgsize` are
/// consumed; the rest of the struct is read (for the fault) and discarded.
/// # C: O(1)
fn read_attr(uptr: u64) -> Result<(i64, i64), Errno> {
    if uptr >= hal::USER_VA_END
        || uptr.checked_add(MQ_ATTR_BYTES as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    for off in (0..MQ_ATTR_BYTES as u64).step_by(8) { read_user_i64(uptr + off)?; }
    Ok((read_user_i64(uptr + MQ_ATTR_MAXMSG_OFF)?, read_user_i64(uptr + MQ_ATTR_MSGSIZE_OFF)?))
}

/// Publish `inode` as a descriptor. An mq descriptor is
/// UNCONDITIONALLY close-on-exec, whatever `oflag` asked for. That is also
/// what keeps a notification registration from surviving an `exec` into an
/// unrelated program.
/// # C: O(1)
fn install(inode: InodeRef, name: &str, oflag: i32) -> i64 {
    let Some(q) = model::queue_of(&inode) else { return errno(Errno::Ebadf) };
    let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }).map(|t| t.clone()) else {
        return errno(Errno::Ebadf);
    };
    // Linux mqueuefs dentry name is the bare queue name (the leading `/` was
    // already stripped by libc before the syscall).
    let dentry = vfs::dcache::d_alloc_pseudo(name, inode.clone(),
                                             &crate::live::anon_dname::MQUEUE_OPS);
    let fl = OpenFlags::from_bits_retain((oflag & (O_ACCMODE | O_NONBLOCK)) as u32);
    model::open_ref(&q);
    let file: Arc<File> = File::new(inode, dentry, fl);
    match fdt.install_limit(file, fl | OpenFlags::O_CLOEXEC, cur.nofile_soft()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_mq_open(name, oflag, mode, attr)` — slot `NR_MQ_OPEN`.
/// # C: O(N_queues) lookup
pub fn sys_mq_open(args: &syscall::SyscallArgs) -> i64 {
    let oflag = args.a1 as i32;
    let mode = args.a2 as u16;

    let attr = if args.a3 == 0 { None } else {
        match read_attr(args.a3) { Ok(a) => Some(a), Err(e) => return errno(e) }
    };
    let name = match read_name(args.a0) { Ok(n) => n, Err(e) => return errno(e) };
    if let Err(e) = check_name(&name) { return errno(e); }

    let ns = match ipc_ns() { Ok(n) => n, Err(e) => return errno(e) };
    let cred = current_cred();
    let existing = model::lookup(ns, &name);
    let action = match prepare_open(existing.is_some(), oflag) {
        Ok(a) => a, Err(e) => return errno(e),
    };
    match action {
        OpenAction::OpenExisting { may_read, may_write } => {
            let inode = match existing { Some(i) => i, None => return errno(Errno::Enoent) };
            let mut mask = 0u32;
            if may_read { mask |= vfs::namei::MAY_READ; }
            if may_write { mask |= vfs::namei::MAY_WRITE; }
            // A zero mask (`O_ACCMODE == 3` reached through a
            // create) grants trivially, exactly as the standard inode
            // permission check does.
            if mask != 0 {
                if let Err(e) = vfs::namei::inode_permission(&inode, mask, &cred) {
                    return -(e as i64);
                }
            }
            install(inode, &name, oflag)
        }
        OpenAction::Create => {
            let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
            let cap_res = cur.has_cap(sched::cap::SYS_RESOURCE);
            let sysctls = model::sysctls(ns);
            let created = match validate_attr(attr, &sysctls, cap_res) {
                Ok(c) => c, Err(e) => return errno(e),
            };
            // The new inode's mode is the caller's requested mode masked by umask.
            let perm = (mode & 0o7777) & !(cur.umask() as u16);
            let rlimit_cur = cur.rlimit(sched::rlimit::rlim::MSGQUEUE).0;
            let inode = match model::create_linked(
                ns, &name, perm, cred.uid, cred.gid,
                created.maxmsg as usize, created.msgsize as usize,
                created.mq_bytes, rlimit_cur, cap_res)
            {
                Ok(i) => i, Err(e) => return errno(e),
            };
            install(inode, &name, oflag)
        }
    }
}

/// `sys_mq_unlink(name)` — slot `NR_MQ_UNLINK`. The link goes; descriptors
/// already open keep working until the last one closes (POSIX), which is when
/// the namespace queue count and the RLIMIT_MSGQUEUE charge are released.
/// # C: O(N_queues)
pub fn sys_mq_unlink(args: &syscall::SyscallArgs) -> i64 {
    let name = match read_name(args.a0) { Ok(n) => n, Err(e) => return errno(e) };
    if let Err(e) = check_name(&name) { return errno(e); }
    let ns = match ipc_ns() { Ok(n) => n, Err(e) => return errno(e) };
    let Some(inode) = model::lookup(ns, &name) else { return errno(Errno::Enoent) };
    let root = model::root_inode(ns);
    // Unlink permission on the mqueue root: write+search on a
    // 01777 directory (so anyone may try) and then the STICKY owner test, which
    // is what makes a non-owner's `mq_unlink` EPERM rather than a silent
    // deletion of somebody else's queue.
    if let Err(e) = vfs::namei::may_delete(&root, &inode, false, &current_cred()) {
        return -(e as i64);
    }
    model::unlink(ns, &name);
    0
}
