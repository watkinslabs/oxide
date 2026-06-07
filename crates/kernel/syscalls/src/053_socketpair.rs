// 053 socketpair — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::{InetSocket, SockKind};
use crate::net_common::{SOCK_STREAM, SOCK_DGRAM};

/// `socketpair` slot 53. AF_UNIX STREAM / SEQPACKET / DGRAM (F125).
/// # C: O(1)
pub fn sys_socketpair(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u32 = 1;
    const SOCK_TYPE_MASK: u32 = 0xF;
    const SOCK_SEQPACKET: u32 = 5;
    let domain = args.a0 as u32;
    let typ    = args.a1 as u32 & SOCK_TYPE_MASK;
    let svp    = args.a3;
    if domain != AF_UNIX { return -(Errno::Eafnosupport.as_i32() as i64); }
    if typ != SOCK_STREAM && typ != SOCK_SEQPACKET && typ != SOCK_DGRAM {
        return -(Errno::Esocktnosupport.as_i32() as i64);
    }
    if svp == 0 || svp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let stream = if typ == SOCK_STREAM { Some(net::UnixPair::new()) } else { None };
    let msg    = if typ != SOCK_STREAM { Some(net::UnixMsgPair::new()) } else { None };
    let mk = |end: net::UnixEnd| -> vfs::InodeRef {
        let s = InetSocket::new_tcp();
        if let Some(p) = &stream {
            *s.kind.lock() = SockKind::Unix(p.clone(), end);
            // F181a: tell the pair which subscribers wake on
            // peer-end writes/close.
            p.register_end_subs(end, &s.poll_subs);
        } else if let Some(p) = &msg {
            *s.kind.lock() = SockKind::UnixMsgPair(p.clone(), end);
            p.register_end_subs(end, &s.poll_subs);
        }
        Arc::new(s) as _
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SO_PEERCRED: both ends of a socketpair belong to the caller.
    if let Some(p) = &stream {
        use core::sync::atomic::Ordering;
        let (pid, uid, gid) = (cur.tgid.load(Ordering::Relaxed),
            cur.creds.euid.load(Ordering::Relaxed), cur.creds.egid.load(Ordering::Relaxed));
        p.set_end_cred(net::UnixEnd::A, pid, uid, gid);
        p.set_end_cred(net::UnixEnd::B, pid, uid, gid);
    }
    if let Some(p) = &msg {
        use core::sync::atomic::Ordering;
        let (pid, uid, gid) = (cur.tgid.load(Ordering::Relaxed),
            cur.creds.euid.load(Ordering::Relaxed), cur.creds.egid.load(Ordering::Relaxed));
        p.set_end_cred(net::UnixEnd::A, pid, uid, gid);
        p.set_end_cred(net::UnixEnd::B, pid, uid, gid);
    }
    let a = {
        let inode = mk(net::UnixEnd::A);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
        match fdt.alloc(f) { Ok(fd) => fd, Err(e) => return -(e as i64) }
    };
    let b = {
        let inode = mk(net::UnixEnd::B);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
        match fdt.alloc(f) { Ok(fd) => fd, Err(e) => return -(e as i64) }
    };
    // Write both fds back to user[]int sv[2].
    // SAFETY: svp range validated < USER_VA_END; user page mapped.
    unsafe {
        core::ptr::write_volatile( svp           as *mut i32, a as i32);
        core::ptr::write_volatile((svp + 4)      as *mut i32, b as i32);
    }
    0
}
