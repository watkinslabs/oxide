// 044 sendto — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::sock::SockKind;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET, AF_INET6, errno_from_neterr, fd_file, file_is_nonblock, inode_as_inet_socket, inode_as_vsock};
use crate::userbuf::validate_user_buf_readable;

fn validate_send_payload(bufp: u64, len: usize) -> Result<(), i64> {
    if len == 0 { return Ok(()); }
    validate_user_buf_readable(bufp, len as u64, 1)
}

fn copy_send_payload(bufp: u64, len: usize) -> alloc::vec::Vec<u8> {
    if len == 0 { return alloc::vec::Vec::new(); }
    // SAFETY: bufp..bufp+len was validated readable in the caller address space.
    unsafe { core::slice::from_raw_parts(bufp as *const u8, len).to_vec() }
}

pub(crate) fn parse_send_dest(sock: &net::sock::InetSocket, dest_p: u64, dest_len: u64) -> Result<(Option<net::sock::RemoteAddr>, usize), i64> {
    if dest_p == 0 { return Ok((None, 0)); }
    let len = move_sockaddr_to_kernel_shape(dest_p, dest_len)?;
    if matches!(*sock.kind.lock(), SockKind::UnixDgram(_)) {
        let p = read_sockaddr_un_path_len(dest_p, len as u64).ok_or(-(Errno::Einval.as_i32() as i64))?;
        return crate::namei_common::resolve_unix_addr(p).map(|a| (Some(net::sock::RemoteAddr::Unix(a)), len));
    }
    let fam = read_sa_family_checked(dest_p, len)?;
    if fam == AF_INET6 as u16 {
        require_sockaddr_in6(len)?;
        return match read_sockaddr_in6(dest_p) {
            Some((_fam, port, bytes, _scope)) => Ok((Some(net::sock::RemoteAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }), len)),
            None => Err(-(Errno::Efault.as_i32() as i64)),
        };
    }
    if fam == AF_INET as u16 {
        require_sockaddr_in(len)?;
        return match read_sockaddr_any(dest_p) {
            Some((_fam, ip, port)) => Ok((Some(net::sock::RemoteAddr::Inet { ip, port }), len)),
            None => Err(-(Errno::Eafnosupport.as_i32() as i64)),
        };
    }
    Err(-(Errno::Eafnosupport.as_i32() as i64))
}

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44.
/// # C: O(payload bytes)
pub fn sys_sendto(args: &SyscallArgs) -> i64 {
    const MSG_DONTWAIT: u64 = 0x40;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let flags  = args.a3;
    let dest_p = args.a4;
    let dest_len = args.a5;
    if let Err(e) = validate_send_payload(bufp, len) {
        return e;
    }
    let file = match fd_file(fd) {
        Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let generic_dest_len = || -> Result<usize, i64> {
        if dest_p == 0 { Ok(0) } else { move_sockaddr_to_kernel_shape(dest_p, dest_len) }
    };
    if crate::netlink_fd::is_netlink_file(&file) {
        let dest_len = match generic_dest_len() {
            Ok(n) => n,
            Err(e) => return e,
        };
        let payload = copy_send_payload(bufp, len);
        return crate::netlink_fd::send_coalesced_file(&file, &payload, dest_p, dest_len as u64);
    }
    if inode_as_vsock(file.inode()).is_some() {
        if let Err(e) = generic_dest_len() {
            return e;
        }
        let payload = copy_send_payload(bufp, len);
        let nb = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
        let r = if nb { file.inode().write_nonblock(0, &payload) } else { file.inode().write(0, &payload) };
        return match r { Ok(n) => n as i64, Err(e) => -(e as i64) };
    }
    let sock   = match inode_as_inet_socket(file.inode()) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"sendto"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
        let dest_len = match generic_dest_len() {
            Ok(n) => n,
            Err(e) => return e,
        };
        let payload = copy_send_payload(bufp, len);
        if let Some(rv) = crate::af_packet::sendto(&sock, &payload, dest_p, dest_len) {
            return rv;
        }
    }
    let (dest, _dest_len) = match parse_send_dest(&sock, dest_p, dest_len) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let payload = copy_send_payload(bufp, len);
    send_over_socket(&sock, &payload, dest, flags, fd)
}

/// Send one kernel-space `payload` as a SINGLE message over an already-resolved
/// socket — the shared core of `sendto` and the `sendmsg` iovec-coalescing path.
/// A `sendmsg(2)` iovec array is ONE message (Linux: the datagram is the
/// concatenation of every iovec), so `sendmsg` coalesces into one buffer and
/// calls this once instead of emitting one datagram per iovec.
/// # C: O(payload bytes)
pub fn send_over_socket(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    payload: &[u8],
    dest: Option<net::sock::RemoteAddr>,
    flags: u64,
    fd: u64,
) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    const MSG_DONTWAIT: u64 = 0x40;
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.sndtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    // Fetch sender creds for AF_UNIX SCM.
    let creds = match sched::live::current() {
        Some(t) => net::sock::SenderCreds {
            pid: t.visible_pid(),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => net::sock::SenderCreds::default(),
    };
    loop {
        match net::sock::sendto(sock, payload, dest.clone(), creds) {
            Ok(n)  => return n as i64,
            Err(net::NetError::Eagain) => {
                if nonblock { return -(Errno::Eagain.as_i32() as i64); }
                if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
                // SAFETY: process ctx; runqueue installed; preempt-off; tick_yield reschedules.
                unsafe { sched::live::tick_yield(); }
            }
            Err(e) => return errno_from_neterr(e),
        }
    }
}
