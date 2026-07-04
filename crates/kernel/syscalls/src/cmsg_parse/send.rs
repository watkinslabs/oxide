use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::USER_VA_END;
use net::sock::{InetSocket, SenderCreds, SockKind};
use syscall::errno::Errno;
use vfs::File;

use super::parse::parse_scm_rights;

/// Detect & dispatch SCM_RIGHTS on AF_UNIX SOCK_DGRAM **or** SOCK_STREAM.
/// Returns Some(rc) when fds rode along; None otherwise (caller falls
/// back to plain iovec walk). openssh's monitor↔preauth privsep uses
/// socketpair(SOCK_STREAM) and relies on SCM_RIGHTS to hand back the
/// pty master/slave fds — so STREAM support is mandatory, not optional.
/// # C: O(controllen + iov)
pub fn try_sendmsg_with_fds(
    fd: u64, name: u64, namelen: u64, iov: u64, iovlen: u64,
    control: u64, controllen: u64,
) -> Option<i64> {
    if controllen < 16 || control == 0 || control >= USER_VA_END { return None; }
    let s = crate::net_common::socket_from_fd(fd)?;
    let kind_kind = {
        let g = s.kind.lock();
        match &*g {
            SockKind::UnixDgram(_) => 1u8,
            SockKind::Unix(_, _) => 2u8,
            SockKind::UnixMsgPair(_, _) => 3u8,
            _ => 0u8,
        }
    };
    if kind_kind == 0 { return None; }
    let fds = parse_scm_rights(control, controllen);
    if fds.is_empty() { return None; }
    match kind_kind {
        1 => Some(sendmsg_unix_dgram_with_fds(&s, name, namelen, iov, iovlen, fds)),
        2 | 3 => Some(sendmsg_unix_stream_with_fds(&s, iov, iovlen, fds)),
        _ => None,
    }
}

/// Send iovec payload over a stream socketpair and queue the fd burst
/// for the peer's next recvmsg.
/// # C: O(iov + nfds)
pub fn sendmsg_unix_stream_with_fds(sock: &Arc<InetSocket>, iov: u64, iovlen: u64, fds: Vec<Arc<File>>) -> i64 {
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut payload: Vec<u8> = Vec::new();
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated; user-mapped iovec entry; 8-byte aligned base/len fields per Linux ABI.
        let (base, len) = unsafe {
            (
                core::ptr::read_volatile(iov_i as *const u64),
                core::ptr::read_volatile((iov_i + 8) as *const u64),
            )
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let start = payload.len();
        payload.resize(start + len as usize, 0);
        // SAFETY: src is validated user iov range; dst is owned Vec capacity.
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, payload.as_mut_ptr().add(start), len as usize); }
    }
    let g = sock.kind.lock();
    match &*g {
        SockKind::Unix(pair, end) => {
            pair.push_fds(*end, fds);
            pair.write(*end, &payload);
            payload.len() as i64
        }
        SockKind::UnixMsgPair(pair, end) => pair.send_with_fds(*end, &payload, fds) as i64,
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// Send a unix-dgram message with fds attached.
/// # C: O(payload + nfds)
pub fn sendmsg_unix_dgram_with_fds(
    sock: &Arc<InetSocket>, name: u64, namelen: u64, iov: u64, iovlen: u64,
    fds: Vec<Arc<File>>,
) -> i64 {
    let path: alloc::string::String = if name != 0 {
        match crate::net_sockaddr::read_sockaddr_un_path_len(name, namelen) {
            Some(p) => p,
            None => return -(Errno::Einval.as_i32() as i64),
        }
    } else {
        match &*sock.kind.lock() {
            SockKind::UnixDgram(q) => match q.peer() {
                Some(p) => p,
                None => return -(Errno::Edestaddrreq.as_i32() as i64),
            },
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    };
    let q = match net::sock::UNIX_REGISTRY.dgram_lookup(&path) {
        Some(q) => q,
        None => return -(Errno::Econnrefused.as_i32() as i64),
    };
    let mut payload: Vec<u8> = Vec::new();
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i+16 inside validated user iov array.
        let (base, len) = unsafe {
            (
                core::ptr::read_volatile(iov_i as *const u64),
                core::ptr::read_volatile((iov_i + 8) as *const u64),
            )
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let start = payload.len();
        payload.resize(start + len as usize, 0);
        // SAFETY: dst is owned Vec capacity, src is validated user iov entry.
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, payload.as_mut_ptr().add(start), len as usize); }
    }
    let creds = match sched::live::current() {
        Some(t) => SenderCreds {
            pid: t.visible_pid(),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => SenderCreds::default(),
    };
    let n = payload.len();
    net::trace_dgram_journal(&path, &payload);
    q.push(net::UnixDgram { payload, creds: (creds.pid, creds.uid, creds.gid), fds });
    n as i64
}
