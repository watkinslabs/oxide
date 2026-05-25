// F189: SCM_RIGHTS parsing for sys_sendmsg + helpers to thread
// Arc<File> through AF_UNIX SOCK_DGRAM. Receiver side lives in
// crates/kernel/net/src/unix_cmsg.rs (writeback after pop).

use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::USER_VA_END;
use net::sock::{InetSocket, SockKind, SenderCreds};
use syscall::errno::Errno;
use vfs::File;

const SOL_SOCKET:  i32 = 1;
const SCM_RIGHTS:  i32 = 1;

/// Detect & dispatch SCM_RIGHTS on AF_UNIX SOCK_DGRAM. Returns
/// Some(rc) when fds rode along; None otherwise (caller falls back
/// to plain iovec walk).
/// # C: O(controllen + iov)
pub fn try_sendmsg_with_fds(
    fd: u64, name: u64, iov: u64, iovlen: u64,
    control: u64, controllen: u64,
) -> Option<i64> {
    if controllen < 16 || control == 0 || control >= USER_VA_END { return None; }
    let s = crate::syscalls::net::socket_from_fd(fd)?;
    if !matches!(*s.kind.lock(), SockKind::UnixDgram(_)) { return None; }
    let fds = parse_scm_rights(control, controllen);
    if fds.is_empty() { return None; }
    Some(sendmsg_unix_dgram_with_fds(&s, name, iov, iovlen, fds))
}

/// Parse a control buffer of length `len` for SCM_RIGHTS cmsgs;
/// returns Arc<File> refs for every fd in caller's fd_table. Bogus
/// fds → silently skipped (Linux returns -EBADF if ANY is bad, but
/// v1 simplifies; tighten later).
/// # C: O(controllen)
pub fn parse_scm_rights(control: u64, controllen: u64) -> Vec<Arc<File>> {
    let mut out: Vec<Arc<File>> = Vec::new();
    let cur = sched::live::current();
    // SAFETY: caller is the currently running task — sole reader of fd_table.
    let fdt = match cur.as_ref().and_then(|c| unsafe { c.fd_table_ref() }) {
        Some(t) => t.clone(), None => return out,
    };
    let mut off: u64 = 0;
    while off + 16 <= controllen {
        let base = control + off;
        if base + 16 > USER_VA_END { break; }
        // SAFETY: base validated < USER_VA_END − 16; cmsghdr is 8-byte aligned per ABI.
        let (cmsg_len, cmsg_level, cmsg_type) = unsafe {
            (core::ptr::read_volatile( base        as *const u64),
             core::ptr::read_volatile((base +  8)  as *const i32),
             core::ptr::read_volatile((base + 12)  as *const i32))
        };
        if cmsg_len < 16 || cmsg_len > controllen - off { break; }
        if cmsg_level == SOL_SOCKET && cmsg_type == SCM_RIGHTS {
            let nfds = ((cmsg_len - 16) / 4) as u64;
            for i in 0..nfds {
                // SAFETY: data area inside cmsg bounded by cmsg_len.
                let fd = unsafe {
                    core::ptr::read_volatile((base + 16 + i * 4) as *const i32)
                };
                if let Ok(f) = fdt.get(fd) { out.push(f); }
            }
        }
        // Advance to next cmsg (8-byte aligned).
        let pad = (cmsg_len + 7) & !7;
        off += pad;
    }
    out
}

/// Send a unix-dgram message with fds attached. Captures iovec
/// contents into a single payload Vec; pushes onto target queue.
/// # C: O(payload + nfds)
pub fn sendmsg_unix_dgram_with_fds(
    sock: &Arc<InetSocket>, name: u64, iov: u64, iovlen: u64,
    fds: Vec<Arc<File>>,
) -> i64 {
    // Resolve target queue: explicit `name` path or stashed peer.
    let path: alloc::string::String = if name != 0 {
        match crate::syscalls::net::read_sockaddr_un_path(name) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        }
    } else {
        match &*sock.kind.lock() {
            SockKind::UnixDgram(_) => {
                // No stashed peer path yet; v1 requires an explicit name.
                return -(Errno::Edestaddrreq.as_i32() as i64);
            }
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    };
    let q = match net::sock::UNIX_REGISTRY.dgram_lookup(&path) {
        Some(q) => q, None => return -(Errno::Econnrefused.as_i32() as i64),
    };
    // Concatenate iovecs into one payload.
    let mut payload: Vec<u8> = Vec::new();
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i+16 inside validated user iov array.
        let (base, len) = unsafe {
            (core::ptr::read_volatile( iov_i      as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64))
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let start = payload.len();
        payload.resize(start + len as usize, 0);
        // SAFETY: dst is owned Vec capacity, src is validated user iov entry.
        unsafe {
            core::ptr::copy_nonoverlapping(
                base as *const u8,
                payload.as_mut_ptr().add(start),
                len as usize,
            );
        }
    }
    let creds = match sched::live::current() {
        Some(t) => SenderCreds {
            pid: t.tgid.load(core::sync::atomic::Ordering::Acquire),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => SenderCreds::default(),
    };
    let n = payload.len();
    q.push(net::UnixDgram {
        payload,
        creds: (creds.pid, creds.uid, creds.gid),
        fds,
    });
    n as i64
}
