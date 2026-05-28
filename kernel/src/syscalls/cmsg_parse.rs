// F189: SCM_RIGHTS parsing for sys_sendmsg + helpers to thread
// Arc<File> through AF_UNIX SOCK_DGRAM. Receiver side lives in
// crates/kernel/net/src/unix_cmsg.rs (writeback after pop).

use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::USER_VA_END;
use net::sock::{InetSocket, SockKind, SenderCreds};
use syscall::errno::Errno;
use vfs::File;
use core::sync::atomic::Ordering;

const SOL_SOCKET:  i32 = 1;
const SCM_RIGHTS:  i32 = 1;

/// Detect & dispatch SCM_RIGHTS on AF_UNIX SOCK_DGRAM **or** SOCK_STREAM.
/// Returns Some(rc) when fds rode along; None otherwise (caller falls
/// back to plain iovec walk). openssh's monitor↔preauth privsep uses
/// socketpair(SOCK_STREAM) and relies on SCM_RIGHTS to hand back the
/// pty master/slave fds — so STREAM support is mandatory, not optional.
/// # C: O(controllen + iov)
pub fn try_sendmsg_with_fds(
    fd: u64, name: u64, iov: u64, iovlen: u64,
    control: u64, controllen: u64,
) -> Option<i64> {
    if controllen < 16 || control == 0 || control >= USER_VA_END { return None; }
    let s = crate::syscalls::net::socket_from_fd(fd)?;
    let kind_kind = {
        let g = s.kind.lock();
        match &*g {
            SockKind::UnixDgram(_)    => 1u8,
            SockKind::Unix(_, _)      => 2u8,
            SockKind::UnixMsgPair(_, _) => 3u8,
            _ => 0u8,
        }
    };
    if kind_kind == 0 { return None; }
    let fds = parse_scm_rights(control, controllen);
    if fds.is_empty() { return None; }
    match kind_kind {
        1 => Some(sendmsg_unix_dgram_with_fds(&s, name, iov, iovlen, fds)),
        2 | 3 => Some(sendmsg_unix_stream_with_fds(&s, iov, iovlen, fds)),
        _ => None,
    }
}

/// Send iovec payload over a stream socketpair and queue the fd burst
/// for the peer's next recvmsg. Writes bytes via the pair's write()
/// path (skipping sys_sendto since we already hold the InetSocket and
/// have parsed iovecs); fds queue on per-direction FIFO so the next
/// recvmsg-with-cmsg hands them to the receiver.
/// # C: O(iov + nfds)
pub fn sendmsg_unix_stream_with_fds(
    sock: &Arc<InetSocket>, iov: u64, iovlen: u64, fds: alloc::vec::Vec<Arc<File>>,
) -> i64 {
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    // Concatenate iovecs into a single payload.
    let mut payload: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated; user-mapped iovec entry; 8-byte aligned base/len fields per Linux ABI.
        let (base, len) = unsafe {
            (core::ptr::read_volatile( iov_i      as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64))
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let start = payload.len();
        payload.resize(start + len as usize, 0);
        // SAFETY: src is validated user iov range; dst is owned Vec capacity.
        unsafe {
            core::ptr::copy_nonoverlapping(
                base as *const u8,
                payload.as_mut_ptr().add(start),
                len as usize,
            );
        }
    }
    // Push fds BEFORE the bytes so a fast peer reading the bytes
    // can't observe data without also seeing the matching cmsg on
    // its next recvmsg.
    let g = sock.kind.lock();
    match &*g {
        SockKind::Unix(pair, end) => {
            pair.push_fds(*end, fds);
            pair.write(*end, &payload);
            payload.len() as i64
        }
        SockKind::UnixMsgPair(pair, end) => {
            // SEQPACKET: dgram-like framing; piggyback fds on the
            // message. UnixMsgPair has its own send path; for v1 we
            // route through the pair's send() and lose the fds since
            // openssh's privsep uses STREAM not SEQPACKET. Mark TODO.
            let n = pair.send(*end, &payload);
            let _ = fds; // dropped per the v1 limitation above
            n as i64
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
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

/// recvmsg(2) for AF_UNIX SOCK_STREAM (socketpair). Reads payload
/// into the caller's iovec via the underlying pair, then if the pair
/// has a pending SCM_RIGHTS burst from the prior sendmsg, installs
/// each Arc<File> into the caller's fd_table and writes a SOL_SOCKET
/// / SCM_RIGHTS cmsg block to msg_control. Sets msg_controllen to the
/// bytes actually written; MSG_CTRUNC bit on msg_flags when the cmsg
/// buffer was too small.
/// # C: O(iov + payload + nfds)
pub fn recvmsg_unix_stream(sock: &Arc<InetSocket>, msgp: u64) -> i64 {
    // SAFETY: msgp range validated by caller (sys_recvmsg).
    let (iov, iovlen, control, controllen) = unsafe {
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        let control   = core::ptr::read_volatile((msgp + 32) as *const u64);
        let controllen= core::ptr::read_volatile((msgp + 40) as *const u64);
        (iov, iovlen, control, controllen)
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    // Read payload directly via the pair, bypassing fd→sock lookup.
    let mut total: i64 = 0;
    'iovloop: for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated; user-mapped iovec entry per Linux ABI.
        let (base, len) = unsafe {
            (core::ptr::read_volatile( iov_i      as *const u64),
             core::ptr::read_volatile((iov_i + 8) as *const u64))
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // Drain up to `len` bytes. Block on the first iov if nothing
        // is queued; subsequent iovs do a single non-block drain
        // (matches Linux short-read semantics for stream recvmsg).
        loop {
            let chunk = {
                let g = sock.kind.lock();
                if let SockKind::Unix(pair, end) = &*g {
                    pair.read(*end, len as usize)
                } else { return -(Errno::Einval.as_i32() as i64); }
            };
            if !chunk.is_empty() {
                // SAFETY: base..base+chunk.len() inside validated iov entry; CPL=0 writes to caller AS.
                unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), base as *mut u8, chunk.len()); }
                total += chunk.len() as i64;
                if (chunk.len() as u64) < len { break 'iovloop; }
                continue 'iovloop;
            }
            // No data — block only on first iov.
            if total > 0 { break 'iovloop; }
            // EOF check: peer's writer closed AND buffer empty.
            let eof = {
                let g = sock.kind.lock();
                if let SockKind::Unix(pair, end) = &*g {
                    pair.is_eof(*end)
                } else { false }
            };
            if eof { break 'iovloop; }
            // SAFETY: process ctx; runqueue installed; tick_yield reschedules.
            unsafe { sched::live::tick_yield(); }
        }
    }
    // Pop the fd burst now (after bytes are consumed) so a peer that
    // sent payload+fds in one sendmsg sees them delivered together.
    let pending_fds: Vec<Arc<File>> = {
        let g = sock.kind.lock();
        match &*g {
            SockKind::Unix(pair, end) => pair.pop_fds(*end),
            _ => Vec::new(),
        }
    };
    let mut ctrl_written: u64 = 0;
    let mut ctrunc = false;
    if !pending_fds.is_empty() {
        if control == 0 || controllen < 16 || control >= USER_VA_END {
            ctrunc = true;
        } else {
            const SOL_SOCKET: i32 = 1;
            const SCM_RIGHTS: i32 = 1;
            let cur = sched::live::current();
            // SAFETY: running task on this CPU; preempt-off owned by syscall stub; sole reader of fd_table per `13§5` single-mutator.
            let fdt = match cur.as_ref().and_then(|c| unsafe { c.fd_table_ref() }) {
                Some(t) => t.clone(), None => return total,
            };
            let nfds = pending_fds.len();
            let fit_n = {
                let max_data = controllen.saturating_sub(16) as usize / 4;
                if max_data < nfds { ctrunc = true; }
                core::cmp::min(nfds, max_data)
            };
            let mut allocated_fds: Vec<i32> = Vec::with_capacity(fit_n);
            for f in pending_fds.iter().take(fit_n) {
                match fdt.alloc((*f).clone()) {
                    Ok(nfd) => allocated_fds.push(nfd),
                    Err(_)  => { ctrunc = true; break; }
                }
            }
            let real_n = allocated_fds.len();
            let real_cmsg_total = 16 + (real_n * 4) as u64;
            if real_n > 0 && real_cmsg_total <= controllen {
                // SAFETY: control range validated; CPL=0 writes; cmsghdr 8-byte aligned per Linux ABI.
                unsafe {
                    core::ptr::write_volatile( control       as *mut u64, real_cmsg_total);
                    core::ptr::write_volatile((control +  8) as *mut i32, SOL_SOCKET);
                    core::ptr::write_volatile((control + 12) as *mut i32, SCM_RIGHTS);
                    for (i, nfd) in allocated_fds.iter().enumerate() {
                        core::ptr::write_volatile(
                            (control + 16 + (i * 4) as u64) as *mut i32,
                            *nfd,
                        );
                    }
                }
                ctrl_written = real_cmsg_total;
            } else if !allocated_fds.is_empty() {
                for nfd in &allocated_fds { let _ = fdt.close(*nfd); }
                ctrunc = true;
            }
        }
    }
    // SAFETY: msgp validated by caller; controllen at +40, flags at +48 per Linux msghdr.
    unsafe {
        core::ptr::write_volatile((msgp + 40) as *mut u64, ctrl_written);
        const MSG_CTRUNC: i32 = 0x08;
        let flags_at = (msgp + 48) as *mut i32;
        let cur = core::ptr::read_volatile(flags_at);
        let new = if ctrunc { cur | MSG_CTRUNC } else { cur };
        core::ptr::write_volatile(flags_at, new);
    }
    let _ = Ordering::Acquire;
    total
}
