use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use hal::USER_VA_END;
use net::sock::{InetSocket, SockKind};
use net::uapi::{MSG_CTRUNC, MSG_DONTWAIT};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::File;

use crate::net_common::file_is_nonblock;

use super::parse::{SCM_RIGHTS, SOL_SOCKET};

/// recvmsg(2) for AF_UNIX SOCK_STREAM (socketpair).
/// # C: O(iov + payload + nfds)
pub fn recvmsg_unix_stream(sock: &Arc<InetSocket>, msgp: u64, nonblock: bool) -> i64 {
    let (iov, iovlen, control, controllen) = unsafe {
        (
            core::ptr::read_volatile((msgp + 16) as *const u64),
            core::ptr::read_volatile((msgp + 24) as *const u64),
            core::ptr::read_volatile((msgp + 32) as *const u64),
            core::ptr::read_volatile((msgp + 40) as *const u64),
        )
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    let deadline_ns = net::sock::compute_deadline_ns(timeo);
    let want_cred = sock.opts.passcred.load(Ordering::Acquire) != 0;
    let mut total: i64 = 0;
    // SCM_RIGHTS fds delivered by `read_stream`, bound to the exact bytes
    // of the write that carried them. `read_stream` stops a read at the
    // next fd boundary, so a burst never rides bytes of an earlier
    // fd-less D-Bus message. Once any fds ride a read we return this
    // recvmsg (Linux returns at the ancillary-data boundary). read_stream
    // never re-queues or parks, so this yield loop always progresses.
    let mut pending_fds: Vec<Arc<File>> = Vec::new();
    let mut pending_cred: Option<(u32, u32, u32)> = None;
    // debug-wakelat: time the first park to the read that makes progress.
    #[cfg(feature = "debug-wakelat")]
    let mut wl_yield_start: u64 = 0;
    'iovloop: for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i validated; user-mapped iovec entry per Linux ABI.
        let (base, len) = unsafe {
            (
                core::ptr::read_volatile(iov_i as *const u64),
                core::ptr::read_volatile((iov_i + 8) as *const u64),
            )
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        loop {
            let (chunk, fds, cred) = {
                let g = sock.kind.lock();
                if let SockKind::Unix(pair, end) = &*g { pair.read_stream(*end, len as usize) }
                else { return -(Errno::Einval.as_i32() as i64); }
            };
            if !fds.is_empty() { pending_fds.extend(fds); }
            if cred.is_some() { pending_cred = cred; }
            if !chunk.is_empty() {
                unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), base as *mut u8, chunk.len()); }
                total += chunk.len() as i64;
                // Stop at the ancillary boundary: fds ride the chunk we
                // just delivered, so return rather than coalescing the
                // next (differently-tagged) message onto this recvmsg.
                if !pending_fds.is_empty() || (want_cred && pending_cred.is_some()) { break 'iovloop; }
                if (chunk.len() as u64) < len { break 'iovloop; }
                continue 'iovloop;
            }
            // Empty payload but fds present (fd-only message): deliver the
            // fds now — don't loop waiting for bytes that aren't coming.
            if !pending_fds.is_empty() || (want_cred && pending_cred.is_some()) { break 'iovloop; }
            if total > 0 { break 'iovloop; }
            let (pair, end) = {
                let g = sock.kind.lock();
                if let SockKind::Unix(pair, end) = &*g { (pair.clone(), *end) }
                else { return -(Errno::Einval.as_i32() as i64); }
            };
            if nonblock {
                if pair.take_reset(end) { return -(Errno::Econnreset.as_i32() as i64); }
                if pair.is_eof(end) { break 'iovloop; }
                return -(Errno::Eagain.as_i32() as i64);
            }
            if sched::live::deliverable_signals_self() != 0 {
                return -(Errno::Eintr.as_i32() as i64);
            }
            if deadline_ns != 0 && crate::poll::poll_common::monotonic_ns() >= deadline_ns {
                return -(Errno::Eagain.as_i32() as i64);
            }
            #[cfg(feature = "debug-wakelat")]
            if wl_yield_start == 0 {
                use hal::TimerOps;
                #[cfg(target_arch = "x86_64")] { wl_yield_start = hal_x86_64::X86TimerOps::monotonic_ns().0.max(1); }
                #[cfg(target_arch = "aarch64")] { wl_yield_start = hal_aarch64::ArmTimerOps::monotonic_ns().0.max(1); }
            }
            match pair.arm_stream_read(end, deadline_ns) {
                net::unix_sock::stream::ArmStreamRead::Retry => continue,
                net::unix_sock::stream::ArmStreamRead::Reset => {
                    let _ = pair.take_reset(end);
                    return -(Errno::Econnreset.as_i32() as i64);
                }
                net::unix_sock::stream::ArmStreamRead::Eof => break 'iovloop,
                // SAFETY: arm_stream_read registered current under the ring
                // lock; writers and close wake only after changing that ring.
                net::unix_sock::stream::ArmStreamRead::Parked => unsafe {
                    sched::live::schedule::schedule();
                    pair.reader_waiters(end).remove_current();
                },
            }
        }
    }
    // debug-wakelat: report a busy-yield recvmsg that finally got data.
    #[cfg(feature = "debug-wakelat")]
    if wl_yield_start != 0 {
        use hal::TimerOps;
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        let tid = sched::current().map(|c| c.tid).unwrap_or(0);
        sched::live::wakelat::note_blocked(
            tid, sched::live::wakelat::KIND_RECVMSG,
            now.saturating_sub(wl_yield_start), total as u64);
    }
    let mut ctrl_written: u64 = 0;
    let mut ctrunc = false;
    if !pending_fds.is_empty() {
        // [SCMR] AF_UNIX SOCK_STREAM SCM_RIGHTS receive probe: logs the
        // receiver vpid, delivered fd count, and control-buffer size for
        // every fd-carrying recvmsg. Pairs with [SCMW] to trace both hops
        // of the dbus-broker relay of logind's CreateSessionWithPIDFD /
        // reply. Kept permanently behind `debug-scmfd` (default-off).
        #[cfg(feature = "debug-scmfd")]
        {
            let vpid = sched::live::current().map(|c| c.visible_pid()).unwrap_or(0);
            klog::write_raw(b"[SCMR pid=");
            klog::write_dec_u64(vpid as u64);
            klog::write_raw(b" nfds=");
            klog::write_dec_u64(pending_fds.len() as u64);
            klog::write_raw(b" ctl=");
            klog::write_dec_u64(controllen);
            klog::write_raw(b"]\n");
        }
        if control == 0 || controllen < 16 || control >= USER_VA_END {
            ctrunc = true;
        } else {
            let cur = sched::live::current();
            let fdt = match cur.as_ref().and_then(|c| unsafe { c.fd_table_ref() }) {
                Some(t) => t.clone(),
                None => return total,
            };
            let nfds = pending_fds.len();
            let fit_n = {
                let max_data = controllen.saturating_sub(16) as usize / 4;
                if max_data < nfds { ctrunc = true; }
                core::cmp::min(nfds, max_data)
            };
            let nofile = cur.map(|c| c.nofile_soft()).unwrap_or(0);
            let mut allocated_fds: Vec<i32> = Vec::with_capacity(fit_n);
            for f in pending_fds.iter().take(fit_n) {
                match fdt.alloc_limit((*f).clone(), nofile) {
                    Ok(nfd) => allocated_fds.push(nfd),
                    Err(_) => { ctrunc = true; break; }
                }
            }
            let real_n = allocated_fds.len();
            let real_cmsg_total = 16 + (real_n * 4) as u64;
            if real_n > 0 && real_cmsg_total <= controllen {
                unsafe {
                    core::ptr::write_volatile(control as *mut u64, real_cmsg_total);
                    core::ptr::write_volatile((control + 8) as *mut i32, SOL_SOCKET);
                    core::ptr::write_volatile((control + 12) as *mut i32, SCM_RIGHTS);
                    for (i, nfd) in allocated_fds.iter().enumerate() {
                        core::ptr::write_volatile((control + 16 + (i * 4) as u64) as *mut i32, *nfd);
                    }
                }
                ctrl_written = real_cmsg_total;
            } else if !allocated_fds.is_empty() {
                for nfd in &allocated_fds { let _ = fdt.close(*nfd); }
                ctrunc = true;
            }
        }
    }
    if want_cred {
        let off = (ctrl_written + 7) & !7u64;
        let creds_total = 28u64;
        if control != 0 && control < USER_VA_END && off + creds_total <= controllen {
            let (pid, uid, gid) = pending_cred.unwrap_or_else(|| {
                let g = sock.kind.lock();
                match &*g { SockKind::Unix(pair, end) => pair.peer_cred(*end), _ => (0, 0, 0) }
            });
            const SCM_CREDENTIALS: i32 = 2;
            let base = control + off;
            unsafe {
                core::ptr::write_volatile(base as *mut u64, creds_total);
                core::ptr::write_volatile((base + 8) as *mut i32, SOL_SOCKET);
                core::ptr::write_volatile((base + 12) as *mut i32, SCM_CREDENTIALS);
                core::ptr::write_volatile((base + 16) as *mut u32, pid);
                core::ptr::write_volatile((base + 20) as *mut u32, uid);
                core::ptr::write_volatile((base + 24) as *mut u32, gid);
            }
            ctrl_written = off + creds_total;
        } else if controllen > 0 {
            ctrunc = true;
        }
    }
    unsafe {
        core::ptr::write_volatile((msgp + 40) as *mut u64, ctrl_written);
        let flags_at = (msgp + 48) as *mut i32;
        let cur = core::ptr::read_volatile(flags_at);
        core::ptr::write_volatile(flags_at, if ctrunc { cur | MSG_CTRUNC as i32 } else { cur });
    }
    total
}

/// recvmsg(2) for AF_UNIX SOCK_DGRAM / SOCK_SEQPACKET socketpair.
/// # C: O(iov + payload + nfds)
pub fn recvmsg_unix_msgpair(sock: &Arc<InetSocket>, fd: u64, msgp: u64, args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let (_name, iov, iovlen, control, controllen) = unsafe {
        (
            core::ptr::read_volatile(msgp as *const u64),
            core::ptr::read_volatile((msgp + 16) as *const u64),
            core::ptr::read_volatile((msgp + 24) as *const u64),
            core::ptr::read_volatile((msgp + 32) as *const u64),
            core::ptr::read_volatile((msgp + 40) as *const u64),
        )
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let nonblock = (args.a2 & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")] let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")] let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    let max_len = {
        let mut sum = 0u64;
        for i in 0..iovlen {
            let iov_i = iov + i * 16;
            if iov_i + 16 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
            let len = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
            sum = sum.saturating_add(len);
        }
        sum
    };
    // debug-wakelat: SOCK_DGRAM recvmsg busy-yield span (H2 busy-wait path).
    #[cfg(feature = "debug-wakelat")]
    let mut wl_yield_start: u64 = 0;
    let msg = loop {
        let got = {
            let g = sock.kind.lock();
            match &*g {
                SockKind::UnixMsgPair(p, e) => p.recv_msg(*e, max_len as usize),
                _ => return -(Errno::Einval.as_i32() as i64),
            }
        };
        if let Some(m) = got {
            #[cfg(feature = "debug-wakelat")]
            if wl_yield_start != 0 {
                let tid = sched::current().map(|c| c.tid).unwrap_or(0);
                sched::live::wakelat::note_blocked(
                    tid, sched::live::wakelat::KIND_RECVMSG,
                    now().saturating_sub(wl_yield_start), 1);
            }
            break m;
        }
        let reset = {
            let g = sock.kind.lock();
            matches!(&*g, SockKind::UnixMsgPair(p, e) if p.take_reset(*e))
        };
        if reset { return -(Errno::Econnreset.as_i32() as i64); }
        if nonblock { return -(Errno::Eagain.as_i32() as i64); }
        if sched::live::deliverable_signals_self() != 0 { return -(Errno::Eintr.as_i32() as i64); }
        if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
        #[cfg(feature = "debug-wakelat")]
        if wl_yield_start == 0 { wl_yield_start = now().max(1); }
        let (pair, end) = {
            let g = sock.kind.lock();
            match &*g {
                SockKind::UnixMsgPair(pair, end) => (pair.clone(), *end),
                _ => return -(Errno::Einval.as_i32() as i64),
            }
        };
        match pair.arm_read(end, deadline.unwrap_or(0)) {
            net::unix_sock::msg_pair::ArmMsgRead::Retry => continue,
            net::unix_sock::msg_pair::ArmMsgRead::Reset => {
                let _ = pair.take_reset(end);
                return -(Errno::Econnreset.as_i32() as i64);
            }
            net::unix_sock::msg_pair::ArmMsgRead::Eof => break net::unix_sock::UnixMsg {
                payload: alloc::vec::Vec::new(), fds: alloc::vec::Vec::new(), creds: (0, 0, 0),
            },
            net::unix_sock::msg_pair::ArmMsgRead::Parked => unsafe {
                sched::live::schedule::schedule();
                pair.reader_waiters(end).remove_current();
            },
        }
    };
    let mut total: usize = 0;
    for i in 0..iovlen {
        if total >= msg.payload.len() { break; }
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let (base, len) = unsafe {
            (
                core::ptr::read_volatile(iov_i as *const u64),
                core::ptr::read_volatile((iov_i + 8) as *const u64),
            )
        };
        if len == 0 { continue; }
        if base + len > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let take = core::cmp::min(len as usize, msg.payload.len() - total);
        unsafe { core::ptr::copy_nonoverlapping(msg.payload.as_ptr().add(total), base as *mut u8, take); }
        total += take;
    }
    let mut ctrl_written: u64 = 0;
    let mut ctrunc = false;
    if !msg.fds.is_empty() {
        if control == 0 || control >= USER_VA_END || controllen < 16 {
            ctrunc = true;
        } else {
            let cur = sched::live::current();
            let fdt = match cur.as_ref().and_then(|c| unsafe { c.fd_table_ref() }) {
                Some(t) => t.clone(),
                None => return total as i64,
            };
            let nfds = msg.fds.len();
            let max_data = controllen.saturating_sub(16) as usize / 4;
            if max_data < nfds { ctrunc = true; }
            let fit_n = core::cmp::min(nfds, max_data);
            let nofile = cur.map(|c| c.nofile_soft()).unwrap_or(0);
            let mut allocated_fds: Vec<i32> = Vec::with_capacity(fit_n);
            for f in msg.fds.iter().take(fit_n) {
                match fdt.alloc_limit((*f).clone(), nofile) {
                    Ok(nfd) => allocated_fds.push(nfd),
                    Err(_) => { ctrunc = true; break; }
                }
            }
            if !allocated_fds.is_empty() {
                let len = 16 + (allocated_fds.len() * 4) as u64;
                unsafe {
                    core::ptr::write_volatile(control as *mut u64, len);
                    core::ptr::write_volatile((control + 8) as *mut i32, SOL_SOCKET);
                    core::ptr::write_volatile((control + 12) as *mut i32, SCM_RIGHTS);
                    for (i, nfd) in allocated_fds.iter().enumerate() {
                        core::ptr::write_volatile((control + 16 + (i * 4) as u64) as *mut i32, *nfd);
                    }
                }
                ctrl_written = len;
            }
        }
    }
    if sock.opts.passcred.load(Ordering::Acquire) != 0 && control != 0 && control < USER_VA_END {
        let off = (ctrl_written + 7) & !7u64;
        let creds_total = 28u64;
        if off + creds_total <= controllen {
            // Per-MESSAGE sender creds (SO_PASSCRED): read from the dequeued
            // message, NOT the shared per-end cred slot. systemd-udevd's
            // worker_watch socketpair is shared by all udev workers writing one
            // end; a per-end last-sender-wins cred tagged each completion with
            // the wrong worker pid, so the manager idled the wrong worker and
            // wedged the udev event queue (card0 never tagged → no gdm greeter).
            let (pid, uid, gid) = msg.creds;
            const SCM_CREDENTIALS: i32 = 2;
            let base = control + off;
            unsafe {
                core::ptr::write_volatile(base as *mut u64, creds_total);
                core::ptr::write_volatile((base + 8) as *mut i32, SOL_SOCKET);
                core::ptr::write_volatile((base + 12) as *mut i32, SCM_CREDENTIALS);
                core::ptr::write_volatile((base + 16) as *mut u32, pid);
                core::ptr::write_volatile((base + 20) as *mut u32, uid);
                core::ptr::write_volatile((base + 24) as *mut u32, gid);
            }
            ctrl_written = off + creds_total;
        } else if controllen > 0 {
            ctrunc = true;
        }
    } else if sock.opts.passcred.load(Ordering::Acquire) != 0 && controllen > 0 {
        ctrunc = true;
    }
    unsafe {
        core::ptr::write_volatile((msgp + 40) as *mut u64, ctrl_written);
        let flags_at = (msgp + 48) as *mut i32;
        let cur = core::ptr::read_volatile(flags_at);
        core::ptr::write_volatile(flags_at, if ctrunc { cur | MSG_CTRUNC as i32 } else { cur });
    }
    total as i64
}
