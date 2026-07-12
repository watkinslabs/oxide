// 023 select — one syscall, one file (docs/53 §0). Moved verbatim from select.rs.
#![cfg(any(target_os = "oxide-kernel", test))]

extern crate alloc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::poll::poll_common::monotonic_ns;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

const FDSET_BITS_PER_WORD: u64 = 64;
const FDSET_WORD_BYTES: u64 = 8;

fn fdset_bytes(nfds: u64) -> u64 {
    ((nfds + FDSET_BITS_PER_WORD - 1) / FDSET_BITS_PER_WORD) * FDSET_WORD_BYTES
}

fn timeval_from_user(p: u64) -> Result<(i64, i64), i64> {
    validate_user_buf_readable(p, 16, 1)?;
    // SAFETY: p validated readable for the 16-byte timeval.
    let s = unsafe { core::ptr::read_unaligned(p as *const i64) };
    // SAFETY: p+8 lies inside the validated 16-byte timeval.
    let u = unsafe { core::ptr::read_unaligned((p + 8) as *const i64) };
    Ok((s, u))
}

fn copy_fdset_from_user(p: u64, len: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; len as usize];
    if p == 0 || len == 0 { return Ok(out); }
    validate_user_buf_readable(p, len, 1)?;
    // SAFETY: p validated readable for len bytes; out has len bytes.
    unsafe { core::ptr::copy_nonoverlapping(p as *const u8, out.as_mut_ptr(), len as usize); }
    Ok(out)
}

fn copy_fdset_to_user(p: u64, buf: &[u8]) -> Result<(), i64> {
    if p == 0 || buf.is_empty() { return Ok(()); }
    validate_user_buf_writable(p, buf.len() as u64, 1)?;
    // SAFETY: p validated writable for buf.len() bytes; source is a live slice.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), p as *mut u8, buf.len()); }
    Ok(())
}

fn bit_at(buf: &[u8], i: u64) -> bool {
    let byte_off = (i / 8) as usize;
    if byte_off >= buf.len() { return false; }
    (buf[byte_off] & (1u8 << (i & 7))) != 0
}

fn set_bit_buf(buf: &mut [u8], i: u64) {
    let byte_off = (i / 8) as usize;
    if byte_off < buf.len() { buf[byte_off] |= 1u8 << (i & 7); }
}

/// `sys_select(nfds, readfds, writefds, exceptfds, timeout)` — slot 23.
/// # C: O(nfds)
pub fn sys_select(args: &SyscallArgs) -> i64 {
    let timeout_p   = args.a4;
    // Decode timeout (struct timeval { tv_sec: i64, tv_usec: i64 }
    // = 16 B). NULL = block forever; {0,0} = non-block.
    let (deadline_ns, timeout_nonzero) = if timeout_p == 0 {
        (None, false)
    } else {
        let (s, u) = match timeval_from_user(timeout_p) { Ok(v) => v, Err(e) => return e };
        if s < 0 || u < 0 || u >= 1_000_000 { return -(Errno::Einval.as_i32() as i64); }
        let total_ns = (s as u64).saturating_mul(1_000_000_000).saturating_add((u as u64) * 1_000);
        (Some(monotonic_ns().saturating_add(total_ns)), total_ns != 0)
    };
    let rv = sys_select_with_deadline(args, deadline_ns);
    if timeout_p != 0 && timeout_nonzero {
        let rem_ns = deadline_ns.map(|d| d.saturating_sub(monotonic_ns())).unwrap_or(0);
        if validate_user_buf_writable(timeout_p, 16, 1).is_ok() {
            let sec = (rem_ns / 1_000_000_000) as i64;
            let usec = ((rem_ns % 1_000_000_000) / 1_000) as i64;
            // SAFETY: timeout_p validated writable for the 16-byte timeval.
            unsafe {
                core::ptr::write_unaligned(timeout_p as *mut i64, sec);
                core::ptr::write_unaligned((timeout_p + 8) as *mut i64, usec);
            }
        }
    }
    rv
}

/// Shared select engine for select/pselect after timeout conversion.
/// # C: O(nfds)
pub(crate) fn sys_select_with_deadline(args: &SyscallArgs, deadline_ns: Option<u64>) -> i64 {
    let n_arg       = args.a0 as i32;
    let readfds_p   = args.a1;
    let writefds_p  = args.a2;
    let exceptfds_p = args.a3;
    if n_arg < 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let nfds = core::cmp::min(n_arg as u64, vfs::FD_TABLE_MAX as u64);
    let fdset_len = fdset_bytes(nfds);
    let in_set  = match copy_fdset_from_user(readfds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    let out_set = match copy_fdset_from_user(writefds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    let ex_set  = match copy_fdset_from_user(exceptfds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut max_fd = 0u64;
    for fd in 0..nfds {
        if bit_at(&in_set, fd) || bit_at(&out_set, fd) || bit_at(&ex_set, fd) {
            if fdt.get(fd as i32).is_err() { return -(Errno::Ebadf.as_i32() as i64); }
            max_fd = fd + 1;
        }
    }
    // Snapshot the requested (fd, want_read, want_write, want_except) tuples from
    // the input fd_sets — we'll clobber the user buffers below and
    // need the original requests to recheck on each loop iteration.
    let mut wanted: alloc::vec::Vec<(u64, bool, bool, bool)> =
        alloc::vec::Vec::with_capacity(max_fd as usize);
    for fd in 0..max_fd {
        let wr = bit_at(&in_set, fd);
        let ww = bit_at(&out_set, fd);
        let we = bit_at(&ex_set, fd);
        if wr || ww || we { wanted.push((fd, wr, ww, we)); }
    }
    // Linux `->poll`: register this call's waiter on each selected fd's OWN
    // wait queue (PollSubscribers). The fd's readiness transition `notify()`s
    // only its subscribers — no global broadcast.
    let waiter = crate::poll::poll_common::PollWaiter::new();
    let mut subbed: alloc::vec::Vec<vfs::InodeRef> = alloc::vec::Vec::new();
    for &(fd, _, _, _) in &wanted {
        if let Ok(file) = fdt.get(fd as i32) {
            if let Some(s) = file.inode().poll_subscribers() {
                waiter.subscribe(s);
                subbed.push(file.inode().clone());
            }
        }
    }
    let rv: i64 = loop {
        let mut res_in  = alloc::vec![0u8; fdset_len as usize];
        let mut res_out = alloc::vec![0u8; fdset_len as usize];
        let mut res_ex  = alloc::vec![0u8; fdset_len as usize];
        let mut ready: i64 = 0;
        for &(fd, want_read, want_write, want_except) in &wanted {
            let file = match fdt.get(fd as i32) { Ok(f) => f, Err(_) => continue };
            // F202: consult inode.poll() — was special-casing pty and
            // returning (true,true) for everything else, so dropbear's
            // pipe-driven exec channel never woke on actual readiness.
            let mask = file.poll();
            let got_read  = (mask & vfs::POLL_IN)  != 0
                         || (mask & vfs::POLL_HUP) != 0
                         || (mask & vfs::POLL_ERR) != 0;
            let got_write = (mask & vfs::POLL_OUT) != 0
                         || (mask & vfs::POLL_ERR) != 0;
            let got_except = (mask & vfs::POLL_PRI) != 0;
            if want_read  && got_read   { set_bit_buf(&mut res_in, fd);  ready += 1; }
            if want_write && got_write  { set_bit_buf(&mut res_out, fd); ready += 1; }
            if want_except && got_except { set_bit_buf(&mut res_ex, fd); ready += 1; }
        }
        if ready > 0 {
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: select ready=");
                klog::write_dec_u64(ready as u64);
                klog::write_raw(b"\n");
            }
            if let Err(e) = copy_fdset_to_user(readfds_p, &res_in) { break e; }
            if let Err(e) = copy_fdset_to_user(writefds_p, &res_out) { break e; }
            if let Err(e) = copy_fdset_to_user(exceptfds_p, &res_ex) { break e; }
            break ready;
        }
        // F205: signal-pending check. Without this the loop sits in
        // tick_yield forever when the only thing about to break the
        // wait is a pending deliverable signal (e.g. SIGCHLD waking
        // dropbear's pselect-style relay so it can wait4 the shell
        // child and let the pipe close-hook fire). Returning -EINTR
        // hands control back to the dispatch tail where signal
        // delivery actually runs.
        use core::sync::atomic::Ordering;
        let pending = cur.sigpending.load(Ordering::Acquire);
        let mask    = cur.sigmask.load(Ordering::Acquire);
        if pending & !mask != 0 {
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: select EINTR pending=");
                klog::write_hex_u64(pending);
                klog::write_raw(b" mask=");
                klog::write_hex_u64(mask);
                klog::write_raw(b"\n");
            }
            break -(Errno::Eintr.as_i32() as i64);
        }
        // Deadline / non-block check + Linux-way block.
        let now = monotonic_ns();
        if let Some(dl) = deadline_ns {
            if now >= dl {
                debug_ssh! { klog::write_raw(b"[INFO]  ssh-trace: select timeout\n"); }
                if let Err(e) = copy_fdset_to_user(readfds_p, &res_in) { break e; }
                if let Err(e) = copy_fdset_to_user(writefds_p, &res_out) { break e; }
                if let Err(e) = copy_fdset_to_user(exceptfds_p, &res_ex) { break e; }
                break 0;
            }
        }
        // Park until a subscribed fd's `notify()` wakes us, or the caller's
        // timeout. Bounded safety-net rescan only covers polled fds with no
        // event source (timerfd) + the scan→park window (same as epoll_wait).
        const RESCAN_NS: u64 = 20_000_000;
        let rescan_at = now.saturating_add(RESCAN_NS);
        let park_dl = match deadline_ns {
            Some(d) => core::cmp::min(d, rescan_at),
            None    => rescan_at,
        };
        // SAFETY: process ctx; preempt-off across the syscall; park+yield per `13§8`.
        unsafe { waiter.park_until(park_dl); }
    };
    // Drop our registration from every fd we subscribed to.
    for ino in &subbed {
        if let Some(s) = ino.poll_subscribers() { waiter.unsubscribe(s); }
    }
    rv
}
