// select / pselect6 extracted from syscall_glue_fs.rs to keep
// that file under the 1000-line cap (`08§7`). Both walk the fd_set
// bitmap and reuse the readability state the existing poll path
// consults; pselect6 simply forwards to select for v1 (sigmask +
// timespec extras are ignored on the non-blocking check).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_select(nfds, readfds, writefds, exceptfds, timeout)` — slot 23.
/// # C: O(nfds)
pub fn sys_select(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    const NFDS_MAX: u64 = 4096;
    let nfds        = args.a0;
    let readfds_p   = args.a1;
    let writefds_p  = args.a2;
    let exceptfds_p = args.a3;
    let timeout_p   = args.a4;
    if nfds > NFDS_MAX { return -(Errno::Einval.as_i32() as i64); }
    // Decode timeout (struct timeval { tv_sec: i64, tv_usec: i64 }
    // = 16 B). NULL = block forever; {0,0} = non-block.
    let deadline_ns: Option<u64> = if timeout_p == 0 || timeout_p >= USER_VA_END {
        None
    } else {
        // SAFETY: timeout_p validated < USER_VA_END; 16 B aligned struct timeval read.
        let (s, u) = unsafe {
            (
                core::ptr::read_volatile(timeout_p as *const i64),
                core::ptr::read_volatile((timeout_p + 8) as *const i64),
            )
        };
        if s < 0 || u < 0 { return -(Errno::Einval.as_i32() as i64); }
        let total_ns = (s as u64).saturating_mul(1_000_000_000).saturating_add((u as u64) * 1_000);
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        Some(now.saturating_add(total_ns))
    };
    let bit_at = |p: u64, i: u64| -> bool {
        if p == 0 || p >= USER_VA_END { return false; }
        let byte_off = (i / 8) as u64;
        if byte_off >= 128 { return false; }
        // SAFETY: byte within the 128-byte fd_set; CPL=0 reads through caller's AS.
        let b = unsafe { core::ptr::read_volatile((p + byte_off) as *const u8) };
        (b & (1u8 << (i & 7))) != 0
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Snapshot the requested (fd, want_read, want_write) pairs from
    // the input fd_sets — we'll clobber the user buffers below and
    // need the original requests to recheck on each loop iteration.
    let mut wanted: alloc::vec::Vec<(u64, bool, bool)> =
        alloc::vec::Vec::with_capacity(nfds as usize);
    for fd in 0..nfds {
        let wr = bit_at(readfds_p, fd);
        let ww = bit_at(writefds_p, fd);
        let we = bit_at(exceptfds_p, fd);
        if wr || ww || we { wanted.push((fd, wr, ww)); }
        let _ = we;
    }
    loop {
        // Zero user fd_sets so we can write ready bits in.
        for &p in &[readfds_p, writefds_p, exceptfds_p] {
            if p != 0 && p < USER_VA_END {
                // SAFETY: 128-byte fd_set fits in user range; CPL=0 writes through caller's AS.
                unsafe {
                    for i in 0..128usize {
                        core::ptr::write_volatile((p + i as u64) as *mut u8, 0);
                    }
                }
            }
        }
        let mut ready: i64 = 0;
        for &(fd, want_read, want_write) in &wanted {
            let file = match fdt.get(fd as i32) { Ok(f) => f, Err(_) => continue };
            // F202: consult inode.poll() — was special-casing pty and
            // returning (true,true) for everything else, so dropbear's
            // pipe-driven exec channel never woke on actual readiness.
            let mask = file.inode().poll();
            let got_read  = (mask & vfs::POLL_IN)  != 0
                         || (mask & vfs::POLL_HUP) != 0;
            let got_write = (mask & vfs::POLL_OUT) != 0;
            let mut hit = false;
            if want_read  && got_read  { set_bit(readfds_p, fd); hit = true; }
            if want_write && got_write { set_bit(writefds_p, fd); hit = true; }
            if hit { ready += 1; }
        }
        if ready > 0 {
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: select ready=");
                klog::write_dec_u64(ready as u64);
                klog::write_raw(b"\n");
            }
            return ready;
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
            return -(Errno::Eintr.as_i32() as i64);
        }
        // Check deadline / non-block.
        if let Some(dl) = deadline_ns {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl {
                debug_ssh! { klog::write_raw(b"[INFO]  ssh-trace: select timeout\n"); }
                return 0;
            }
        }
        // SAFETY: process ctx; runqueue installed; tick_yield reschedules and returns.
        unsafe { sched::live::tick_yield(); }
    }
}

#[inline]
fn set_bit(p: u64, i: u64) {
    if p == 0 || p >= USER_VA_END { return; }
    let byte_off = (i / 8) as u64;
    if byte_off >= 128 { return; }
    // SAFETY: byte within the 128-byte fd_set; CPL=0 read+write through caller's AS.
    unsafe {
        let b = core::ptr::read_volatile((p + byte_off) as *const u8);
        core::ptr::write_volatile((p + byte_off) as *mut u8, b | (1u8 << (i & 7)));
    }
}

/// `sys_pselect6(nfds, r, w, e, timeout, sigmask_pair)` — slot 270.
///
/// Two ABI differences vs slot 23 `sys_select`:
///   1. `timeout` is `timespec { sec, nsec }` (nsec resolution) instead
///      of `timeval { sec, usec }`. Both are 16 bytes, same layout.
///      Convert nsec → usec when staging the inner timeval on the
///      kernel stack so sys_select's existing decoder still works.
///   2. `args.a5` carries a pointer to a 16-byte pair
///      `{ sigmask_ptr: u64, sigmask_size: u64 }` Linux uses to
///      atomically swap the task's sigmask for the duration of the
///      call (`pselect6` is `select` + an atomic sigprocmask).
///      Without honoring it, dropbear's `pselect`-style relay
///      (block SIGCHLD via sigprocmask; pselect with an oldset that
///      unblocks SIGCHLD; restore on return) blocks SIGCHLD across
///      the entire select. The shell child's SIGCHLD posts to
///      sigpending but never delivers → no wait4 → FdTable leaks →
///      pipe POLL_HUP never propagates → no CHANNEL_EOF. F205.
/// # C: O(nfds)
pub fn sys_pselect6(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    debug_ssh! {
        klog::write_raw(b"[INFO]  ssh-trace: pselect6 nfds=");
        klog::write_dec_u64(args.a0);
        klog::write_raw(b" timeout=");
        klog::write_hex_u64(args.a4);
        klog::write_raw(b" sigmask_pair=");
        klog::write_hex_u64(args.a5);
        klog::write_raw(b"\n");
    }
    // 1) Convert timespec → timeval on the kernel stack.
    let inner_timeout: u64;
    let mut tv_buf: [u64; 2] = [0; 2];
    if args.a4 == 0 || args.a4 >= USER_VA_END {
        inner_timeout = 0;
    } else {
        // SAFETY: args.a4 validated < USER_VA_END; user pages mapped via active TTBR0/CR3; CPL=0 reads.
        let (s, ns) = unsafe {
            (
                core::ptr::read_volatile( args.a4        as *const i64),
                core::ptr::read_volatile((args.a4 + 8)   as *const i64),
            )
        };
        // sys_select expects timeval {sec, usec} → convert.
        tv_buf[0] = s as u64;
        tv_buf[1] = (ns / 1000) as u64;
        inner_timeout = tv_buf.as_ptr() as u64;
    }
    // 2) Atomically install the caller's sigmask. The pair at a5 is
    //    `{ const sigset_t *ss; size_t ss_len; }`. Linux ignores
    //    ss_len for compatibility once it's read; we do the same.
    let cur = sched::live::current();
    let saved_mask = if args.a5 != 0 && args.a5 < USER_VA_END {
        // SAFETY: a5 validated < USER_VA_END; 16-byte pair (ptr+len); 8-aligned per ABI.
        let ss_ptr = unsafe { core::ptr::read_volatile(args.a5 as *const u64) };
        debug_ssh! {
            klog::write_raw(b"[INFO]  ssh-trace: pselect6 a5_pair=");
            klog::write_hex_u64(args.a5);
            klog::write_raw(b" inner_ptr=");
            klog::write_hex_u64(ss_ptr);
            klog::write_raw(b"\n");
        }
        if ss_ptr != 0 && ss_ptr < USER_VA_END {
            // SAFETY: ss_ptr validated < USER_VA_END; 8-byte sigset_t per Linux ABI.
            let new_mask = unsafe { core::ptr::read_volatile(ss_ptr as *const u64) };
            // SIGKILL (9) and SIGSTOP (19) are non-blockable per signal(7).
            let new_mask = new_mask & !(1u64 << 8) & !(1u64 << 18);
            let r = cur.as_ref().map(|c| c.sigmask.swap(new_mask, Ordering::AcqRel));
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: pselect6 swap_mask new=");
                klog::write_hex_u64(new_mask);
                klog::write_raw(b" old=");
                klog::write_hex_u64(r.unwrap_or(0));
                klog::write_raw(b"\n");
            }
            r
        } else {
            None
        }
    } else {
        None
    };
    // 3) Forward to sys_select with the converted timeout.
    let inner = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2, a3: args.a3,
        a4: inner_timeout, a5: 0,
    };
    let rv = sys_select(&inner);
    // 4) Restore the saved sigmask if we swapped. Linux pselect6
    //    semantics: if a deliverable signal is pending at return,
    //    LEAVE the new mask installed so the syscall-tail signal
    //    delivery in `oxide_syscall_dispatch` actually delivers it
    //    (the signal handler's rt_sigreturn then restores the mask
    //    saved on the user signal frame, which equals the new mask;
    //    user-space follow-up sigprocmask resets to background).
    //    No deliverable signal pending → restore old mask immediately
    //    so post-pselect user code sees its original mask. Mirrors
    //    Linux's restore_user_sigmask / TIF_RESTORE_SIGMASK path.
    if let Some(old) = saved_mask {
        if let Some(c) = cur.as_ref() {
            let pending = c.sigpending.load(Ordering::Acquire);
            let cur_mask = c.sigmask.load(Ordering::Acquire);
            if pending & !cur_mask == 0 {
                c.sigmask.store(old, Ordering::Release);
            }
        }
    }
    rv
}
