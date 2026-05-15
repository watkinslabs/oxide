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
            let (got_read, got_write) = if file.inode().file_type() == vfs::FileType::CharDev {
                let ino = file.inode().ino();
                if (ino & 0xFFFF_0000) == 0x6000_0000 {
                    let is_master = (ino & 0x8000) == 0;
                    crate::dev::pty::pair_for((ino & 0x7FFF) as u32).map(|pair| {
                        let r = pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() });
                        (r, true)
                    }).unwrap_or((false, false))
                } else { (true, true) }
            } else { (true, true) };
            let mut hit = false;
            if want_read  && got_read  { set_bit(readfds_p, fd); hit = true; }
            if want_write && got_write { set_bit(writefds_p, fd); hit = true; }
            if hit { ready += 1; }
        }
        if ready > 0 { return ready; }
        // Check deadline / non-block.
        if let Some(dl) = deadline_ns {
            #[cfg(target_arch = "x86_64")]
            let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
            #[cfg(target_arch = "aarch64")]
            let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
            if now >= dl { return 0; }
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
/// # C: O(nfds)
pub fn sys_pselect6(args: &SyscallArgs) -> i64 {
    sys_select(args)
}
