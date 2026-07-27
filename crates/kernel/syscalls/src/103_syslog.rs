// 103 syslog (Linux `klogctl`) — one syscall, one file (`53§0`). ABI shim
// only: capability fetch, user-buffer validation, copy, encode. Every action
// decision lives in `103_syslog/decide.rs` (hosted-tested); every piece of
// log state — ring, read cursor, clear point, console loglevel,
// `dmesg_restrict` — lives with the ring in `klog::syslog`, so there is one
// owner rather than a shadow copy here.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::s103_syslog_decide as decide;

// A blocked SYSLOG_ACTION_READ owns a task reference here while parked.
// Linux wakes `log_wait` from `wake_up_klogd`, which printk defers to an
// irq_work because `vprintk_emit` runs in NMI / lock-held contexts. Our
// `ring_push` has the same constraint, so instead of waking from the emit
// path the waiter re-parks on a short deadline and re-checks; the block is
// real (task Sleeping, signal-interruptible), only the wake is timer-driven.
static SYSLOG_READERS: sched::live::WaitList = sched::live::WaitList::new();

/// Re-check interval for a blocked `SYSLOG_ACTION_READ`.
const READ_POLL_NS: u64 = 20_000_000;

/// `sys_syslog(type, buf, len)` — slot 103. Linux `do_syslog(..., SYSLOG_FROM_READER)`.
/// # C: O(len) per action; READ blocks until the ring has unread bytes.
pub fn sys_syslog(args: &SyscallArgs) -> i64 {
    let action = args.a0 as u32;
    let buf    = args.a1;
    let len    = args.a2 as i32;

    // Linux checks permission for EVERY action before looking at any
    // argument, so an unprivileged caller cannot probe argument validity.
    let cap = sched::live::current()
        .map(|c| c.has_cap(sched::cap::SYSLOG))
        .unwrap_or(true);
    if let Err(e) = decide::check_permissions(action, cap, klog::syslog::dmesg_restrict()) {
        return -(e.as_i32() as i64);
    }
    if !decide::is_known_action(action) { return -(Errno::Einval.as_i32() as i64); }

    match action {
        // No per-caller open state: Linux's CLOSE/OPEN are also no-ops for
        // the syscall source (only `/proc/kmsg` open does real work).
        decide::ACTION_CLOSE | decide::ACTION_OPEN => 0,
        decide::ACTION_READ => read_blocking(buf, len),
        decide::ACTION_READ_ALL   => read_all(buf, len, false),
        decide::ACTION_READ_CLEAR => read_all(buf, len, true),
        decide::ACTION_CLEAR => { klog::syslog::clear(); 0 }
        decide::ACTION_CONSOLE_OFF => { klog::syslog::console_off(); 0 }
        decide::ACTION_CONSOLE_ON  => { klog::syslog::console_on(); 0 }
        decide::ACTION_CONSOLE_LEVEL => match decide::validate_console_level(len) {
            Ok(lvl) => { klog::syslog::set_console_level(lvl); 0 }
            Err(e)  => -(e.as_i32() as i64),
        },
        decide::ACTION_SIZE_UNREAD => klog::syslog::unread_bytes() as i64,
        decide::ACTION_SIZE_BUFFER => klog::ring_size() as i64,
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// Copy `n` bytes of `src` to the already-validated user buffer `dst`.
fn copy_out(dst: u64, src: &[u8]) {
    // SAFETY: `dst .. dst+src.len()` was accepted by validate_user_buf_writable before this call, so it is a mapped, writable user range in the caller's live address space; CPL=0 byte stores through it.
    unsafe {
        for (i, b) in src.iter().enumerate() {
            core::ptr::write_volatile((dst + i as u64) as *mut u8, *b);
        }
    }
}

/// `SYSLOG_ACTION_READ`: consume from the syslog cursor, blocking until the
/// ring has unread bytes (Linux `syslog_print` → `wait_event_interruptible`).
fn read_blocking(buf: u64, len: i32) -> i64 {
    let n = match decide::validate_read(buf, len) {
        Ok(decide::ReadArgs::Empty) => return 0,
        Ok(decide::ReadArgs::Len(n)) => n,
        Err(e) => return -(e.as_i32() as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, n as u64, 1) { return rv; }
    let mut tmp = alloc::vec![0u8; n];
    loop {
        let got = klog::syslog::read_into(&mut tmp[..]);
        if got != 0 { copy_out(buf, &tmp[..got]); return got as i64; }
        if sched::live::sigpend::deliverable_signals_self() != 0 {
            return -(Errno::Eintr.as_i32() as i64);
        }
        #[cfg(target_arch = "x86_64")]
        let now = { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 };
        #[cfg(target_arch = "aarch64")]
        let now = { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 };
        // SAFETY: process context in the syscall shim; publication as Sleeping is immediately followed by the recheck + park_yield below, so a record pushed in the window cannot be missed.
        unsafe { SYSLOG_READERS.park_with_deadline(now.saturating_add(READ_POLL_NS)); }
        if klog::syslog::unread_bytes() != 0
            || sched::live::sigpend::deliverable_signals_self() != 0
        {
            SYSLOG_READERS.cancel_current_park();
            continue;
        }
        // SAFETY: the task is Sleeping on the published wait list; the deadline scanner or signal delivery transitions it back to Runnable.
        unsafe { sched::live::park_yield(); }
    }
}

/// `SYSLOG_ACTION_READ_ALL` / `READ_CLEAR`: newest bytes that fit, never
/// behind the clear point, never moving the READ cursor. Non-blocking.
fn read_all(buf: u64, len: i32, clear_after: bool) -> i64 {
    let n = match decide::validate_read(buf, len) {
        Ok(decide::ReadArgs::Empty) => return 0,
        Ok(decide::ReadArgs::Len(n)) => n,
        Err(e) => return -(e.as_i32() as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, n as u64, 1) { return rv; }
    let mut tmp = alloc::vec![0u8; n];
    let got = klog::syslog::read_all_into(&mut tmp[..], clear_after);
    copy_out(buf, &tmp[..got]);
    got as i64
}
