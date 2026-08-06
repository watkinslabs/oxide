#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
#[cfg(feature = "debug-desktop")]
use core::sync::atomic::{AtomicU32, Ordering};

use super::ptrace::ptrace_syscall_stop_if_armed;

/// Value a tracer sees in the ABI return register at a PTRACE_SYSCALL
/// *entry* stop. Linux stores `-ENOSYS` there before running the handler so a
/// tracer can distinguish entry from exit (`syscall_trace_enter`).
const ENOSYS_AT_ENTRY_STOP: u64 = (-(syscall::errno::Errno::Enosys.as_i32() as i64)) as u64;
use super::route_a::dispatch_route_a;
use super::route_b::dispatch_route_b;
use super::route_c::dispatch_route_c;

/// Linux `SYSCALL_WORK_SYSCALL_TRACEPOINT` entry side. The disabled path stops
/// at the current task's syscall-work word and never enters the AtomicPtr hook
/// wrapper. # C: O(1)
#[inline]
fn fire_sys_enter_if_armed(task: Option<&sched::Task>, nr: u32) {
    if !sched::syscall_work::tracepoint_pending(task) { return; }
    syscall::tracepoint::fire_sys_enter(nr);
}

/// Linux `syscall_exit_work` tracepoint leg. Re-read the task word at exit: an
/// event may have been enabled or disabled while this syscall slept. # C: O(1)
#[inline]
fn fire_sys_exit_if_armed(task: Option<&sched::Task>, nr: u32, rv: i64) {
    if !sched::syscall_work::tracepoint_pending(task) { return; }
    syscall::tracepoint::fire_sys_exit(nr, rv);
}

/// Emit a focused syscall ledger for the compositor while diagnosing display
/// bring-up.  This is deliberately narrower than `debug-syscall`: the latter
/// makes a full desktop boot too slow to preserve the ordering at the KMS
/// boundary.  Keeping this feature-gated trace permanent lets future display
/// regressions distinguish an absent DRM request from a syscall that returned
/// an errno before it reached DRM.
#[cfg(feature = "debug-desktop")]
static MUTTER_POLL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(16);

/// Once Mutter owns its initial KMS buffers, retain a small syscall ledger for
/// the KMS handoff.  The pre-buffer startup is intentionally omitted: Mesa and
/// GLib issue enough setup calls there to obscure the first presentation
/// boundary.  `debug-desktop` only; normal syscall dispatch has no trace cost.
/// It ran on `debug-boot` until B1474, where its unconditional per-syscall
/// `with_exe_path` (a lock plus two substring scans, twice per syscall) plus the
/// serial volume made a `make qemu-*` guest run an order of magnitude slow.
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
/// Separate budget for render submission.  Synchronization can consume dozens
/// of calls before the compositor maps its first BO, so it must not starve the
/// mmap/epoll evidence above the KMS boundary.
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_RENDER_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
/// Keep the first failures after KMS-buffer allocation separate from the
/// ordinary handoff budget.  A compositor can legitimately issue a dense
/// futex/eventfd exchange before its first map, so failures must never be
/// hidden merely because that exchange consumed the presentation ledger.
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_ERR_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
/// `ppoll` owns GLib's main-context sleep. Keep a separate post-buffer budget
/// so startup probes cannot consume the frame-source deadline evidence.
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_PPOLL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
/// GLib's main wakeup descriptor must be drained after it becomes readable.
/// Keep a separate, narrow ledger for it: a generic post-KMS trace can be
/// consumed by the render worker before the main context reaches its first
/// frame source.
#[cfg(feature = "debug-desktop")]
static MUTTER_MAIN_FD3_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
/// Frame-clock timerfds are created by Clutter and must remain installed in
/// the main context.  Retaining their descriptor numbers lets a debug boot
/// prove whether a view is destroyed before GLib can arm it.
#[cfg(feature = "debug-desktop")]
static MUTTER_FRAME_TIMERFD_A: AtomicU32 = AtomicU32::new(u32::MAX);
#[cfg(feature = "debug-desktop")]
static MUTTER_FRAME_TIMERFD_B: AtomicU32 = AtomicU32::new(u32::MAX);
#[cfg(feature = "debug-desktop")]
static MUTTER_FRAME_TIMERFD_POLL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(16);
/// The thread which first allocates the KMS dumb buffer owns Mutter's GLib
/// main context.  Worker threads generate dense control-pipe traffic, so keep
/// their ppoll calls out of the frame-clock ledger.
#[cfg(feature = "debug-desktop")]
static MUTTER_KMS_MAIN_TID: AtomicU32 = AtomicU32::new(0);
/// Epoll's return count alone cannot identify a missing GLib source wakeup.
/// Retain the first returned event records independently, so a compositor
/// regression can distinguish an absent timerfd event from a mismatched data
/// payload without enabling a desktop-wide syscall trace.
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_EPOLL_EVENT_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);
#[cfg(feature = "debug-desktop")]
static MUTTER_POST_DUMB_TRACE_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "debug-desktop")]
const DRM_IOCTL_MODE_CREATE_DUMB: u64 = 0xc020_64b2;
#[cfg(feature = "debug-desktop")]
const PR_SET_VMA: u64 = 0x5356_4d41;

#[cfg(feature = "debug-desktop")]
#[cfg(feature = "debug-desktop")]
fn trace_mutter_syscall(phase: &'static [u8], nr: u64, a0: u64, a1: u64, a2: u64,
    a3: u64, a4: u64, a5: u64, rv: Option<i64>)
{
    // The KMS ABI itself crosses ioctl: CREATE_DUMB/MAP_DUMB/ADDFB/SETCRTC
    // all appear there.  mmap is much too hot during Mesa startup to include
    // in an always-available boot trace; DRM's own MAP_DUMB ioctl record
    // identifies the cookie before that mapping.  This keeps diagnostics from
    // changing a desktop service's startup timing.
    // timerfd_settime is included with ioctl so the compositor ledger can
    // distinguish an unarmed frame clock from a failed timerfd syscall.
    let is_mutter = sched::live::current()
        .map(|c| c.with_exe_path(|p| p.map(|s| {
            s.contains("gnome-shell") || s.contains("mutter")
        }).unwrap_or(false)))
        .unwrap_or(false);
    if !is_mutter { return; }
    if nr == syscall::nrs::NR_IOCTL && a1 == DRM_IOCTL_MODE_CREATE_DUMB
        && phase == b"exit" && rv == Some(0)
    {
        MUTTER_POST_DUMB_TRACE_ON.store(true, Ordering::Release);
        if let Some(cur) = sched::live::current() {
            let _ = MUTTER_KMS_MAIN_TID.compare_exchange(
                0, cur.tid, Ordering::AcqRel, Ordering::Acquire);
        }
    }
    if nr == syscall::nrs::NR_TIMERFD_CREATE && phase == b"exit" && rv.unwrap_or(-1) >= 0
        && a0 == 1
        && sched::live::current().is_some_and(|cur| {
            cur.with_exe_path(|path| path.is_some_and(|path| path.contains("gnome-shell")))
        })
    {
        let fd = rv.unwrap_or(-1) as u32;
        if MUTTER_FRAME_TIMERFD_A.compare_exchange(
            u32::MAX, fd, Ordering::AcqRel, Ordering::Acquire).is_err()
            && MUTTER_FRAME_TIMERFD_A.load(Ordering::Acquire) != fd
        {
            let _ = MUTTER_FRAME_TIMERFD_B.compare_exchange(
                u32::MAX, fd, Ordering::AcqRel, Ordering::Acquire);
        }
        klog::write_raw(b"[MUTTERFRAMEFD create tid=");
        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b" fd=");
        klog::write_dec_u64(fd as u64);
        klog::write_raw(b"]\n");
    }
    if nr == syscall::nrs::NR_CLOSE
        && (a0 as u32 == MUTTER_FRAME_TIMERFD_A.load(Ordering::Acquire)
            || a0 as u32 == MUTTER_FRAME_TIMERFD_B.load(Ordering::Acquire))
        && phase == b"exit"
    {
        klog::write_raw(b"[MUTTERFRAMEFD close tid=");
        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b" fd=");
        klog::write_dec_u64(a0);
        klog::write_raw(b" rv=");
        if rv.unwrap_or(0) < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.unwrap_or(0).wrapping_neg() as u64); }
        else { klog::write_dec_u64(rv.unwrap_or(0) as u64); }
        klog::write_raw(b"]\n");
    }
    if nr == syscall::nrs::NR_PPOLL
        && MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && sched::live::current().is_some_and(|cur|
            cur.tid == MUTTER_KMS_MAIN_TID.load(Ordering::Acquire))
        // The small startup polls are D-Bus and worker setup.  Mutter's
        // actual GLib main context carries the KMS and frame-clock sources in
        // its larger descriptor set; trace that set without consuming the
        // ledger before source attachment.
        && a1 >= 9
        && MUTTER_POST_DUMB_PPOLL_TRACE_REMAINING.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_ok()
    {
        klog::write_raw(b"[MUTTERPPOLL ");
        klog::write_raw(phase);
        klog::write_raw(b" tid=");
        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b" nfds=");
        klog::write_dec_u64(a1);
        if phase == b"enter" && a2 != 0 && crate::userbuf::validate_user_buf_readable(a2, 16, 1).is_ok() {
            // SAFETY: the debug trace just validated the complete user timespec.
            let (sec, nsec) = unsafe {
                (core::ptr::read_unaligned(a2 as *const i64),
                 core::ptr::read_unaligned((a2 + 8) as *const i64))
            };
            klog::write_raw(b" sec=");
            klog::write_dec_u64(sec as u64);
            klog::write_raw(b" nsec=");
            klog::write_dec_u64(nsec as u64);
        }
        if let Some(rv) = rv {
            klog::write_raw(b" rv=");
            if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
            else { klog::write_dec_u64(rv as u64); }
            if phase == b"exit" && rv > 0 {
                let n = core::cmp::min(a1, 16);
                let bytes = n.checked_mul(8).unwrap_or(0);
                if bytes != 0 && crate::userbuf::validate_user_buf_readable(a0, bytes, 1).is_ok() {
                    let mut index = 0u64;
                    while index < n {
                        let pfd = a0 + index * 8;
                        // SAFETY: the trace validated all returned pollfd records.
                        let (fd, events, revents) = unsafe {
                            (core::ptr::read_unaligned(pfd as *const i32),
                             core::ptr::read_unaligned((pfd + 4) as *const i16),
                             core::ptr::read_unaligned((pfd + 6) as *const i16))
                        };
                        klog::write_raw(b" fd="); klog::write_dec_u64(fd as u32 as u64);
                        klog::write_raw(b" ev="); klog::write_hex_u64(events as u16 as u64);
                        klog::write_raw(b" re="); klog::write_hex_u64(revents as u16 as u64);
                        if let Some(cur) = sched::live::current() {
                            // SAFETY: this running task is the fd-table's sole
                            // mutator; the trace only snapshots the returned fd.
                            if let Some(table) = unsafe { cur.fd_table_ref() }.cloned() {
                                if let Ok(file) = table.get(fd) {
                                    klog::write_raw(b" ino=");
                                    klog::write_hex_u64(file.inode().ino());
                                    klog::write_raw(b" poll=");
                                    klog::write_hex_u64(file.poll() as u64);
                                }
                            }
                        }
                        index += 1;
                    }
                }
            }
        }
        klog::write_raw(b"]\n");
        return;
    }
    if nr == syscall::nrs::NR_PPOLL && phase == b"enter"
        && MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && a0 != 0
    {
        let bytes = a1.checked_mul(8).unwrap_or(0);
        if bytes != 0 && crate::userbuf::validate_user_buf_readable(a0, bytes, 1).is_ok() {
            let frame_a = MUTTER_FRAME_TIMERFD_A.load(Ordering::Acquire) as i32;
            let frame_b = MUTTER_FRAME_TIMERFD_B.load(Ordering::Acquire) as i32;
            let mut i = 0u64;
            while i < a1 {
                let pfd = a0 + i * 8;
                // SAFETY: validated complete pollfd array above.
                let fd = unsafe { core::ptr::read_unaligned(pfd as *const i32) };
                if (fd == frame_a || fd == frame_b)
                    && MUTTER_FRAME_TIMERFD_POLL_TRACE_REMAINING.fetch_update(
                        Ordering::Relaxed, Ordering::Relaxed,
                        |remaining| remaining.checked_sub(1)).is_ok()
                {
                    klog::write_raw(b"[MUTTERFRAMEFD ppoll tid=");
                    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                    klog::write_raw(b" fd=");
                    klog::write_dec_u64(fd as u32 as u64);
                    klog::write_raw(b" nfds=");
                    klog::write_dec_u64(a1);
                    klog::write_raw(b"]\n");
                }
                i += 1;
            }
        }
    }
    if MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && nr == syscall::nrs::NR_READ
        && a0 == 3
        && sched::live::current().is_some_and(|cur|
            cur.tid == MUTTER_KMS_MAIN_TID.load(Ordering::Acquire))
        && MUTTER_MAIN_FD3_TRACE_REMAINING.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_ok()
    {
        klog::write_raw(b"[MUTTERFD3 ");
        klog::write_raw(phase);
        klog::write_raw(b" tid=");
        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b" count=");
        klog::write_dec_u64(a2);
        if phase == b"enter" {
            if let Some(cur) = sched::live::current() {
                // SAFETY: the running task is the only mutator of its table;
                // this trace clones the table before examining fd 3.
                if let Some(table) = unsafe { cur.fd_table_ref() }.cloned() {
                    if let Ok(file) = table.get(3) {
                        klog::write_raw(b" ino=");
                        klog::write_hex_u64(file.inode().ino());
                        klog::write_raw(b" poll=");
                        klog::write_hex_u64(file.poll() as u64);
                    }
                }
            }
        }
        if let Some(rv) = rv {
            klog::write_raw(b" rv=");
            if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
            else { klog::write_dec_u64(rv as u64); }
            if phase == b"exit" {
                if let Some(cur) = sched::live::current() {
                    // SAFETY: see the matching entry trace above; this only
                    // observes the post-read readiness of the same fd.
                    if let Some(table) = unsafe { cur.fd_table_ref() }.cloned() {
                        if let Ok(file) = table.get(3) {
                            klog::write_raw(b" poll=");
                            klog::write_hex_u64(file.poll() as u64);
                        }
                    }
                }
            }
        }
        klog::write_raw(b"]\n");
    }
    // This ledger deliberately precedes the general post-DUMB trace budgets:
    // a busy compositor can exhaust those budgets before an epoll return, but
    // the returned event payload is precisely the evidence needed to diagnose
    // a missed GLib frame-clock wakeup.
    if phase == b"exit" && nr == syscall::nrs::NR_EPOLL_WAIT && rv.unwrap_or(0) > 0
        && MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
    {
        let count = core::cmp::min(rv.unwrap_or(0) as u64, a2) as usize;
        let bytes = match (count as u64).checked_mul(12) {
            Some(bytes) => bytes,
            None => return,
        };
        if crate::userbuf::validate_user_buf_readable(a1, bytes, 1).is_ok() {
            let mut index = 0usize;
            while index < count {
                if MUTTER_POST_DUMB_EPOLL_EVENT_TRACE_REMAINING.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |remaining| remaining.checked_sub(1)).is_err()
                { break; }
                let event = a1 + (index as u64) * 12;
                // SAFETY: the kernel just copied this epoll_event to `event`; the
                // readable user range remains validated for this debug-only ledger.
                let (mask, data) = unsafe {
                    (core::ptr::read_unaligned(event as *const u32),
                     core::ptr::read_unaligned((event + 4) as *const u64))
                };
                klog::write_raw(b"[MUTTEREPOLL tid=");
                klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                klog::write_raw(b" epfd="); klog::write_dec_u64(a0);
                klog::write_raw(b" ev="); klog::write_hex_u64(mask as u64);
                klog::write_raw(b" data="); klog::write_hex_u64(data);
                klog::write_raw(b"]\n");
                index += 1;
            }
        }
    }
    let post_dumb = MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && matches!(nr, syscall::nrs::NR_READ | syscall::nrs::NR_WRITE
            | syscall::nrs::NR_FUTEX | syscall::nrs::NR_EPOLL_WAIT
            | syscall::nrs::NR_EVENTFD2);
    let render_post_dumb = MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && matches!(nr, syscall::nrs::NR_MMAP | syscall::nrs::NR_EPOLL_WAIT);
    let err_post_dumb = MUTTER_POST_DUMB_TRACE_ON.load(Ordering::Acquire)
        && rv.is_some_and(|v| v < 0);
    let anon_vma_name = nr == syscall::nrs::NR_PRCTL && a0 == PR_SET_VMA;
    if nr != syscall::nrs::NR_IOCTL && nr != syscall::nrs::NR_TIMERFD_SETTIME
        && nr != syscall::nrs::NR_PPOLL && !anon_vma_name && !post_dumb && !render_post_dumb
        && !err_post_dumb
    { return; }
    if nr == 271
        && MUTTER_POLL_TRACE_REMAINING.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_err()
    { return; }
    if post_dumb
        && MUTTER_POST_DUMB_TRACE_REMAINING.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_err()
    { return; }
    if render_post_dumb
        && MUTTER_POST_DUMB_RENDER_TRACE_REMAINING.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_err()
    { return; }
    if err_post_dumb
        && MUTTER_POST_DUMB_ERR_TRACE_REMAINING.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |remaining| remaining.checked_sub(1)).is_err()
    { return; }
    klog::write_raw(b"[MUTTERSYS ");
    klog::write_raw(phase);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" fd=");
    klog::write_dec_u64(a0);
    klog::write_raw(b" req=");
    klog::write_hex_u64(a1);
    klog::write_raw(b" arg=");
    klog::write_hex_u64(a2);
    if nr == syscall::nrs::NR_MMAP {
        klog::write_raw(b" fl=");
        klog::write_hex_u64(a3);
        klog::write_raw(b" mapfd=");
        klog::write_dec_u64(a4 as i32 as u32 as u64);
        klog::write_raw(b" off=");
        klog::write_hex_u64(a5);
    }
    if let Some(rv) = rv {
        klog::write_raw(b" rv=");
        if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
        else { klog::write_dec_u64(rv as u64); }
    }
    klog::write_raw(b"]\n");
}

/// The pre-call entry work — `syscall_trace_enter`'s ptrace stop, the
/// post-stop number re-read, and the seccomp filter — in a frame of its own.
///
/// Returns `(skip_value, abi_syscall_number)`: `Some(rv)` means do not run the
/// call and send `rv` down the normal exit path; the number is the one to
/// dispatch on, which a tracer may have rewritten.
/// # C: O(1) plus the filter's own cost
#[inline(never)]
fn syscall_entry_work(orig_nr: u64, args: &SyscallArgs) -> (Option<u64>, u64) {
    let aborted = ptrace_syscall_stop_if_armed(ENOSYS_AT_ENTRY_STOP, true);
    let abi_nr = super::ptrace::syscall_nr_after_entry_stop(orig_nr);
    let outcome = crate::dispatch_entry_order::entry_work(
        aborted, abi_nr, ENOSYS_AT_ENTRY_STOP,
        |n| super::seccomp::seccomp_gate(n,
            &[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5]));
    match outcome {
        crate::dispatch_entry_order::EntryOutcome::Skip(rv) => (Some(rv), abi_nr),
        crate::dispatch_entry_order::EntryOutcome::Run(nr)  => (None, nr),
    }
}

#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    // Linux `vtime_user_exit`: the architectural syscall entry has crossed
    // into kernel mode; close the user interval before any dispatch work.
    sched::cpustat::user_exit();
    // Architectural entry masks IRQs while it saves the user frame. Ordinary
    // syscall work is process context: timers, completion IRQs and wakeups
    // must run while it blocks. Dropping this guard restores the entry mask
    // before the return-to-user work loop starts its flag-check discipline.
    let process_irqs = super::process_irq::ProcessIrqs::enable();
    let dispatch_task = sched::current();
    let orig_nr = nr;
    #[cfg(target_arch = "aarch64")]
    let nr = syscall::arm_abi::aarch64_nr_to_x86(nr);
    debug_ssh! { crate::signal_trace::dispatch_entry(orig_nr, nr); }
    #[cfg(target_arch = "aarch64")]
    if let Some(c) = dispatch_task {
        c.svc_frame.store(hal_aarch64::current_svc_frame() as u64, core::sync::atomic::Ordering::Release);
    }
    // SAFETY: `syscall_a5` reads the sixth argument out of the per-CPU entry
    // save block, which the arch stub filled for THIS syscall before calling
    // here and which nothing else writes until the next entry.
    let a5 = unsafe { crate::syscall_a5::read() };
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5 };
    if let Some(c) = sched::current() {
        c.note_syscall(nr as u32);
        // Per-syscall checkpoint (state.md: stack-guard-wipe hunt) — `current_ref`
        // alone only checks at scheduler-internal touchpoints (~a dozen call
        // sites), giving a multi-second resolution window on when a hit
        // actually happened. Every syscall entry, for every task, gives
        // per-syscall resolution instead: a no-op when the guard is intact
        // (the common case), and on a hit, bisects the wipe to "between this
        // task's last two syscalls" rather than "somewhere in the last several
        // seconds of boot".
        c.debug_check_canary("syscall_entry");
    }
    #[cfg(feature = "debug-sshd")]
    trace_sshd_listener_enter(nr, &args);
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"enter", nr, None);
    fire_sys_enter_if_armed(dispatch_task, nr as u32);
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    debug_gnome_syscall! { sched::trace::entry(nr, a0, a1, a2, a3); }
    #[cfg(feature = "debug-desktop")]
    trace_mutter_syscall(b"enter", nr, a0, a1, a2, a3, a4, a5, None);
    // seccomp sees the syscall number AS THE CALLING ABI NUMBERS IT. This
    // dispatcher remaps aarch64's generic-ABI number onto the x86_64 numbering
    // it dispatches on (`aarch64_nr_to_x86` above), but that is an internal
    // detail: `seccomp_data.arch` reports AUDIT_ARCH_AARCH64, so
    // `seccomp_data.nr` must be the arm64 number the caller actually used.
    // Feeding the translated number instead makes every libseccomp filter
    // compiled for arm64 miss every `nr` comparison and fall through to its
    // default action — SCMP_ACT_KILL or a blanket errno — which kills or
    // corrupts any confined process on aarch64 while behaving on x86_64.
    // Syscall user dispatch runs FIRST — before ptrace and before seccomp.
    // A dispatched call's ABI is whatever foreign personality the userspace
    // handler emulates, so neither a tracer nor a cBPF filter compiled for
    // THIS ABI may be shown its arguments.
    if let Some(rv) = super::user_dispatch::user_dispatch_gate(orig_nr, a0) {
        drop(process_irqs);
        sched::cpustat::user_enter();
        return rv;
    }
    // The ptrace entry stop runs BEFORE seccomp, and the number is re-read
    // afterwards, so a tracer's rewrite is what the filter judges and what the
    // dispatcher runs. The reverse order let a tracer substitute a call the
    // filter had already approved under a different number.
    // Kept in its own non-inlined frame: its locals would otherwise sum into
    // this function's, which sits on the deepest aarch64 syscall chain the
    // stack gate measures. The entry work is a shallow sibling of the routes.
    let entry = syscall_entry_work(orig_nr, &args);
    #[cfg(target_arch = "aarch64")]
    let nr = if entry.1 == orig_nr { nr } else { syscall::arm_abi::aarch64_nr_to_x86(entry.1) };
    #[cfg(not(target_arch = "aarch64"))]
    let nr = entry.1;
    #[cfg(feature = "debug-syscost")]
    let __syscost = crate::syscost::start();
    #[cfg(feature = "debug-startlat")]
    let __startlat = crate::startlat::start();
    // A skipped call does NOT return early: it falls through to the exit tail
    // below, so its syscall-exit stop and — for a `SECCOMP_RET_TRAP` SIGSYS —
    // its signal delivery happen before the return to userspace instead of
    // waiting for the next timer tick.
    let rv = if let Some(rv) = entry.0 { rv as i64 }
    else if let Some(rv) = dispatch_route_a(nr, &args) { rv }
    else if let Some(rv) = dispatch_route_b(nr, &args) { rv }
    else if let Some(rv) = dispatch_route_c(nr, &args) { rv }
    else if let Some(rv) = sched::cred::cred_dispatch(nr, &args) { rv }
    else if let Some(rv) = sched::timers::timer_dispatch(nr, &args) { rv }
    else if let Some(rv) = crate::perms::perms_dispatch(nr, &args) { rv }
    else if let Some(rv) = ::fs::keyring::keyring_dispatch(nr, &args) { rv }
    else if let Some(rv) = sched::compat::try_compat(nr, &args) { rv }
    // No modern route claimed this nr: honest ENOSYS. There is NO legacy
    // fallback table (docs/53 hollow-shell) — an unimplemented syscall must
    // report ENOSYS, never silently hit a stub with wrong semantics.
    else { -(syscall::Errno::Enosys.as_i32() as i64) };
    // rv is left un-normalized here (may still carry an internal restart
    // sentinel like -ERESTARTSYS) — the ignored-restart check below and
    // dispatch_pending() need the raw sentinel. normalize_user_return()
    // runs once, at the final return, per docs/38 restart ABI.
    #[cfg(feature = "debug-syscall-return")]
    let return_task = sched::live::current();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DISPATCH);
    }
    #[cfg(feature = "debug-swap")]
    trace_swapon_process(b"exit", nr, Some(rv));
    debug_syscall! { sched::trace::ret(nr, rv); }
    debug_gnome_syscall! { sched::trace::ret(nr, rv); }
    #[cfg(feature = "debug-desktop")]
    trace_mutter_syscall(b"exit", nr, a0, a1, a2, a3, a4, a5, Some(rv));
    fire_sys_exit_if_armed(dispatch_task, nr as u32, rv);
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    debug_ssh! { crate::signal_trace::syscall_nr_rv(nr, rv); }
    #[cfg(feature = "debug-sshd-detail")]
    trace_sshd_syscall(nr, rv);
    #[cfg(feature = "debug-sshd")]
    trace_sshd_listener_exit(nr, rv);
    #[cfg(feature = "debug-random-seed")]
    trace_random_seed_syscall(nr, rv);
    #[cfg(feature = "debug-zram-lifecycle")]
    crate::signal_trace::zram_lifecycle_syscall(nr, rv);
    #[cfg(feature = "debug-syscost")]
    crate::syscost::record(nr, __syscost);
    #[cfg(feature = "debug-startlat")]
    crate::startlat::record(nr, __startlat, rv);
    #[cfg(feature = "debug-boot")]
    trace_einval(nr, a0, a1, a2, a3, a4, a5, rv);
    #[cfg(any(feature = "debug-taskdump", feature = "debug-polktrace"))]
    sched::diag::record_syscall(nr as u32, rv);
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_DIAG);
    }
    crate::proc::rseq_writeback();
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_RSEQ);
    }
    // A syscall rolled back by user dispatch never reached the kernel's ABI,
    // so its exit-side tracer work is skipped for the same reason the entry
    // side was.
    if !super::user_dispatch::rolled_back_this_syscall() {
        ptrace_syscall_stop_if_armed(rv as u64, false);
    }
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_AFTER_PTRACE);
    }
    // Return-to-user work begins with IRQs masked, enables them only around a
    // work pass, then masks again before re-reading the pending-work flags.
    drop(process_irqs);
    // Linux `syscall_exit_to_user_mode_prepare` -> `exit_to_user_mode_loop`:
    // reschedule, deliver signals and apply the restart decision, LOOPING while
    // work remains. The SAME loop runs on the IRQ and exception return paths
    // (`sched::exit_to_user::hook`), which is what makes a signal reach a task
    // that never enters the kernel (B1471 / `wait-diff-open-items.md` W9).
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task {
        sched::diag::syscall_return_stage(task, sched::diag::SYSCALL_RETURN_STAGE_IN_EXIT_TO_USER);
    }
    let regs = crate::arch_frame::current_user_regs();
    // SAFETY: syscall-return tail on the running task's own kernel stack; the
    // entry frame is live and exclusively owned until the epilogue consumes it.
    let rv_out = unsafe { crate::exit_to_user::exit_to_user_mode_loop(regs, Some(rv)) };
    #[cfg(feature = "debug-syscall-return")]
    if let Some(task) = return_task { sched::diag::syscall_return_clear(task); }
    // Diagnostic only: the ARM wait4(ECHILD) investigation needs to know
    // whether the kernel is about to ERET to a zero PC, or whether userspace
    // later branches through a zero link register.  The SVC frame is owned by
    // this task for the whole dispatch, including any schedule() above.
    #[cfg(all(target_arch = "aarch64", feature = "debug-smp"))]
    if nr == syscall::nrs::NR_WAIT4 {
        let frame = crate::arch_frame::current_svc_frame();
        if !frame.is_null() {
            // SAFETY: the task-owned frame is live until the assembly SVC
            // epilogue consumes it after this dispatcher returns.
            let frame = unsafe { &*frame };
            klog::write_raw(b"[WAIT4-RETURN tid=");
            klog::write_dec_u64(sched::live::current().map(|t| t.tid).unwrap_or(0) as u64);
            klog::write_raw(b" rv="); klog::write_hex_u64(rv as u64);
            klog::write_raw(b" elr="); klog::write_hex_u64(frame.elr_el1);
            klog::write_raw(b" lr="); klog::write_hex_u64(frame.x30);
            klog::write_raw(b" sp="); klog::write_hex_u64(frame.sp_el0);
            klog::write_raw(b"]\n");
        }
    }
    // Linux `vtime_user_enter`: all exit work is complete and the assembly
    // epilogue is about to resume userspace.
    sched::cpustat::user_enter();
    rv_out
}

/// Retained executable-scoped syscall trace for the OpenSSH daemon. The
/// startup path uses this instead of the global SSH trace so generator fanout
/// keeps production timing while a no-banner daemon remains diagnosable.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd-detail")]
fn trace_sshd_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    let is_sshd = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/sshd")));
    if !is_sshd { return; }
    klog::write_raw(b"[SSHD] tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle trace for the OpenSSH daemon.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
fn trace_sshd_listener_enter(nr: u64, args: &SyscallArgs) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] enter tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" a0=");
    klog::write_hex_u64(args.a0);
    klog::write_raw(b" a1=");
    klog::write_hex_u64(args.a1);
    klog::write_raw(b" a2=");
    klog::write_hex_u64(args.a2);
    klog::write_raw(b" a3=");
    klog::write_hex_u64(args.a3);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle return trace for OpenSSH.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
fn trace_sshd_listener_exit(nr: u64, rv: i64) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] exit tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-sshd")]
fn is_sshd_listener_syscall(nr: u64) -> bool {
    matches!(nr,
        syscall::nrs::NR_SOCKET |
        syscall::nrs::NR_BIND |
        syscall::nrs::NR_LISTEN |
        syscall::nrs::NR_ACCEPT4)
}

#[cfg(feature = "debug-sshd")]
fn sshd_tid() -> Option<u32> {
    let task = sched::current()?;
    task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/sshd"))).then_some(task.tid)
}

/// Retained, feature-gated syscall trace for systemd's random-seed helper.
/// It locates an early-boot entropy or persistence stall without changing the
/// production path or flooding the serial console with unrelated service I/O.
/// # C: O(executable-path length)
#[cfg(feature = "debug-random-seed")]
fn trace_random_seed_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    let is_random_seed = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/systemd-random-seed")));
    if !is_random_seed { return; }
    klog::write_raw(b"[RSEED] nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained, feature-gated syscall boundary trace for `/sbin/swapon` only.
/// It identifies an ABI failure before the final `swapon(2)` request without
/// perturbing any other userspace process.
/// # C: O(executable-path length)
#[cfg(feature = "debug-swap")]
fn trace_swapon_process(phase: &[u8], nr: u64, result: Option<i64>) {
    let Some(task) = sched::current() else { return; };
    let is_swapon = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/swapon")));
    if !is_swapon { return; }
    klog::write_raw(b"[SWAPON] ");
    klog::write_raw(phase);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    if let Some(result) = result {
        klog::write_raw(b" rv=");
        klog::write_hex_u64(result as u64);
    }
    klog::write_raw(b"\n");
}

/// Bounded ledger of every syscall that returns `EINVAL`, with the task that
/// received it. A userspace event loop whose dispatch callback fails with
/// "Invalid argument" gives no clue WHICH call failed — this names it instead
/// of guessing at the library's internals. Capped so a chatty-but-correct
/// EINVAL (e.g. `readlink` on a directory, which Linux also rejects) cannot
/// flood the console. # C: O(1) until the budget is spent, then a no-op
#[cfg(feature = "debug-boot")]
static EINVAL_LEDGER_REMAINING: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(4000);

#[cfg(feature = "debug-boot")]
fn trace_einval(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, rv: i64) {
    use core::sync::atomic::Ordering as O;
    if rv != -(syscall::errno::Errno::Einval.as_i32() as i64) { return; }
    // Drop the two EINVALs that are CORRECT and high-volume, or they spend the
    // budget during early boot and the interesting one — which arrives with the
    // desktop, ~35s in — never prints. Both are probes whose EINVAL IS the
    // answer, and Linux returns it too:
    //   readlink(2) on a directory (libdrm/udev walking /sys), and
    //   prctl(PR_CAPBSET_READ, cap) above CAP_LAST_CAP, which is how
    //   `cap_last_cap` is discovered.
    const PR_CAPBSET_READ: u64 = 23;
    if nr == syscall::nrs::NR_READLINK || nr == syscall::nrs::NR_READLINKAT { return; }
    if nr == syscall::nrs::NR_PRCTL && a0 == PR_CAPBSET_READ { return; }
    if EINVAL_LEDGER_REMAINING.fetch_update(O::Relaxed, O::Relaxed,
        |remaining| remaining.checked_sub(1)).is_err() { return; }
    let Some(cur) = sched::live::current() else { return };
    klog::write_raw(b"[EINVAL nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(cur.tid as u64);
    klog::write_raw(b" a0=");
    klog::write_hex_u64(a0);
    klog::write_raw(b" a1=");
    klog::write_hex_u64(a1);
    klog::write_raw(b" a2=");
    klog::write_hex_u64(a2);
    klog::write_raw(b" a3=");
    klog::write_hex_u64(a3);
    klog::write_raw(b" a4=");
    klog::write_hex_u64(a4);
    klog::write_raw(b" a5=");
    klog::write_hex_u64(a5);
    // `a0` is an fd for most of the syscalls that land here; rendering its path
    // is what turns "write(33) failed" into "write to /run/... failed". Silent
    // when a0 is not a live fd, which is the common case for non-fd syscalls.
    // SAFETY: syscall-exit on the running task; the fd table has no concurrent
    // writer here, the same contract every other dispatch-path reader uses.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        if let Ok(file) = fdt.get(a0 as i32) {
            klog::write_raw(b" fdpath=");
            let path = file.dentry().dentry_path(None);
            klog::write_raw(path.as_bytes());
        }
    }
    klog::write_raw(b" comm=");
    if let Some(name) = cur.try_comm_bytes() {
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        klog::write_raw(&name[..end]);
    }
    klog::write_raw(b"]\n");
}
