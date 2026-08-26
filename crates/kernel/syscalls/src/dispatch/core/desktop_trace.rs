#[cfg(feature = "debug-desktop")]
use core::sync::atomic::{AtomicU32, Ordering};

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
pub(super) fn trace_mutter_syscall(phase: &'static [u8], nr: u64, a0: u64, a1: u64, a2: u64,
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
            // Debug trace only: a fault on the fetch just skips this field pair.
            if let (Ok(sec), Ok(nsec)) = (crate::user_mem::get_i64(a2), crate::user_mem::get_i64(a2 + 8)) {
                klog::write_raw(b" sec=");
                klog::write_dec_u64(sec as u64);
                klog::write_raw(b" nsec=");
                klog::write_dec_u64(nsec as u64);
            }
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
                        // Debug trace only: a fault on the fetch just skips this record.
                        let Ok(fd) = crate::user_mem::get_i32(pfd) else { index += 1; continue; };
                        let Ok(events) = crate::user_mem::get_i16(pfd + 4) else { index += 1; continue; };
                        let Ok(revents) = crate::user_mem::get_i16(pfd + 6) else { index += 1; continue; };
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
                // Debug trace only: a fault on the fetch just skips this record.
                let Ok(fd) = crate::user_mem::get_i32(pfd) else { i += 1; continue; };
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
                // Debug trace only: a fault on the fetch just skips this record.
                let (Ok(mask), Ok(data)) = (crate::user_mem::get_u32(event), crate::user_mem::get_u64(event + 4)) else {
                    index += 1; continue;
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

