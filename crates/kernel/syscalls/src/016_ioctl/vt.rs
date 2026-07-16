#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use super::font::handle_font_ioctl;
use super::tioclinux::handle_tioclinux;

/// VT_WAITACTIVE sleep queue: a task blocks here until a VT switch completes
/// (Linux `vt_event` / `vt_waitactive`). Woken by `vt_switch_wake`, which the
/// vt crate's switch-completion hook drives from `do_switch`.
static VT_SWITCH_WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// Wake every task blocked in VT_WAITACTIVE. Registered (via
/// `vt::set_switch_hook`) as the vt switch-completion hook in kmain, so each
/// completed `do_switch` rouses the blocked waiters to re-check the active VT.
/// # C: O(N_waiters)
pub fn vt_switch_wake() { VT_SWITCH_WAIT.wake_all(); }

/// KD_*/VT_* ioctls on /dev/tty<N> via the vt crate. Returns
/// debug-boot: true when the current task is part of the display stack whose VT
/// handshake gates the greeter (gdm / logind / mutter / gnome-shell). # C: O(len)
#[cfg(feature = "debug-displaystack")]
fn vt_is_ui_caller() -> bool {
    sched::live::current()
        .and_then(|c| unsafe {
            (*c.exe_path.get()).as_ref().map(|s| {
                s.contains("gdm") || s.contains("logind") || s.contains("mutter")
                    || s.contains("gnome-shell") || s.contains("systemd")
            })
        })
        .unwrap_or(false)
}

/// `Some(rv)` when the ioctl is recognised; `None` to fall back to
/// the existing tty-line-discipline path.
/// # C: O(1)
pub(super) fn handle_vt_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    if inode.file_type() != vfs::FileType::CharDev { return None; }
    // /dev/console + /dev/tty0 (ConsoleInode vt=0) carry the FG-alias low
    // byte (FG_VT_INO_LB) and act on the ACTIVE VT — Linux: a VT/KD ioctl on
    // the controlling console operates on `fg_console`. /dev/tty<N> carries
    // its own low byte N and acts on VT N specifically. (The old test
    // `ino_low == 1` was a dead branch: the alias low byte is 0xFD, never 1,
    // so VT/KD ioctls on /dev/console never resolved — and /dev/tty1 wrongly
    // targeted the active VT instead of VT 1.)
    let ino_low = (inode.ino() & 0xFF) as u8;
    let vt_target = if ino_low == console::FG_VT_INO_LB { vt::active() } else { ino_low };
    // debug-boot: trace VT ioctls by the display stack (gdm/logind/mutter). A
    // gdm-wayland greeter session gets a seat from logind ONLY if it holds a
    // valid VT: gdm allocates one via VT_OPENQRY + opens /dev/ttyN + VT_ACTIVATE.
    // If any of these fails, the session has vtnr=0, logind assigns no seat, and
    // mutter's TakeDevice(card0) returns ENODEV ("No GPUs found"). Log the op +
    // target + caller so the VT-allocation handshake can be followed offline.
    #[cfg(feature = "debug-displaystack")]
    if vt_is_ui_caller() {
        klog::write_raw(b"[VTIO req="); klog::write_hex_u64(req);
        klog::write_raw(b" tgt="); klog::write_dec_u64(vt_target as u64);
        klog::write_raw(b" active="); klog::write_dec_u64(vt::active() as u64);
        klog::write_raw(b" by=");
        if let Some(c) = sched::live::current() { klog::write_raw(c.name.as_bytes()); }
        klog::write_raw(b"]\n");
    }
    if !(1..=63).contains(&vt_target) { return None; }
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    match req {
        vt::KDGETMODE => {
            let v = vt::slot(vt_target).map(|s| s.kd_mode).unwrap_or(vt::KD_TEXT);
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store of mode value into caller's AS.
                unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
            }
            Some(0)
        }
        vt::KDSETMODE => {
            let mode = arg as u32;
            match vt::set_kd_mode(vt_target, mode) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGKBMODE => {
            let v = vt::slot(vt_target).map(|s| s.kb_mode).unwrap_or(vt::K_XLATE);
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store.
                unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
            }
            Some(0)
        }
        vt::KDSKBMODE => {
            let mode = arg as u32;
            match vt::set_kb_mode(vt_target, mode) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGKBTYPE => {
            // KB_101 = 2; arg is u8 user pointer.
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; single-byte store.
                unsafe { core::ptr::write_volatile(arg as *mut u8, 2u8); }
            }
            Some(0)
        }
        vt::KDSIGACCEPT => {
            // systemd (manager.c) asks the kernel to deliver a signal on the
            // VT secure-attention keypress. We have no kbd-signal path; accept
            // as a no-op so PID1 doesn't warn "Failed to enable kbrequest".
            Some(0)
        }
        vt::VT_OPENQRY => {
            let id = match vt::openqry() { Ok(n) => n as u32, Err(_) => return Some(errno(Errno::Ebusy)) };
            #[cfg(feature = "debug-displaystack")]
            if vt_is_ui_caller() {
                klog::write_raw(b"[VTIO OPENQRY->"); klog::write_dec_u64(id as u64); klog::write_raw(b"]\n");
            }
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store.
                unsafe { core::ptr::write_volatile(arg as *mut u32, id); }
            }
            Some(0)
        }
        vt::VT_GETSTATE => {
            let st = vt::get_state();
            #[cfg(feature = "debug-displaystack")]
            if vt_is_ui_caller() {
                klog::write_raw(b"[VTIO GETSTATE active="); klog::write_dec_u64(st.v_active as u64); klog::write_raw(b"]\n");
            }
            if arg == 0 || arg + 6 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 6; struct vt_stat is 6 bytes.
            unsafe {
                core::ptr::write_volatile(arg as *mut u16, st.v_active);
                core::ptr::write_volatile((arg + 2) as *mut u16, st.v_signal);
                core::ptr::write_volatile((arg + 4) as *mut u16, st.v_state);
            }
            Some(0)
        }
        vt::VT_ACTIVATE => {
            let n = arg as u8;
            match vt::activate(n) {
                Ok(()) => Some(0),
                Err(vt::Error::Busy) => Some(errno(Errno::Ebusy)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_WAITACTIVE => {
            // Block until the active VT == n (Linux `vt_waitactive`): the
            // requested switch may be DEFERRED behind a VT_PROCESS owner's
            // VT_RELDISP, so this must sleep rather than EINVAL on a not-yet-
            // current target. Signal-interruptible (EINTR): the owner that
            // must field relsig + call VT_RELDISP is frequently the SAME task
            // blocked here, so the wait MUST yield to signal delivery or the
            // switch deadlocks.
            let n = arg as u8;
            if !(1..=63).contains(&n) { return Some(errno(Errno::Einval)); }
            use core::sync::atomic::Ordering;
            loop {
                if vt::active() == n { return Some(0); }
                let cur = match sched::live::current() {
                    Some(c) => c, None => return Some(errno(Errno::Einval)),
                };
                // Any unblocked pending signal interrupts the wait (mirrors the
                // poll/pselect6 EINTR check) so the dispatch tail can deliver it
                // — including the relsig the owner must answer with VT_RELDISP.
                let pending = cur.sigpending.load(Ordering::Acquire);
                let mask    = cur.sigmask.load(Ordering::Acquire);
                if pending & !mask != 0 { return Some(-(Errno::Eintr.as_i32() as i64)); }
                // park WITH a re-check deadline (not a bare park): the
                // active() check and the park are NOT under a shared lock, so a
                // do_switch completing in that window would wake an empty list
                // and the park would then miss it. The deadline bounds a missed
                // wake to RESCAN_NS of latency (the re-loop re-reads active())
                // instead of a hang — the same safety net poll/select use.
                const RESCAN_NS: u64 = 20_000_000; // 20ms
                let dl = crate::poll::poll_common::monotonic_ns().saturating_add(RESCAN_NS);
                // SAFETY: process ctx; preempt-off across the syscall; park_with_deadline marks the running task Sleeping on VT_SWITCH_WAIT + stamps the wake deadline; schedule yields; the re-loop re-reads active() on wake — woken by vt_switch_wake (do_switch) or the deadline scanner.
                unsafe {
                    VT_SWITCH_WAIT.park_with_deadline(dl);
                    sched::live::schedule();
                }
            }
        }
        vt::VT_DISALLOCATE => {
            match vt::disallocate(arg as u8) {
                Ok(()) => Some(0),
                Err(vt::Error::Busy) => Some(errno(Errno::Ebusy)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_LOCKSWITCH | vt::VT_UNLOCKSWITCH => {
            let lock = req == vt::VT_LOCKSWITCH;
            match vt::lock_switch(vt_target, lock) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_GETMODE => {
            let m = vt::slot(vt_target).map(|s| s.vt_mode).unwrap_or_default();
            if arg == 0 || arg + 8 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 8; struct vt_mode is 8 bytes (u8,u8,u16,u16,u16) written field-by-field into the caller's AS.
            unsafe {
                core::ptr::write_volatile(arg as *mut u8, m.mode);
                core::ptr::write_volatile((arg + 1) as *mut u8, m.waitv);
                core::ptr::write_volatile((arg + 2) as *mut u16, m.relsig);
                core::ptr::write_volatile((arg + 4) as *mut u16, m.acqsig);
                core::ptr::write_volatile((arg + 6) as *mut u16, m.frsig);
            }
            Some(0)
        }
        vt::VT_SETMODE => {
            if arg == 0 || arg + 8 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 8; reading the 8-byte struct vt_mode from the caller's AS field-by-field.
            let m = unsafe {
                vt::VtMode {
                    mode:   core::ptr::read_volatile(arg as *const u8),
                    waitv:  core::ptr::read_volatile((arg + 1) as *const u8),
                    relsig: core::ptr::read_volatile((arg + 2) as *const u16),
                    acqsig: core::ptr::read_volatile((arg + 4) as *const u16),
                    frsig:  core::ptr::read_volatile((arg + 6) as *const u16),
                }
            };
            // Record the calling process as the VT's controlling owner (Linux
            // vc->vt_pid): BOTH its namespace vpid (to signal) and its internal
            // tid (monotonic, never reused) so the handshake's liveness test is
            // immune to vpid reuse.
            let (vpid, tid) = sched::live::current()
                .map(|t| (t.vtgid.load(core::sync::atomic::Ordering::Acquire), t.tid))
                .unwrap_or((0, 0));
            match vt::set_vt_mode(vt_target, m, vpid, tid) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_RELDISP => {
            // The foreground VT_PROCESS owner answers a release request: arg>=1
            // allows a pending switch to complete, arg==0 refuses it. The vt
            // layer validates the caller IS that VT's recorded owner (vpid+tid)
            // — a non-owner that tries to ack/cancel another's switch gets
            // EPERM (Linux `vt_reldisp` ownership check).
            let (vpid, tid) = sched::live::current()
                .map(|t| (t.vtgid.load(core::sync::atomic::Ordering::Acquire), t.tid))
                .unwrap_or((0, 0));
            match vt::reldisp(arg as i32, vpid, tid) {
                Ok(()) => Some(0),
                Err(vt::Error::Perm) => Some(errno(Errno::Eperm)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGETLED | vt::KDGKBLED => {
            let leds = vt::slot(vt_target).map(|s| s.leds).unwrap_or(0) as u8;
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; single-byte LED state store into caller's AS.
                unsafe { core::ptr::write_volatile(arg as *mut u8, leds); }
            }
            Some(0)
        }
        vt::KDSETLED | vt::KDSKBLED => {
            // arg = LED bitmask by value (Scroll=1,Num=2,Caps=4); 0xff means
            // "revert to the default kbd-driven state" — no LED hardware, so
            // store the bits (0 on revert).
            let leds = if (arg as u32) == 0xff { 0 } else { (arg as u32) & 0x7 };
            match vt::set_leds(vt_target, leds) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_RESIZE | vt::VT_RESIZEX => {
            // vt_sizes { u16 v_rows, v_cols, ... } / vt_consize { u16 v_rows,
            // v_cols, ... } — both lead with rows then cols.
            if arg == 0 || arg + 4 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 4; reading the leading 2×u16 (rows, cols) of the resize struct from the caller's AS.
            let (rows, cols) = unsafe {
                (core::ptr::read_volatile(arg as *const u16),
                 core::ptr::read_volatile((arg + 2) as *const u16))
            };
            match vt::resize(vt_target, rows, cols) {
                Ok(()) => { vt_apply_winsize(rows, cols); Some(0) }
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::TIOCLINUX => Some(handle_tioclinux(arg)),
        // Linux's vt_ioctl() has NO case for VT_SENDSIG: it falls through to
        // ENOIOCTLCMD → the tty layer maps that to ENOTTY/EINVAL. Mirror that
        // deliberately (parity decision, not a silent gap) — do not invent a
        // behaviour Linux itself does not implement.
        vt::VT_SENDSIG => Some(errno(Errno::Einval)),
        // Font + unicode-map (setfont): own handler.
        vt::KDFONTOP | vt::PIO_UNIMAP | vt::GIO_UNIMAP | vt::PIO_UNIMAPCLR => {
            handle_font_ioctl(req, arg)
        }
        // KIOCSOUND / KDMKTONE / KDADDIO — accept silently or EPERM.
        vt::KIOCSOUND | vt::KDMKTONE => Some(0),
        vt::KDADDIO => Some(errno(Errno::Eperm)),
        _ => None,
    }
}

/// VT_RESIZE/VT_RESIZEX side effect: push the new grid into the system
/// console winsize and raise SIGWINCH on its fg pgrp (Linux `vt_resize` →
/// tty winsize update + signal), so a full-screen app reflows.
/// # C: O(P) tasks in the fg pgrp.
fn vt_apply_winsize(rows: u16, cols: u16) {
    let ws = tty::pty::Winsize { rows, cols, xpixel: 0, ypixel: 0 };
    // VT_RESIZE targets the foreground VIDEO console, not the serial line.
    let fgvt = console::foreground_vt();
    let tty = console::vt_tty::vt_tty(fgvt);
    let changed = tty.set_winsize(ws);
    let fg = tty.fg_pgrp();
    if changed && fg != 0 {
        use core::sync::atomic::Ordering;
        // SIGWINCH is the canonical window-size notification signal.
        for t in sched::live::registry::tasks_in_pgrp(fg) {
            t.sigpending.fetch_or(sched::Signum::Sigwinch.bit(), Ordering::Release);
        }
    }
}
