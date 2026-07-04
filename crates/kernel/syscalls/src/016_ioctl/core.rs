#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::autofs::handle_autofs_dev_ioctl;
use super::tty_ioctl::handle_tty_ioctl;

/// `sys_ioctl(fd, request, arg)` - slot 16.
/// # C: O(1)
pub fn sys_ioctl(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    // ioctl request numbers are conventionally 32-bit (Linux's
    // `_IO*` macros encode them in 32 bits). musl's userspace stub
    // passes them as `int`, so on x86_64 the upper 32 bits of rsi
    // can carry sign-extended garbage (e.g. TIOCGPTN = 0x80045430
    // sign-extends to 0xFFFFFFFF80045430). Mask to 32 bits so our
    // match arms compare correctly.
    let req = args.a1 & 0xFFFF_FFFF;
    let arg = args.a2;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // pidfd ioctls (PIDFD_GET_INFO): route before the CharDev gate.
    // systemd verifies a forked service is its child via this ioctl;
    // ENOTTY makes it SIGKILL the child (console-getty respawn).
    if let Some(target) = crate::pidfd::task_from_inode(&file.inode()) {
        let rv = crate::pidfd::handle_pidfd_ioctl(target, req, arg);
        #[cfg(feature = "debug-syscall")]
        if rv == -(Errno::Enotty.as_i32() as i64) {
            klog::write_raw(b"[ioctl] pidfd ENOTTY req=");
            klog::write_hex_u64(req);
            klog::write_raw(b" ino=");
            klog::write_dec_u64(file.inode().ino());
            klog::write_raw(b"\n");
        }
        return rv;
    }
    // userfaultfd / perf ioctls: route through the dedicated handlers
    // before the CharDev gate (those inodes are tagged Regular).
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5546_4644_0000_0000 {
        return ::fs::userfaultfd::handle_uffd_ioctl(file.inode(), req, arg);
    }
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5045_5246_0000_0000 {
        return ::fs::perf::handle_perf_ioctl(file.inode(), req, arg);
    }
    // evdev ioctls.
    if let Some(rv) = drv_virtio_input::devfs::handle_evdev_ioctl(&file, req, arg) {
        return rv;
    }
    // DRM/render fd ioctls.
    if let Some(rv) = fbdev::devfs::handle_fbdev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    if let Some(rv) = drm::node::handle_drm_ioctl(&file, req, arg) {
        return rv;
    }
    // ALSA /dev/snd/* + OSS /dev/dsp,/dev/mixer — the `sound` ALSA core.
    if let Some(rv) = sound::handle_ioctl(file.inode(), req, arg) { return rv; }
    if let Some(rv) = handle_autofs_dev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    // B48: SIOC* network-iface ioctls on AF_INET / AF_INET6 sockets.
    // dhcpcd's whole bring-up dance uses SIOCGIFFLAGS / SIOCSIFFLAGS
    // / SIOCGIFADDR / SIOCSIFADDR / SIOCGIFINDEX / SIOCGIFHWADDR
    // / SIOCGIFMTU / SIOCGIFNETMASK / SIOCADDRT to probe + configure
    // eth0 before sending the DHCPDISCOVER.
    if (req & 0xFFFFFF00) == 0x00008900 {
        if let Some(rv) = crate::siocgif::handle_sioc(req, arg) {
            return rv;
        }
    }
    // FIFREEZE / FITHAW (Linux `ioctl_fsfreeze`/`ioctl_fsthaw`, fs/ioctl.c).
    // Issued on a regular file / directory / block-device fd; route BEFORE the
    // CharDev gate. CAP_SYS_ADMIN-gated. `arg` is ignored (Linux ignores it).
    // FIFREEZE → `freeze_super` (EBUSY if already frozen); FITHAW →
    // `thaw_super` (EINVAL if not frozen). The sb is the file inode's `i_sb`.
    const FIFREEZE: u64 = 0xC0045877;
    const FITHAW:   u64 = 0xC0045878;
    if req == FIFREEZE || req == FITHAW {
        if !cur.has_cap(sched::cap::SYS_ADMIN) { return -(Errno::Eperm.as_i32() as i64); }
        let sb = match file.inode().i_sb() {
            Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
        };
        let r = if req == FIFREEZE { sb.freeze_super() } else { sb.thaw_super() };
        return match r {
            Ok(())  => 0,
            Err(e)  => crate::namei_common::errno_from_vfs(e),
        };
    }
    if file.inode().file_type() != vfs::FileType::CharDev {
        // Socket/pipe ioctls (Linux `sock_ioctl`): a socket is NOT a CharDev but
        // supports FIONREAD/SIOCINQ, SIOCOUTQ/TIOCOUTQ, FIONBIO, FIOASYNC. dbus-
        // broker's socket write path calls one of these for flow control and
        // treats ENOTTY as FATAL — so a blanket ENOTTY crashed the whole D-Bus
        // system bus (Inappropriate ioctl for device), taking down every
        // D-Bus-dependent service (logind↔gdm → no greeter). Answer them.
        const FIONREAD:  u64 = 0x541B; // == SIOCINQ: bytes available to read
        const SIOCOUTQ:  u64 = 0x5411; // == TIOCOUTQ: bytes queued to send
        const FIONBIO:   u64 = 0x5421; // set/clear O_NONBLOCK
        const FIOASYNC:  u64 = 0x5452; // set/clear O_ASYNC
        match req {
            FIONREAD | SIOCOUTQ => {
                // Report a pending byte count as an int out-param. Best-effort:
                // FIONREAD signals "data readable" (1) vs not (0); SIOCOUTQ (send
                // queue) reports drained (0). Never fatal, unlike ENOTTY.
                let n: u32 = if req == FIONREAD
                    && (file.inode().poll_file(file.pos()) & vfs::POLL_IN) != 0 { 1 } else { 0 };
                if arg != 0 && arg < hal::USER_VA_END {
                    // SAFETY: arg validated < USER_VA_END; 4-byte int out-param.
                    unsafe { core::ptr::write_volatile(arg as *mut u32, n); }
                }
                return 0;
            }
            FIONBIO => {
                if arg != 0 && arg < hal::USER_VA_END {
                    // SAFETY: arg validated; read the on/off int the caller passed.
                    let on = unsafe { core::ptr::read_volatile(arg as *const u32) } != 0;
                    let mut fl = file.flags();
                    if on { fl |= vfs::OpenFlags::O_NONBLOCK; } else { fl &= !vfs::OpenFlags::O_NONBLOCK; }
                    file.set_flags(fl);
                }
                return 0;
            }
            FIOASYNC => return 0, // accept; async SIGIO wiring rides fasync
            _ => {}
        }
        return -(Errno::Enotty.as_i32() as i64);
    }
    handle_tty_ioctl(&file, fd, req, arg)
}
