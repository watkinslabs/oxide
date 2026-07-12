#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::autofs::handle_autofs_dev_ioctl;
use super::blk::handle_blk_ioctl;
use super::common::{handle_common_ioctl, handle_nonchar_queue_ioctl};
use super::uapi::INT_BYTES;
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
    if let Some(rv) = handle_common_ioctl(cur, &file, &fdt, fd, req, arg) {
        return rv;
    }
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
    // SIOCGSKNS (linux/sockios.h): "get the network namespace fd of this
    // socket". systemd's sd-device-monitor probes its NETLINK_KOBJECT_UEVENT
    // socket with it (device-monitor.c, under DEBUG_LOGGING) then fstat-compares
    // the result with /proc/1/ns/net; a blanket ENOTTY produced the per-worker
    // "Unable to get network namespace of udev netlink socket, unable to
    // determine if we are in host netns, ignoring: Inappropriate ioctl for
    // device" warning. Linux `sock_ioctl` answers it for ANY socket fd (netlink,
    // inet, unix) — all of which are FileType::Socket here.
    if req == super::netns::SIOCGSKNS
        && file.inode().file_type() == vfs::FileType::Socket
    {
        return super::netns::handle_siocgskns();
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
    // FS_IOC_GETFLAGS / FS_IOC_SETFLAGS (Linux fs/ioctl.c ioctl_getflags/
    // setflags) — the chattr/lsattr inode flag word. Regular files + directories
    // (any inode whose fs implements fileattr_get/set); route BEFORE the CharDev
    // gate. Was a blanket ENOTTY → chattr/lsattr/e2fsprogs failed.
    const FS_IOC_GETFLAGS: u64 = 0x8008_6601; // _IOR('f', 1, long)
    const FS_IOC_SETFLAGS: u64 = 0x4008_6602; // _IOW('f', 2, long)
    const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
    const FS_APPEND_FL:    u32 = 0x0000_0020;
    if req == FS_IOC_GETFLAGS {
        let fa = match file.inode().fileattr_get() {
            Ok(f) => f, Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
        // SAFETY: arg validated < USER_VA_END; FS_IOC_GETFLAGS writes one int flag word.
        unsafe { core::ptr::write_volatile(arg as *mut u32, fa.flags); }
        return 0;
    }
    if req == FS_IOC_SETFLAGS {
        if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
        // SAFETY: arg validated < USER_VA_END; read the caller's int flag word.
        let want = unsafe { core::ptr::read_volatile(arg as *const u32) };
        // inode_owner_or_capable: only the owner (or CAP_FOWNER) may chattr.
        let cred = crate::pathresolve::current_cred();
        if file.inode().uid() != Some(cred.uid) && !cur.has_cap(sched::cap::FOWNER) {
            return -(Errno::Eperm.as_i32() as i64);
        }
        // Toggling IMMUTABLE/APPEND additionally needs CAP_LINUX_IMMUTABLE.
        let cur_flags = file.inode().fileattr_get().map(|f| f.flags).unwrap_or(0);
        if (want ^ cur_flags) & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0
            && !cur.has_cap(sched::cap::LINUX_IMMUTABLE)
        {
            return -(Errno::Eperm.as_i32() as i64);
        }
        let fa = vfs::FileAttr { flags: want, ..Default::default() };
        return match file.inode().fileattr_set(&fa) {
            Ok(()) => 0, Err(e) => crate::namei_common::errno_from_vfs(e),
        };
    }
    // FS_IOC_FIEMAP (filefrag/backup/dedup): map a regular file's physical
    // extents. A regular-file/dir fd is not a CharDev, so route here before the
    // generic non-CharDev path returns ENOTTY.
    if let Some(rv) = super::fiemap::handle_fiemap(&file.inode(), req, arg) { return rv; }
    // Block-device geometry ioctls (BLKGETSIZE64/BLKGETSIZE/BLKSSZGET/BLKBSZGET).
    // A block node is not a CharDev, so answer these before the generic
    // non-CharDev path returns ENOTTY — blkid/mkfs/udev probe them on /dev/vda.
    if file.inode().file_type() == vfs::FileType::BlockDev {
        if let Some(rv) = handle_blk_ioctl(&file.inode(), req, arg) { return rv; }
    }
    if file.inode().file_type() != vfs::FileType::CharDev {
        // Socket/pipe ioctls (Linux `sock_ioctl`): a socket is NOT a CharDev but
        // supports FIONREAD/SIOCINQ, SIOCOUTQ/TIOCOUTQ, FIONBIO, FIOASYNC. dbus-
        // broker's socket write path calls one of these for flow control and
        // treats ENOTTY as FATAL — so a blanket ENOTTY crashed the whole D-Bus
        // system bus (Inappropriate ioctl for device), taking down every
        // D-Bus-dependent service (logind↔gdm → no greeter). Answer them.
        if let Some(rv) = handle_nonchar_queue_ioctl(&file, req, arg) {
            return rv;
        }
        return -(Errno::Enotty.as_i32() as i64);
    }
    handle_tty_ioctl(&file, fd, req, arg)
}
