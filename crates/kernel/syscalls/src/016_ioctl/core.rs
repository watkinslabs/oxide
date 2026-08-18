#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::ioctl_user as user;

use super::autofs::handle_autofs_dev_ioctl;
use super::blk::handle_blk_ioctl;
use super::device_mapper::handle_mapper_control_ioctl;
use super::loop_dev::{handle_loop_control_ioctl, handle_loop_ioctl};
use super::md::handle_md_ioctl;
use super::scsi::handle_scsi_ioctl;
use super::ata::handle_ata_ioctl;
use super::common::{handle_common_ioctl, handle_nonchar_queue_ioctl, handle_socket_owner_ioctl};
use super::f2fs::handle_f2fs_ioctl;
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
    // Device control is decided by the rights recorded at open. A fixed set of
    // commands stays available regardless: they act on the filesystem rather
    // than the device, or duplicate something reachable through descriptor
    // flags, so gating them would restrict nothing while breaking ordinary
    // programs.
    if !::landlock::access::ioctl_allowed(file.landlock_access(),
        ::landlock::access::is_device(file.inode().file_type()), req)
    {
        return -(Errno::Eacces.as_i32() as i64);
    }
    // Stage 1 — `do_vfs_ioctl`: the generic commands the VFS owns for THIS
    // file. Anything it declines falls through to the file's own operations,
    // exactly like Linux's `-ENOIOCTLCMD` → `vfs_ioctl` hand-off. The
    // filesystem's own `unlocked_ioctl` (the version/label/trim set) is NOT
    // part of this stage — running it here shadowed every anon fd's handler
    // for those command numbers.
    if let Some(rv) = handle_common_ioctl(cur, &file, &fdt, fd, req, arg) {
        return rv;
    }
    // Stage 2 — `f_op->unlocked_ioctl`, per file kind.
    // pidfd ioctls (PIDFD_GET_INFO): route before the CharDev gate.
    // systemd verifies a forked service is its child via this ioctl;
    // ENOTTY makes it SIGKILL the child (console-getty respawn).
    if let Some(identity) = pidfd::identity_from_inode(&file.inode()) {
        let rv = crate::pidfd::handle_pidfd_ioctl(identity, req, arg);
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
    // The watch-queue ioctls (`IOC_WATCH_QUEUE_SET_{SIZE,FILTER}`): a pipe is
    // a Fifo, which the generic stage has no handler for, so they route here.
    if let Some(rv) = ::fs::watch_queue::handle_watch_queue_ioctl(&file, req, arg) {
        return rv;
    }
    // timerfd `TFD_IOC_SET_TICKS`: route before the CharDev gate; a timerfd
    // inode is tagged CharDev but has no device backend to dispatch to.
    if let Some(rv) = ::fs::timerfd::handle_timerfd_ioctl(&file.inode(), req, arg) {
        return rv;
    }
    // `ep_eventpoll_ioctl` (EPIOCSPARAMS/EPIOCGPARAMS, and EINVAL for anything
    // else reaching an epoll file).
    if let Some(rv) = ::fs::epoll::handle_epoll_ioctl(&file, req, arg) {
        return rv;
    }
    // seccomp user-notification ioctls. The handler recognises its own files
    // by the listener their inode owns, so a foreign inode reusing these
    // command numbers falls through untouched.
    if let Some(rv) = security::seccomp::notif::handle_ioctl(&file, req, arg) {
        return rv;
    }
    // userfaultfd / perf ioctls: route through the dedicated handlers before
    // the CharDev gate (those inodes are tagged Regular). Each handler's file
    // is recognised by the backend state its inode owns, as Linux compares
    // `f_op` against `userfaultfd_fops` / `perf_fops`. The literal high-half
    // number tests these replace routed any foreign inode reusing those bits
    // into a handler that then read its unrelated private word as its own
    // state, and consumed the command before the real owner was consulted.
    if ::fs::userfaultfd::is_uffd_inode(&file.inode()) {
        return ::fs::userfaultfd::handle_uffd_ioctl(file.inode(), req, arg);
    }
    if ::fs::perf::is_perf_inode(&file.inode()) {
        return ::fs::perf::handle_perf_ioctl(file.inode(), req, arg);
    }
    // evdev ioctls. The handler recognises its own files by the backend state
    // their inode owns, so a foreign inode that happens to reuse an evdev
    // inode NUMBER falls through here untouched.
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
    if let Some(rv) = sound::handle_ioctl(&file, req, arg) { return rv; }
    // `/dev/videoN` — the V4L2 device core. It recognises its own files by the
    // backend state their inode owns, so a foreign inode never reaches it.
    if let Some(rv) = v4l2::node::handle_ioctl(&file, req, arg) { return rv; }
    if let Some(rv) = handle_autofs_dev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    // Device mapper owns every command arriving on `/dev/mapper/control`.
    // This is before generic character dispatch so the control ABI is the
    // same for its devtmpfs node and an equivalent mknod-created node.
    if let Some(rv) = handle_mapper_control_ioctl(file.inode(), req, arg,
        cur.has_cap(sched::cap::SYS_ADMIN)) {
        return rv;
    }
    // `/dev/loop-control` owns every command sent to it; a `/dev/loopN` owns
    // only the loop commands, so its size and discard ioctls still reach the
    // block handler below.
    if let Some(rv) = handle_loop_control_ioctl(file.inode(), req, arg) {
        return rv;
    }
    if let Some(rv) = handle_loop_ioctl(&file, req, arg) {
        return rv;
    }
    // The filesystem's own `unlocked_ioctl` (`ext4_ioctl`): inode version,
    // filesystem label, FITRIM. Runs AFTER every fd-kind handler above, and
    // never for an anon inode, which has no filesystem to answer for and whose
    // own operations already had their turn.
    if super::fs_unlocked_ioctl_applies(super::ioctl_file(&file)) {
        if let Some(rv) = handle_file_ioctl(cur, &file, req, arg) {
            return rv;
        }
        // f2fs's own command set (`f2fs_ioctl`), reached with the number
        // untouched. It runs AFTER the typed set above and claims only what
        // neither the generic stage nor the typed stage owns, so no stage
        // shadows another; and it recognises its own files by the backend
        // state their inode carries, so a foreign inode falls through it.
        if let Some(rv) = handle_f2fs_ioctl(cur, &file, &fdt, req, arg) {
            return rv;
        }
    }
    // SIOCGSKNS: "get the network namespace fd of this
    // socket". systemd's sd-device-monitor probes its NETLINK_KOBJECT_UEVENT
    // socket with it (device-monitor.c, under DEBUG_LOGGING) then fstat-compares
    // the result with /proc/1/ns/net; a blanket ENOTTY produced the per-worker
    // "Unable to get network namespace of udev netlink socket, unable to
    // determine if we are in host netns, ignoring: Inappropriate ioctl for
    // device" warning. Linux `sock_ioctl` answers it for ANY socket fd (netlink,
    // inet, unix) — all of which are FileType::Socket here.
    if req == super::netns::SIOCGSKNS {
        let namespace = match sioc_socket_net_namespace(&file) {
            Some(namespace) => namespace,
            None => return -(Errno::Enotty.as_i32() as i64),
        };
        if let Err(error) = net::security_admission::check(
            net::net_ns::namespace_id(&namespace), sioc_socket_family(&file),
            security::network::Operation::Ioctl,
        ) { return crate::net_errno::errno_from_neterr(error); }
        return super::netns::handle_siocgskns(namespace);
    }
    if matches!(req, super::uapi::SIOCGSTAMP_OLD | super::uapi::SIOCGSTAMPNS_OLD
        | super::uapi::SIOCGSTAMP_NEW | super::uapi::SIOCGSTAMPNS_NEW)
    {
        return socket_receive_timestamp_ioctl(&file, req, arg);
    }
    // Linux `sock_ioctl` owns the FIO* f_owner aliases. Keep their usercopy
    // and File-owned SIGIO target state out of the generic ioctl shim, and do
    // not expose them on non-socket file types.
    if file.inode().file_type() == vfs::FileType::Socket
        && matches!(req, super::uapi::FIOSETOWN | super::uapi::SIOCSPGRP
            | super::uapi::FIOGETOWN | super::uapi::SIOCGPGRP)
    {
        // The aliases mutate/read socket-associated asynchronous-notification
        // state. Admit them before their usercopy or f_owner transition, like
        // every other socket ioctl owner.
        let namespace = match sioc_socket_net_namespace(&file) {
            Some(namespace) => namespace,
            None => return -(Errno::Enotty.as_i32() as i64),
        };
        if let Err(error) = net::security_admission::check(
            net::net_ns::namespace_id(&namespace), sioc_socket_family(&file),
            security::network::Operation::Ioctl,
        ) { return crate::net_errno::errno_from_neterr(error); }
        if let Some(rv) = handle_socket_owner_ioctl(&file, req, arg) { return rv; }
    }
    // B48: SIOC* network-iface ioctls on AF_INET / AF_INET6 sockets.
    // dhcpcd's whole bring-up dance uses SIOCGIFFLAGS / SIOCSIFFLAGS
    // / SIOCGIFADDR / SIOCSIFADDR / SIOCGIFINDEX / SIOCGIFHWADDR
    // / SIOCGIFMTU / SIOCGIFNETMASK / SIOCADDRT to probe + configure
    // eth0 before sending the DHCPDISCOVER.
    let access = match crate::siocgif::sioc_access(req, arg) {
        Ok(access) => access, Err(rv) => return rv,
    };
    if let Some(access) = access {
        let net_namespace = match sioc_socket_net_namespace(&file) {
            Some(namespace) => namespace,
            None => return -(Errno::Enotty.as_i32() as i64),
        };
        if let Err(error) = net::security_admission::check(
            net::net_ns::namespace_id(&net_namespace), sioc_socket_family(&file),
            security::network::Operation::Ioctl,
        ) { return crate::net_errno::errno_from_neterr(error); }
        if let Some(error) = net::sock::legacy_ioctl_errno(sioc_socket_family(&file), req) {
            return crate::net_errno::errno_from_neterr(error);
        }
        if access == crate::siocgif::SiocAccess::Mutate
            && !nscg::has_net_admin_for(cur, &net_namespace)
        {
            return -(Errno::Eperm.as_i32() as i64);
        }
        return crate::siocgif::handle_sioc_in(net_namespace.id().as_u64(), req, arg)
            .unwrap_or(-(Errno::Enotty.as_i32() as i64));
    }
    // FIFREEZE / FITHAW (Linux `ioctl_fsfreeze`/`ioctl_fsthaw`).
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
    // FS_IOC_FIEMAP (filefrag/backup/dedup): map a regular file's physical
    // extents. A regular-file/dir fd is not a CharDev, so route here before the
    // generic non-CharDev path returns ENOTTY.
    if let Some(rv) = super::fiemap::handle_fiemap(&file.inode(), req, arg) { return rv; }
    // Block-device ioctls (geometry + discard family).
    // A block node is not a CharDev, so answer these before the generic
    // non-CharDev path returns ENOTTY — blkid/mkfs/udev probe them on /dev/vda.
    if file.inode().file_type() == vfs::FileType::BlockDev {
        if let Some(rv) = handle_blk_ioctl(&file, req, arg) { return rv; }
        if let Some(rv) = handle_md_ioctl(&file, req, arg) { return rv; }
        if let Some(rv) = handle_ata_ioctl(&file, req, arg,
            cur.has_cap(sched::cap::SYS_ADMIN), cur.has_cap(sched::cap::SYS_RAWIO)) { return rv; }
        if let Some(rv) = handle_scsi_ioctl(&file, req, arg, cur.has_cap(sched::cap::SYS_RAWIO)) { return rv; }
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
    // An opened character device owns its file_operations ioctl. In particular,
    // external DRM drivers require the private state installed by their open
    // callback, not a synthetic file assembled from the device number.
    if let Some(rv) = vfs::opened_chrdev_ioctl(&file, req as u32, arg as usize) {
        return match rv { Ok(v) => v as i64, Err(e) => -(e as i64) };
    }
    handle_tty_ioctl(cur, &file, &fdt, fd, req, arg)
}

fn sioc_socket_net_namespace(file: &vfs::File) -> Option<network_namespace::NetworkNamespaceRef> {
    if file.inode().file_type() != vfs::FileType::Socket { return None; }
    if let Ok(sock) = file.inode().i_private().clone().downcast::<net::sock::InetSocket>() {
        return Some(sock.net_namespace.clone());
    }
    if let Ok(sock) = file.inode().i_private().clone().downcast::<::netlink::NetlinkSocket>() {
        return Some(sock.net_ns.clone());
    }
    file.inode().i_private().clone().downcast::<net::vsock_socket::VsockSocket>()
        .ok().map(|sock| sock.net_namespace.clone())
}

fn sioc_socket_family(file: &vfs::File) -> u16 {
    if let Ok(sock) = file.inode().i_private().clone().downcast::<net::sock::InetSocket>() {
        return sock.family.load(core::sync::atomic::Ordering::Acquire);
    }
    if file.inode().i_private().clone().downcast::<::netlink::NetlinkSocket>().is_ok() {
        return net::socket_args::AF_NETLINK_WIRE;
    }
    if file.inode().i_private().clone().downcast::<net::vsock_socket::VsockSocket>().is_ok() {
        return net::socket_args::AF_VSOCK as u16;
    }
    net::sock::AF_INET
}

/// Linux `sock_gettstamp`: export the socket owner's most recently delivered
/// receive timestamp in the selected old/new timeval or timespec ABI. # C: O(1)
fn socket_receive_timestamp_ioctl(file: &vfs::File, req: u64, arg: u64) -> i64 {
    let sock = match file.inode().i_private().clone().downcast::<net::sock::InetSocket>() {
        Ok(sock) => sock,
        Err(_) => return -(Errno::Enotty.as_i32() as i64),
    };
    if let Err(error) = net::security_admission::check(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), security::network::Operation::Ioctl)
    { return crate::net_errno::errno_from_neterr(error); }
    let timestamp_ns = match sock.enable_receive_timestamp() {
        Some(timestamp_ns) => timestamp_ns,
        None => return -(Errno::Enoent.as_i32() as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg,
        super::uapi::SOCKET_TIMESTAMP_BYTES, 1)
    { return rv; }
    let (seconds, subsecond) = if matches!(req, super::uapi::SIOCGSTAMP_OLD
        | super::uapi::SIOCGSTAMP_NEW)
    {
        let (seconds, microseconds) = sched::clock::ns_to_timeval(timestamp_ns);
        (seconds, microseconds)
    } else {
        (timestamp_ns / super::uapi::NSEC_PER_SECOND,
            timestamp_ns % super::uapi::NSEC_PER_SECOND)
    };
    let mut out = [0u8; 2 * core::mem::size_of::<i64>()];
    out[..8].copy_from_slice(&(seconds as i64).to_ne_bytes());
    out[8..].copy_from_slice(&(subsecond as i64).to_ne_bytes());
    if let Err(rv) = user::put_bytes(arg, &out) { return rv; }
    0
}

fn handle_file_ioctl(cur: &sched::Task, file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    match req {
        super::uapi::EXT4_IOC_GETVERSION | super::uapi::FS_IOC_GETVERSION =>
            Some(ioctl_getversion(file, arg)),
        super::uapi::EXT4_IOC_SETVERSION | super::uapi::FS_IOC_SETVERSION =>
            Some(ioctl_setversion(file, arg)),
        super::uapi::FS_IOC_GETFSLABEL => Some(ioctl_getfslabel(file, arg)),
        super::uapi::FS_IOC_SETFSLABEL => Some(ioctl_setfslabel(cur, file, arg)),
        super::uapi::FITRIM => Some(ioctl_fitrim(cur, file, arg)),
        _ => None,
    }
}

fn ioctl_getversion(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    let gen = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::GetVersion) {
        Ok(vfs::FileIoctlReply::U32(v)) => v,
        Ok(_) => return -(Errno::Enotty.as_i32() as i64),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::INT_BYTES, 1) {
        return rv;
    }
    match user::put_u32(arg, gen) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_setversion(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetVersionPrepare) {
        return -(e as i64);
    }
    let m = file.vfsmount();
    if let Some(ref mnt) = m {
        if let Err(e) = vfs::mount::mnt_want_write(mnt) { return -(e as i64); }
        if mnt.sb().is_readonly() {
            vfs::mount::mnt_drop_write(mnt);
            return -(vfs::VfsError::Erofs as i64);
        }
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::INT_BYTES, 1) {
        if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
        return rv;
    }
    let gen = match user::get_u32(arg) {
        Ok(v) => v,
        Err(rv) => { if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); } return rv; }
    };
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetVersion(gen)) {
        Ok(_) => 0,
        Err(e) => -(e as i64),
    };
    if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
    rv
}

fn ioctl_getfslabel(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    let label = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::GetFsLabel) {
        Ok(vfs::FileIoctlReply::Label(v)) => v,
        Ok(_) => return -(Errno::Enotty.as_i32() as i64),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::EXT4_LABEL_BYTES, 1) {
        return rv;
    }
    match user::put_bytes(arg, &label) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_setfslabel(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    let cap = cur.has_cap(sched::cap::SYS_ADMIN);
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetFsLabelPrepare(cap)) {
        return -(e as i64);
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::EXT4_LABEL_BYTES, 1) {
        return rv;
    }
    let mut buf = [0u8; super::uapi::EXT4_LABEL_MAX + 1];
    if let Err(rv) = user::get_into(arg, &mut buf) { return rv; }
    let len = match buf.iter().position(|&b| b == 0) {
        Some(n) => n,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut label = [0u8; super::uapi::EXT4_LABEL_MAX];
    label[..len].copy_from_slice(&buf[..len]);
    let m = file.vfsmount();
    if let Some(ref mnt) = m {
        if let Err(e) = vfs::mount::mnt_want_write(mnt) { return -(e as i64); }
        if mnt.sb().is_readonly() {
            vfs::mount::mnt_drop_write(mnt);
            return -(vfs::VfsError::Erofs as i64);
        }
    }
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetFsLabel(label)) {
        Ok(_) => 0,
        Err(e) => -(e as i64),
    };
    if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
    rv
}

fn ioctl_fitrim(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    let cap = cur.has_cap(sched::cap::SYS_ADMIN);
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FitTrimPrepare(cap)) {
        return -(e as i64);
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::FSTRIM_RANGE_BYTES, 1) {
        return rv;
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::FSTRIM_RANGE_BYTES, 1) {
        return rv;
    }
    let range = match user::get_bytes::<{ super::uapi::FSTRIM_RANGE_BYTES as usize }>(arg) {
        Ok(b) => b, Err(rv) => return rv,
    };
    let fld = |o: usize| { let mut v = [0u8; 8]; v.copy_from_slice(&range[o..o + 8]); u64::from_ne_bytes(v) };
    let (start, len, minlen) = (fld(0), fld(8), fld(16));
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FitTrim { start, len, minlen }) {
        Ok(_) => 0,
        Err(e) => return -(e as i64),
    };
    let mut out = [0u8; super::uapi::FSTRIM_RANGE_BYTES as usize];
    out[..8].copy_from_slice(&start.to_ne_bytes());
    out[8..16].copy_from_slice(&len.to_ne_bytes());
    out[16..24].copy_from_slice(&minlen.to_ne_bytes());
    if let Err(fault) = user::put_bytes(arg, &out) { return fault; }
    rv
}

#[cfg(not(test))]
fn current_cred() -> vfs::Cred {
    crate::pathresolve::current_cred()
}

#[cfg(test)]
fn current_cred() -> vfs::Cred {
    vfs::Cred::root()
}
