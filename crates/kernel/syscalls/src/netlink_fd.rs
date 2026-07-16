// F132: netlink-fd shims for socket-shaped syscalls.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

use crate::net_sockaddr::{copy_sockaddr_to_user, encoded_sockaddr_nl};

/// NETLINK socket plus the Linux `fget`-style file pin retained for one syscall.
pub struct NetlinkFileRef {
    file: Arc<vfs::File>,
    socket: Arc<::netlink::NetlinkSocket>,
}

impl NetlinkFileRef {
    /// Classify an already-pinned file without consulting the descriptor table. # C: O(1)
    pub fn from_file(file: Arc<vfs::File>) -> Option<Self> {
        let socket = ::netlink::netlink_arc_from_inode(file.inode())?;
        Some(Self { file, socket })
    }

    /// Retained open file description for status flags and VFS operations. # C: O(1)
    pub fn file(&self) -> &Arc<vfs::File> { &self.file }

    /// Concrete NETLINK endpoint owned by the retained file. # C: O(1)
    pub fn socket(&self) -> &Arc<::netlink::NetlinkSocket> { &self.socket }
}

/// Classify an already-pinned file as NETLINK while retaining that exact file. # C: O(1)
pub fn from_file(file: Arc<vfs::File>) -> Option<NetlinkFileRef> {
    NetlinkFileRef::from_file(file)
}

/// True if `file` is backed by a NetlinkSocket inode. # C: O(1)
pub fn is_netlink_file(file: &Arc<vfs::File>) -> bool {
    file.inode().private::<::netlink::NetlinkSocket>().is_some()
}

// DIAG (debug-uevent): trace the udev-monitor delivery chain.
#[cfg(feature = "debug-uevent")]
fn uev_kv<'a>(payload: &'a [u8], key: &[u8]) -> &'a [u8] {
    let mut i = 0;
    while i < payload.len() {
        let start = i;
        while i < payload.len() && payload[i] != 0 { i += 1; }
        let field = &payload[start..i];
        if field.len() > key.len() && &field[..key.len()] == key { return &field[key.len()..]; }
        i += 1; // skip NUL
    }
    b""
}

#[cfg(feature = "debug-uevent")]
fn uev_comm() {
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b"/");
        klog::write_raw(c.name.as_bytes());
    } else { klog::write_raw(b"?"); }
}

#[cfg(feature = "debug-uevent")]
fn trace_uev_send(cooked: bool, dest_pid: u32, groups: u32, payload: &[u8], path_tag: &[u8], reached: usize) {
    klog::write_raw(b"[UEV-SEND ");
    uev_comm();
    klog::write_raw(b" cooked="); klog::write_dec_u64(cooked as u64);
    klog::write_raw(b" dst_pid="); klog::write_dec_u64(dest_pid as u64);
    klog::write_raw(b" grp="); klog::write_dec_u64(groups as u64);
    klog::write_raw(b" act="); klog::write_raw(uev_kv(payload, b"ACTION="));
    klog::write_raw(b" dp="); klog::write_raw(uev_kv(payload, b"DEVPATH="));
    klog::write_raw(b" -> "); klog::write_raw(path_tag);
    klog::write_raw(b"="); klog::write_dec_u64(reached as u64);
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-uevent")]
fn trace_uev_bind(nl_groups: u32, via: &[u8]) {
    klog::write_raw(b"[UEV-BIND ");
    uev_comm();
    klog::write_raw(b" "); klog::write_raw(via);
    klog::write_raw(b" grp="); klog::write_dec_u64(nl_groups as u64);
    klog::write_raw(b"\n");
}

/// `bind(fd, sockaddr_nl, addrlen)` for netlink. `nl_groups` (offset 8)
/// is the multicast subscription bitmask (legacy RTMGRP_* layout); set
/// it on the socket so rtnl_multicast delivers RTM_NEW*/DEL* notifications
/// (`ip monitor`, systemd-networkd). `nl_pid` autobind is unchanged (the
/// socket keeps its allocated port_id, which getsockname reports).
/// # C: O(1)
pub fn bind(target: &NetlinkFileRef, addr_p: u64) -> i64 {
    if addr_p == 0 || addr_p + 12 >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: addr_p+12 validated < USER_VA_END; sockaddr_nl.nl_groups @ +8.
    let nl_groups = unsafe { core::ptr::read_volatile((addr_p + 8) as *const u32) };
    let s = target.socket();
    s.set_group_mask(nl_groups);
    #[cfg(feature = "debug-uevent")]
    if s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT { trace_uev_bind(nl_groups, b"bind"); }
    0
}

/// `setsockopt(fd, level, optname, optval, optlen)` for netlink. At
/// SOL_NETLINK, NETLINK_ADD_MEMBERSHIP / NETLINK_DROP_MEMBERSHIP take a
/// group NUMBER (RTNLGRP_*) in optval and (un)subscribe the socket so
/// rtnl_multicast reaches it (`ip monitor`, networkd). Other tuning knobs
/// (NETLINK_BROADCAST_ERROR, NETLINK_NO_ENOBUFS, NETLINK_PKTINFO) no-op.
/// # C: O(1)
pub fn setsockopt(target: &NetlinkFileRef, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    const SOL_NETLINK: u64 = 270;
    const NETLINK_ADD_MEMBERSHIP:  u64 = 1;
    const NETLINK_DROP_MEMBERSHIP: u64 = 2;
    if level == SOL_NETLINK
        && (optname == NETLINK_ADD_MEMBERSHIP || optname == NETLINK_DROP_MEMBERSHIP)
    {
        if optval == 0 || optval + 4 > USER_VA_END || optlen < 4 {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: optval+4 validated < USER_VA_END; group is a 4-byte int.
        let group = unsafe { core::ptr::read_volatile(optval as *const u32) };
        let s = target.socket();
        if optname == NETLINK_ADD_MEMBERSHIP { s.add_membership(group); }
        else { s.drop_membership(group); }
        #[cfg(feature = "debug-uevent")]
        if s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT {
            trace_uev_bind(group, if optname == NETLINK_ADD_MEMBERSHIP { b"addmemb" } else { b"dropmemb" });
        }
    }
    0
}

/// `getsockopt(fd, level, optname, optval, optlen)` for netlink.
/// sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it stores
/// the result as the socket's protocol. SO_TYPE → SOCK_RAW. The
/// NETLINK_LIST_MEMBERSHIPS size-query passes optval=NULL (report 0 groups).
/// # C: O(1)
pub fn getsockopt(target: &NetlinkFileRef, level: u64, optname: u64, optval: u64, optlen_p: u64) -> i64 {
    const SOL_SOCKET: u64 = 1;
    const SO_TYPE: u64 = 3;
    const SO_PROTOCOL: u64 = 38;
    const SOL_NETLINK: u64 = 270;
    const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
    if level == SOL_NETLINK && optname == NETLINK_LIST_MEMBERSHIPS {
        if optlen_p != 0 && optlen_p < USER_VA_END {
            // SAFETY: optlen_p validated < USER_VA_END; 4-byte store at CPL=0.
            unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
        }
        return 0;
    }
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it
    // stores the result as the socket's protocol. The reply-pid fix
    // (handle_one stamps nlmsg_pid = port_id; getsockname returns the
    // same) makes sd_netlink accept our rtnl replies, so open + rtnl now
    // work and lo comes up.
    let proto = target.socket().protocol;
    let val: u32 = if level == SOL_SOCKET && optname == SO_PROTOCOL { proto as u32 }
                   else if level == SOL_SOCKET && optname == SO_TYPE { 3 /* SOCK_RAW */ }
                   else { 0 };
    // SAFETY: optval+optlen_p validated < USER_VA_END; 4-byte stores at CPL=0.
    unsafe {
        core::ptr::write_volatile(optval as *mut u32, val);
        core::ptr::write_volatile(optlen_p as *mut u32, 4);
    }
    0
}

/// `getsockname(fd, addr, addrlen)` for netlink. Writes a sockaddr_nl with the
/// socket's stable port ID, matching the ID carried by its replies.
/// # C: O(1)
pub fn getsockname(target: &NetlinkFileRef, addr_p: u64, addrlen_p: u64) -> i64 {
    // nl_pid MUST be the socket's port_id — the same value its replies
    // carry in nlmsg_pid. sd_netlink learns this via getsockname and then
    // drops any reply whose nlmsg_pid differs. Returning current.tid here
    // (≠ the port_id replies use) made every reply mismatch and get
    // dropped.
    use core::sync::atomic::Ordering;
    let pid = target.socket().port_id.load(Ordering::Acquire);
    let sa = encoded_sockaddr_nl(pid as u32, 0);
    copy_sockaddr_to_user(addr_p, addrlen_p, &sa)
}

/// Read the destination multicast group from a user `sockaddr_nl` (nl_groups @
/// +8), or 0 when absent. # C: O(1)
fn dest_nl_groups(dest_p: u64, dest_len: u64) -> u32 {
    if dest_p != 0 && dest_len >= 12 && dest_p + 12 <= USER_VA_END {
        // SAFETY: dest_p+12 validated in-range; nl_groups is a 4-byte field @ +8.
        unsafe { core::ptr::read_volatile((dest_p + 8) as *const u32) }
    } else { 0 }
}

/// Send one coalesced message through an already-resolved netlink file. # C: O(len)
pub fn send_coalesced_file(file: &Arc<vfs::File>, buf: &[u8], name: u64, namelen: u64) -> i64 {
    send_slice(file, buf, dest_nl_groups(name, namelen))
}

/// Core netlink send over a byte slice. A KOBJECT_UEVENT socket carrying a
/// COOKED libudev message (magic "libudev\0" prefix) or a multicast destination
/// re-broadcasts to the monitor group so systemd PID1 / logind receive processed
/// device events (a cooked message is NOT an nlmsghdr). The cooked datagram is
/// header+properties across MULTIPLE `sendmsg` iovecs — it must be coalesced
/// (see `sys_sendmsg`) so the whole libudev message reaches the monitor as one
/// datagram, not split into a header-only + properties-only pair that logind
/// can't parse (card0 add lost → seat0 never CanGraphical → no greeter).
/// # C: O(len)
fn send_slice(file: &alloc::sync::Arc<vfs::File>, buf: &[u8], dest_groups: u32) -> i64 {
    if let Some(s) = file.inode().private::<::netlink::NetlinkSocket>() {
        let is_uevent = s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT;
        let is_cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
        if is_uevent && (is_cooked || dest_groups != 0) {
            let _reached = ::netlink::rebroadcast_cooked_uevent(buf, dest_groups, s);
            #[cfg(feature = "debug-uevent")]
            trace_uev_send(is_cooked, 0, dest_groups, buf, b"rebc", _reached);
            return buf.len() as i64;
        }
    }
    match file.inode().write(0, buf) {
        Ok(n) => n as i64,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}

/// Kernel-snapshot `sendmsg` for netlink. Unlike the generic fallback,
/// this preserves datagram boundaries across iovecs and passes
/// sockaddr_nl.nl_groups into the netlink layer so userspace-originated
/// multicast, especially systemd-udevd's cooked kobject uevents, reaches
/// monitor subscribers.
/// # C: O(iov + payload bytes)
pub fn sendmsg_imported(file: &Arc<vfs::File>, name: &[u8], payload: &[u8]) -> i64 {
    let sock = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(s) => s,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let (groups, dest_pid) = if !name.is_empty() {
        if name.len() < 12 { return -(Errno::Einval.as_i32() as i64); }
        if u16::from_ne_bytes(name[..2].try_into().unwrap()) != 16 {
            return -(Errno::Eafnosupport.as_i32() as i64);
        }
        (u32::from_ne_bytes(name[8..12].try_into().unwrap()),
            u32::from_ne_bytes(name[4..8].try_into().unwrap()))
    } else {
        (0, 0)
    };
    // UNICAST to a specific port (Linux `netlink_unicast`): systemd-udevd's
    // worker signals event COMPLETION to the manager by addressing the cooked
    // device to the manager's netlink port (nl_pid != 0, nl_groups = 0). Honour
    // it — a group broadcast never reaches the manager's per-event socket, so it
    // re-dispatched each event ~20× (starving card0 → CAN_GRAPHICAL=0). Group
    // broadcasts (nl_pid = 0) keep the write_to_groups path.
    if sock.protocol == 15 && dest_pid != 0 && groups == 0 {
        let src = sock.port_id.load(core::sync::atomic::Ordering::Acquire);
        let _reached = ::netlink::unicast_uevent_to_port(dest_pid, payload, src);
        #[cfg(feature = "debug-uevent")]
        { let cooked = payload.len() >= 8 && &payload[..8] == b"libudev\0";
          trace_uev_send(cooked, dest_pid, groups, &payload, b"uni", _reached); }
        return payload.len() as i64;
    }
    // uevent cooked/group broadcast (manager → monitors): call the rebroadcast
    // directly (equivalent to write_to_groups' cooked path) so the reach count is
    // observable for the debug trace. Non-uevent / non-cooked falls through.
    if sock.protocol == 15 {
        let cooked = payload.len() >= 8 && &payload[..8] == b"libudev\0";
        if cooked || groups != 0 {
            let _reached = ::netlink::rebroadcast_cooked_uevent(payload, groups, sock);
            #[cfg(feature = "debug-uevent")]
            trace_uev_send(cooked, dest_pid, groups, &payload, b"bcast", _reached);
            return payload.len() as i64;
        }
    }
    match sock.write_to_groups(payload, groups) {
        Ok(n) => n as i64,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}
