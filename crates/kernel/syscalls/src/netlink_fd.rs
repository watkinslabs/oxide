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
/// (`ip monitor`, systemd-networkd). `nl_pid` claims one canonical live port
/// ID in the socket's namespace and protocol domain.
/// # C: O(1)
pub fn bind(target: &NetlinkFileRef, addr_p: u64, addrlen: usize) -> i64 {
    const SOCKADDR_FAMILY_BYTES: usize = core::mem::size_of::<u16>();
    if addrlen < ::netlink::SOCKADDR_NL_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let mut address = [0u8; ::netlink::SOCKADDR_NL_SIZE];
    if uaccess::copy_from_user(&mut address, addr_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
    let family = u16::from_ne_bytes(address[..SOCKADDR_FAMILY_BYTES].try_into().unwrap());
    if family != ::netlink::AF_NETLINK { return -(Errno::Einval.as_i32() as i64); }
    let port_id = u32::from_ne_bytes(address[::netlink::SOCKADDR_NL_PORT_ID_OFFSET
        ..::netlink::SOCKADDR_NL_PORT_ID_OFFSET + core::mem::size_of::<u32>()].try_into().unwrap());
    let nl_groups = u32::from_ne_bytes(address[::netlink::SOCKADDR_NL_GROUPS_OFFSET
        ..::netlink::SOCKADDR_NL_GROUPS_OFFSET + core::mem::size_of::<u32>()].try_into().unwrap());
    let s = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&s.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Bind)
    { return crate::net_common::errno_from_neterr(error); }
    if let Err(error) = ::netlink::bind_port_id(s, port_id) {
        return crate::net_common::errno_from_neterr(error);
    }
    s.set_group_mask(nl_groups);
    #[cfg(feature = "debug-uevent")]
    if s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT { trace_uev_bind(nl_groups, b"bind"); }
    0
}

/// `connect(fd, sockaddr_nl, addrlen)` for Netlink. Linux persists the
/// destination in the socket, selects only the first multicast group, and
/// clears both fields for AF_UNSPEC. # C: O(1)
pub fn connect(target: &NetlinkFileRef, addr_p: u64, addrlen: usize) -> i64 {
    const SOCKADDR_FAMILY_BYTES: usize = core::mem::size_of::<u16>();
    if addrlen < SOCKADDR_FAMILY_BYTES { return -(Errno::Einval.as_i32() as i64); }
    let mut family = [0u8; SOCKADDR_FAMILY_BYTES];
    if uaccess::copy_from_user(&mut family, addr_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
    let family = u16::from_ne_bytes(family);
    let socket = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Connect)
    { return crate::net_common::errno_from_neterr(error); }
    if family as u32 == net::socket_args::AF_UNSPEC {
        return socket.disconnect_destination().map_or_else(crate::net_common::errno_from_neterr, |_| 0);
    }
    if family != ::netlink::AF_NETLINK { return -(Errno::Einval.as_i32() as i64); }
    if addrlen < ::netlink::SOCKADDR_NL_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let mut address = [0u8; ::netlink::SOCKADDR_NL_SIZE];
    if uaccess::copy_from_user(&mut address, addr_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
    let port_id = u32::from_ne_bytes(address[4..8].try_into().unwrap());
    let groups = u32::from_ne_bytes(address[8..12].try_into().unwrap());
    socket.connect_destination(port_id, groups).map_or_else(crate::net_common::errno_from_neterr, |_| 0)
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
    let socket = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Option)
    { return crate::net_common::errno_from_neterr(error); }
    if level == SOL_NETLINK
        && (optname == NETLINK_ADD_MEMBERSHIP || optname == NETLINK_DROP_MEMBERSHIP)
    {
        if optval == 0 || optval + 4 > USER_VA_END || optlen < 4 {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: optval+4 validated < USER_VA_END; group is a 4-byte int.
        let group = unsafe { core::ptr::read_volatile(optval as *const u32) };
        let s = socket;
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
    let socket = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Option)
    { return crate::net_common::errno_from_neterr(error); }
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
    let proto = socket.protocol;
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

/// `getsockname(fd, addr, addrlen)` for netlink. Writes the socket's stable
/// port ID and current bound multicast-group mask. # C: O(1)
pub fn getsockname(target: &NetlinkFileRef, addr_p: u64, addrlen_p: u64) -> i64 {
    if let Err(e) = net::security_admission::check(
        net::net_ns::namespace_id(&target.socket().net_ns),
        net::socket_args::AF_NETLINK_WIRE,
        security::network::Operation::NameQuery,
    ) {
        return crate::net_common::errno_from_neterr(e);
    }
    // nl_pid MUST be the socket's port_id — the same value its replies
    // carry in nlmsg_pid. sd_netlink learns this via getsockname and then
    // drops any reply whose nlmsg_pid differs. Returning current.tid here
    // (≠ the port_id replies use) made every reply mismatch and get
    // dropped.
    use core::sync::atomic::Ordering;
    let socket = target.socket();
    let pid = socket.port_id.load(Ordering::Acquire);
    let groups = socket.groups.load(Ordering::Acquire);
    let sa = encoded_sockaddr_nl(pid, groups);
    copy_sockaddr_to_user(addr_p, addrlen_p, &sa)
}

/// `getpeername(fd, sockaddr_nl, addrlen)` for Netlink. Linux
/// `netlink_getname(peer=true)` exposes the current destination; a newly
/// created, unconnected socket has the canonical zero port and group values.
/// # C: O(1)
pub fn getpeername(target: &NetlinkFileRef, addr_p: u64, addrlen_p: u64) -> i64 {
    if let Err(e) = net::security_admission::check(
        net::net_ns::namespace_id(&target.socket().net_ns),
        net::socket_args::AF_NETLINK_WIRE,
        security::network::Operation::NameQuery,
    ) {
        return crate::net_common::errno_from_neterr(e);
    }
    let (port_id, groups) = target.socket().destination();
    let sa = encoded_sockaddr_nl(port_id, groups);
    copy_sockaddr_to_user(addr_p, addrlen_p, &sa)
}

/// Read the destination port and group mask from an already validated
/// `sockaddr_nl`, or report that no destination was supplied. # C: O(1)
fn dest_nl_address(dest_p: u64, dest_len: u64) -> Option<(u32, u32)> {
    let address_bytes = ::netlink::SOCKADDR_NL_SIZE as u64;
    let end = dest_p.checked_add(address_bytes)?;
    if dest_p == 0 || dest_len < address_bytes || end > USER_VA_END { return None; }
    // SAFETY: the complete sockaddr_nl range is user-address-valid for both typed loads.
    unsafe {
        let groups = core::ptr::read_volatile((dest_p + ::netlink::SOCKADDR_NL_GROUPS_OFFSET as u64) as *const u32);
        let port_id = core::ptr::read_volatile((dest_p + ::netlink::SOCKADDR_NL_PORT_ID_OFFSET as u64) as *const u32);
        Some((groups, port_id))
    }
}

/// Send one coalesced message through an already-resolved netlink file. # C: O(len)
pub fn send_coalesced_file(file: &Arc<vfs::File>, buf: &[u8], name: u64, namelen: u64) -> i64 {
    let socket = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(socket) => socket,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Send)
    { return crate::net_common::errno_from_neterr(error); }
    let (groups, port_id) = dest_nl_address(name, namelen).unwrap_or_else(|| socket.destination());
    let result = socket.send_to(buf, groups, port_id);
    // Keep the diagnostic path available after coalesced sends moved to the
    // canonical destination owner. It is intentionally feature-gated, like
    // the imported-send trace, rather than being removed or made unconditional.
    #[cfg(feature = "debug-uevent")]
    {
        let cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
        let delivered = usize::from(result.is_ok());
        trace_uev_send(cooked, port_id, groups, buf, b"owner", delivered);
    }
    match result {
        Ok(n) => n as i64,
        Err(::netlink::SendError::Emsgsize) => -(Errno::Emsgsize.as_i32() as i64),
        Err(::netlink::SendError::Backend(error)) => -(error as i64),
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
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&sock.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Send)
    { return crate::net_common::errno_from_neterr(error); }
    let (groups, dest_pid) = if !name.is_empty() {
        if name.len() < ::netlink::SOCKADDR_NL_SIZE { return -(Errno::Einval.as_i32() as i64); }
        if u16::from_ne_bytes(name[..2].try_into().unwrap()) != net::socket_args::AF_NETLINK_WIRE {
            return -(Errno::Eafnosupport.as_i32() as i64);
        }
        (u32::from_ne_bytes(name[8..12].try_into().unwrap()),
            u32::from_ne_bytes(name[4..8].try_into().unwrap()))
    } else { sock.destination() };
    let result = sock.send_to(payload, groups, dest_pid);
    #[cfg(feature = "debug-uevent")]
    {
        let cooked = payload.len() >= 8 && &payload[..8] == b"libudev\0";
        let delivered = usize::from(result.is_ok());
        trace_uev_send(cooked, dest_pid, groups, payload, b"owner", delivered);
    }
    match result {
        Ok(n) => n as i64,
        Err(::netlink::SendError::Emsgsize) => -(Errno::Emsgsize.as_i32() as i64),
        Err(::netlink::SendError::Backend(error)) => -(error as i64),
    }
}
