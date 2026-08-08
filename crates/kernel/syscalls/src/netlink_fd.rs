// F132: netlink-fd shims for socket-shaped syscalls.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;

// SOL_SOCKET is answered before family dispatch, never by the family table.
pub mod sol_socket;

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
        { let comm = c.comm_bytes(); klog::write_raw(sched::Task::comm_trim(&comm).as_bytes()); }
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
pub fn bind(target: &NetlinkFileRef, storage: &net::SockaddrStorage) -> i64 {
    const SOCKADDR_FAMILY_BYTES: usize = core::mem::size_of::<u16>();
    let address = storage.as_bytes();
    if address.len() < ::netlink::SOCKADDR_NL_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    let family = u16::from_ne_bytes(address[..SOCKADDR_FAMILY_BYTES].try_into().unwrap());
    if family != ::netlink::AF_NETLINK { return -(Errno::Einval.as_i32() as i64); }
    let port_id = u32::from_ne_bytes(address[::netlink::SOCKADDR_NL_PORT_ID_OFFSET
        ..::netlink::SOCKADDR_NL_PORT_ID_OFFSET + core::mem::size_of::<u32>()].try_into().unwrap());
    let nl_groups = u32::from_ne_bytes(address[::netlink::SOCKADDR_NL_GROUPS_OFFSET
        ..::netlink::SOCKADDR_NL_GROUPS_OFFSET + core::mem::size_of::<u32>()].try_into().unwrap());
    let s = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&s.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Bind)
    { return crate::net_errno::errno_from_neterr(error); }
    if let Err(error) = ::netlink::bind_port_id(s, port_id) {
        return crate::net_errno::errno_from_neterr(error);
    }
    s.set_group_mask(nl_groups);
    #[cfg(feature = "debug-uevent")]
    if s.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT { trace_uev_bind(nl_groups, b"bind"); }
    0
}

/// `connect(fd, sockaddr_nl, addrlen)` for Netlink. Linux persists the
/// destination in the socket, selects only the first multicast group, and
/// clears both fields for AF_UNSPEC. # C: O(1)
pub fn connect(target: &NetlinkFileRef, storage: &net::SockaddrStorage) -> i64 {
    const SOCKADDR_FAMILY_BYTES: usize = core::mem::size_of::<u16>();
    let address = storage.as_bytes();
    if address.len() < SOCKADDR_FAMILY_BYTES { return -(Errno::Einval.as_i32() as i64); }
    let family = u16::from_ne_bytes(address[..SOCKADDR_FAMILY_BYTES].try_into().unwrap());
    let socket = target.socket();
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Connect)
    { return crate::net_errno::errno_from_neterr(error); }
    if family as u32 == net::socket_args::AF_UNSPEC {
        return socket.disconnect_destination().map_or_else(crate::net_errno::errno_from_neterr, |_| 0);
    }
    if family != ::netlink::AF_NETLINK { return -(Errno::Einval.as_i32() as i64); }
    if address.len() < ::netlink::SOCKADDR_NL_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    let port_id = u32::from_ne_bytes(address[4..8].try_into().unwrap());
    let groups = u32::from_ne_bytes(address[8..12].try_into().unwrap());
    socket.connect_destination(port_id, groups).map_or_else(crate::net_errno::errno_from_neterr, |_| 0)
}

/// `setsockopt(fd, level, optname, optval, optlen)` for netlink. At
/// SOL_NETLINK, NETLINK_ADD_MEMBERSHIP / NETLINK_DROP_MEMBERSHIP take a
/// group NUMBER (RTNLGRP_*) in optval and (un)subscribe the socket so
/// rtnl_multicast reaches it (`ip monitor`, networkd). `NETLINK_NO_ENOBUFS`
/// controls the socket-owned multicast-overrun error report.
/// # C: O(1)
pub fn setsockopt(target: &NetlinkFileRef, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    use ::netlink::{sockopt, SetAction};
    const NETLINK_OPTION_BYTES: u64 = core::mem::size_of::<u32>() as u64;
    let socket = target.socket();
    if let Err(error) = net::socket_security::option::setsockopt(
        net::socket_security::option::OptSock::plain(
            net::net_ns::namespace_id(&socket.net_ns), net::socket_args::AF_NETLINK_WIRE),
        level as i32, optname as i32)
    { return crate::net_errno::errno_from_neterr(error); }
    // The family table owns its own level and nothing else: SOL_SOCKET was
    // already answered generically before dispatch, and every other level is
    // ENOPROTOOPT.
    if level != sockopt::SOL_NETLINK { return -(Errno::Enoprotoopt.as_i32() as i64); }
    // Netlink reads the value only when the caller supplied a whole `int`; a
    // shorter option is not an error, it simply leaves the value zero.
    let mut val: u32 = 0;
    if optlen >= NETLINK_OPTION_BYTES {
        if optval == 0 || optval + NETLINK_OPTION_BYTES > USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        let mut raw = [0u8; core::mem::size_of::<u32>()];
        if uaccess::copy_from_user(&mut raw, optval).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        val = u32::from_ne_bytes(raw);
    }
    match ::netlink::set_action(optname) {
        SetAction::Unknown => -(Errno::Enoprotoopt.as_i32() as i64),
        SetAction::Flag(bit) => { socket.flags.assign(bit, val != 0); 0 }
        SetAction::PrivilegedFlag(bit) => {
            if !has_net_broadcast(socket) { return -(Errno::Eperm.as_i32() as i64); }
            socket.flags.assign(bit, val != 0);
            0
        }
        SetAction::NoEnobufs => { socket.set_no_enobufs(val != 0); 0 }
        SetAction::Membership { add } => {
            if !::netlink::nonroot_recv(socket.protocol) && !has_net_admin(socket) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            let membership = if add { socket.add_membership(val) } else { socket.drop_membership(val) };
            if let Err(error) = membership { return crate::net_errno::errno_from_neterr(error); }
            #[cfg(feature = "debug-uevent")]
            if socket.protocol == ::netlink::proto::NETLINK_KOBJECT_UEVENT {
                trace_uev_bind(val, if add { b"addmemb" } else { b"dropmemb" });
            }
            0
        }
    }
}

/// `CAP_NET_BROADCAST` in the user namespace owning the socket's network
/// namespace, gating `NETLINK_LISTEN_ALL_NSID`. # C: O(ns depth)
fn has_net_broadcast(socket: &::netlink::NetlinkSocket) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    { sched::current().is_some_and(|cur| nscg::has_cap_for(cur,
        &socket.net_ns.owner_user_namespace(), sched::cap::NET_BROADCAST)) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = socket; true }
}

/// `CAP_NET_ADMIN` for a protocol that does not declare unprivileged
/// multicast subscription. # C: O(ns depth)
fn has_net_admin(socket: &::netlink::NetlinkSocket) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    { sched::current().is_some_and(|cur| nscg::has_net_admin_for(cur, &socket.net_ns)) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = socket; true }
}

/// `getsockopt(fd, level, optname, optval, optlen)` for netlink.
/// sd_netlink_open REQUIRES getsockopt(SOL_SOCKET, SO_PROTOCOL) — it stores
/// the result as the socket's protocol. SO_TYPE → SOCK_RAW.
/// # C: O(1)
pub fn getsockopt(target: &NetlinkFileRef, level: u64, optname: u64, optval: u64, optlen_p: u64) -> i64 {
    const NETLINK_SCALAR_BYTES: usize = core::mem::size_of::<u32>();
    let socket = target.socket();
    if let Err(error) = net::socket_security::option::getsockopt(
        net::socket_security::option::OptSock::plain(
            net::net_ns::namespace_id(&socket.net_ns), net::socket_args::AF_NETLINK_WIRE),
        level as i32, optname as i32)
    { return crate::net_errno::errno_from_neterr(error); }
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let requested = match crate::netlink_getsockopt_policy::requested_len(raw_len) {
        Ok(requested) => requested,
        Err(error) => return -(error.as_i32() as i64),
    };
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if level == net::uapi::SOL_SOCKET {
        // The generic table truncates the answer to what the caller asked for
        // and publishes the truncated length, exactly as it does for every
        // other family — a short buffer is not an error here.
        return match sol_socket::get(target, optname, requested) {
            Some(Ok(value)) => {
                let take = core::cmp::min(requested, value.len());
                netlink_getsockopt_copyout(optval, optlen_p, &value[..take], take)
            }
            Some(Err(e)) => e,
            None => -(Errno::Enoprotoopt.as_i32() as i64),
        };
    }
    let copied = match (level, optname) {
        (::netlink::sockopt::SOL_NETLINK, name) => match ::netlink::get_answer(name) {
            ::netlink::GetAnswer::Unknown => return -(Errno::Enoprotoopt.as_i32() as i64),
            ::netlink::GetAnswer::Memberships => {
                bytes = netlink_membership_words(socket.membership_words());
                crate::netlink_getsockopt_policy::whole_words(requested, bytes.len())
            }
            ::netlink::GetAnswer::Flag(bit) => {
                if requested < NETLINK_SCALAR_BYTES { return -(Errno::Einval.as_i32() as i64); }
                bytes.extend_from_slice(&(socket.flags.get(bit) as u32).to_ne_bytes());
                NETLINK_SCALAR_BYTES
            }
        },
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    };
    // The published length is the option's own full length, which is how a
    // caller discovers the buffer a truncated membership list needs.
    netlink_getsockopt_copyout(optval, optlen_p, &bytes[..copied], bytes.len())
}

/// Encode NETLINK's canonical membership bitmap as its Linux ABI words: one
/// `u32` per 32 groups the protocol offers, and the FULL length reported back
/// through optlen even when only a prefix fits. # C: O(words)
fn netlink_membership_words(words: alloc::vec::Vec<u32>) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(words.len() * core::mem::size_of::<u32>());
    for word in words { out.extend_from_slice(&word.to_ne_bytes()); }
    out
}

/// Copy one NETLINK getsockopt result, then report the length the option
/// publishes — which is not always the number of bytes copied. # C: O(len)
fn netlink_getsockopt_copyout(optval: u64, optlen_p: u64, value: &[u8], publish: usize) -> i64 {
    if !value.is_empty() && uaccess::copy_to_user(optval, value).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let Ok(required) = i32::try_from(publish) else { return -(Errno::Einval.as_i32() as i64); };
    if uaccess::copy_to_user(optlen_p, &required.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
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
        return crate::net_errno::errno_from_neterr(e);
    }
    // nl_pid MUST be the socket's port_id — the same value its replies
    // carry in nlmsg_pid. sd_netlink learns this via getsockname and then
    // drops any reply whose nlmsg_pid differs. Returning current.tid here
    // (≠ the port_id replies use) made every reply mismatch and get
    // dropped.
    use core::sync::atomic::Ordering;
    let socket = target.socket();
    let pid = socket.port_id.load(Ordering::Acquire);
    let groups = socket.groups.low_mask();
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
        return crate::net_errno::errno_from_neterr(e);
    }
    let dest = target.socket().destination();
    let sa = encoded_sockaddr_nl(dest.port_id, dest.group);
    copy_sockaddr_to_user(addr_p, addrlen_p, &sa)
}

/// Copy an optional user `sockaddr_nl` into kernel memory. `None` means no
/// destination was supplied, which is not an error — the socket's connected
/// destination is used instead. # C: O(1)
fn user_sockaddr_nl(dest_p: u64, dest_len: u64) -> Option<[u8; ::netlink::SOCKADDR_NL_SIZE]> {
    let address_bytes = ::netlink::SOCKADDR_NL_SIZE as u64;
    let end = dest_p.checked_add(address_bytes)?;
    if dest_p == 0 || dest_len < address_bytes || end > USER_VA_END { return None; }
    let mut name = [0u8; ::netlink::SOCKADDR_NL_SIZE];
    for (index, byte) in name.iter_mut().enumerate() {
        // SAFETY: the complete sockaddr_nl range was bounds-checked against
        // USER_VA_END above, so every byte of this read is user-address-valid.
        *byte = unsafe { core::ptr::read_volatile((dest_p + index as u64) as *const u8) };
    }
    Some(name)
}

/// Send one coalesced message through an already-resolved netlink file. # C: O(len)
pub fn send_coalesced_file(file: &Arc<vfs::File>, buf: &[u8], name: u64, namelen: u64) -> i64 {
    let socket = match file.inode().private::<::netlink::NetlinkSocket>() {
        Some(socket) => socket,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if let Err(error) = net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, security::network::Operation::Send)
    { return crate::net_errno::errno_from_neterr(error); }
    let dest = match user_sockaddr_nl(name, namelen) {
        Some(name) => match ::netlink::parse_dest(&name) {
            Ok(dest) => dest,
            Err(error) => return -(error as i64),
        },
        None => socket.destination(),
    };
    let result = socket.send_to(buf, dest);
    // Keep the diagnostic path available after coalesced sends moved to the
    // canonical destination owner. It is intentionally feature-gated, like
    // the imported-send trace, rather than being removed or made unconditional.
    #[cfg(feature = "debug-uevent")]
    {
        let cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
        let delivered = usize::from(result.is_ok());
        trace_uev_send(cooked, dest.port_id, dest.group, buf, b"owner", delivered);
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
    { return crate::net_errno::errno_from_neterr(error); }
    let dest = if name.is_empty() { sock.destination() } else {
        match ::netlink::parse_dest(name) {
            Ok(dest) => dest,
            Err(error) => return -(error as i64),
        }
    };
    let result = sock.send_to(payload, dest);
    #[cfg(feature = "debug-uevent")]
    {
        let cooked = payload.len() >= 8 && &payload[..8] == b"libudev\0";
        let delivered = usize::from(result.is_ok());
        trace_uev_send(cooked, dest.port_id, dest.group, payload, b"owner", delivered);
    }
    match result {
        Ok(n) => n as i64,
        Err(::netlink::SendError::Emsgsize) => -(Errno::Emsgsize.as_i32() as i64),
        Err(::netlink::SendError::Backend(error)) => -(error as i64),
    }
}
