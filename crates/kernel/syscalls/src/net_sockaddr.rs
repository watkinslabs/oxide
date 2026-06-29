// P5-01: sockaddr parse/format helpers — extracted from net.rs to
// stay under the 1000-line cap (docs/08§7). All helpers are
// pub(crate); net.rs and net_recv.rs consume them.

use hal::USER_VA_END;
use net::sock::InetSocket;

const AF_INET:  u32 = 2;
const AF_INET6: u32 = 10;
const AF_UNIX:  u16 = 1;

/// Write a `sockaddr_un` (family + sun_path) at user pointer `ptr`. An
/// abstract address (leading NUL) writes its name after the family with the
/// leading NUL preserved; a pathname address writes the path + a trailing
/// NUL. `None`/empty path writes the bare 2-byte family (unbound socket).
/// Caller's `getsockname` keeps the in/out addrlen the caller passed, which
/// is what `sd_is_socket` relies on. # C: O(path len)
pub(crate) fn write_sockaddr_un(ptr: u64, path: Option<&str>) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    // SAFETY: ptr validated in user range; caller AS active; bounded writes within sockaddr_un (2 + 108).
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_UNIX);
        let bytes = path.unwrap_or("").as_bytes();
        let n = core::cmp::min(bytes.len(), 108);
        for i in 0..n {
            core::ptr::write_volatile((ptr + 2 + i as u64) as *mut u8, bytes[i]);
        }
        if n < 108 {
            core::ptr::write_volatile((ptr + 2 + n as u64) as *mut u8, 0);
        }
    }
}

/// Read sa_family (first 2 bytes) at user pointer `ptr`. # C: O(1)
pub(crate) fn read_sa_family(ptr: u64) -> Option<u16> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS).
    unsafe { Some(core::ptr::read_volatile(ptr as *const u16)) }
}

/// Read sockaddr_un path. Filesystem paths are NUL-terminated; Linux
/// abstract namespace paths preserve the addrlen-delimited leading NUL
/// marker. # C: O(108)
pub(crate) fn read_sockaddr_un_path_len(ptr: u64, addrlen: u64) -> Option<alloc::string::String> {
    if ptr == 0 || ptr >= USER_VA_END || addrlen <= 2 { return None; }
    let path_len = (addrlen - 2).min(108) as usize;
    // SAFETY: ptr in user range; caller's address space is active; read is bounded by sockaddr_un.
    unsafe {
        let p = (ptr + 2) as *const u8;
        let first = core::ptr::read_volatile(p);
        let mut bytes = alloc::vec::Vec::new();
        if first == 0 {
            for i in 0..path_len {
                bytes.push(core::ptr::read_volatile(p.add(i)));
            }
            while bytes.len() > 1 && bytes.last().copied() == Some(0) { bytes.pop(); }
        } else {
            bytes.push(first);
            for i in 1..path_len {
                let b = core::ptr::read_volatile(p.add(i));
                if b == 0 { break; }
                bytes.push(b);
            }
        }
        alloc::string::String::from_utf8(bytes).ok()
    }
}

/// Read sockaddr_in (v4): (family, port_host, addr_host). # C: O(1)
pub(crate) fn read_sockaddr_in(ptr: u64) -> Option<(u32, u16, u32)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte aligned read.
    unsafe {
        let family = core::ptr::read_volatile(ptr as *const u16) as u32;
        let port_be = core::ptr::read_volatile((ptr + 2) as *const u16);
        let addr_be = core::ptr::read_volatile((ptr + 4) as *const u32);
        Some((family, u16::from_be(port_be), u32::from_be(addr_be)))
    }
}

/// Write a sockaddr_in (v4) at `ptr`. # C: O(1)
pub(crate) fn write_sockaddr_in(ptr: u64, addr_be: u32, port_be: u16) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte writes.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_INET as u16);
        core::ptr::write_volatile((ptr + 2) as *mut u16, port_be);
        core::ptr::write_volatile((ptr + 4) as *mut u32, addr_be);
        core::ptr::write_volatile((ptr + 8) as *mut u64, 0);
    }
}

/// Read sockaddr_in6 (28 B). Returns (family, port_host, addr_bytes, scope_id). # C: O(1)
pub(crate) fn read_sockaddr_in6(ptr: u64) -> Option<(u32, u16, [u8; 16], u32)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    if ptr.checked_add(28).map_or(true, |e| e >= USER_VA_END) { return None; }
    // SAFETY: 28 bytes inside validated range; caller's AS active.
    unsafe {
        let family   = core::ptr::read_volatile(ptr as *const u16) as u32;
        let port_be  = core::ptr::read_volatile((ptr + 2) as *const u16);
        let _flow    = core::ptr::read_volatile((ptr + 4) as *const u32);
        let mut a = [0u8; 16];
        for i in 0..16 {
            a[i] = core::ptr::read_volatile((ptr + 8 + i as u64) as *const u8);
        }
        let scope    = core::ptr::read_volatile((ptr + 24) as *const u32);
        Some((family, u16::from_be(port_be), a, scope))
    }
}

/// Write a sockaddr_in6 (28 B) at `ptr`. # C: O(1)
pub(crate) fn write_sockaddr_in6(ptr: u64, addr_bytes: [u8; 16], port_be: u16, scope_id: u32) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    if ptr.checked_add(28).map_or(true, |e| e >= USER_VA_END) { return; }
    // SAFETY: 28 bytes inside validated range; caller's AS active.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_INET6 as u16);
        core::ptr::write_volatile((ptr + 2) as *mut u16, port_be);
        core::ptr::write_volatile((ptr + 4) as *mut u32, 0); // flowinfo
        for i in 0..16 {
            core::ptr::write_volatile((ptr + 8 + i as u64) as *mut u8, addr_bytes[i]);
        }
        core::ptr::write_volatile((ptr + 24) as *mut u32, scope_id);
    }
}

/// D3.3: read sockaddr_vm (AF_VSOCK, 16 B). Layout per Linux uapi
/// `struct sockaddr_vm`: svm_family u16 @0, svm_reserved1 u16 @2,
/// svm_port u32 @4, svm_cid u32 @8 (Linux CID is u32 but the wire
/// protocol carries u64; we widen). Returns (family, port, cid).
/// # C: O(1)
pub(crate) fn read_sockaddr_vm(ptr: u64) -> Option<(u16, u32, u64)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    if ptr.checked_add(16).map_or(true, |e| e >= USER_VA_END) { return None; }
    // SAFETY: 16 bytes inside validated user range; caller's AS active.
    unsafe {
        let family = core::ptr::read_volatile(ptr as *const u16);
        let port   = core::ptr::read_volatile((ptr + 4) as *const u32);
        let cid    = core::ptr::read_volatile((ptr + 8) as *const u32);
        Some((family, port, cid as u64))
    }
}

/// D3.3: write sockaddr_vm (16 B) at `ptr` (accept/getpeername).
/// # C: O(1)
pub(crate) fn write_sockaddr_vm(ptr: u64, port: u32, cid: u64) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    if ptr.checked_add(16).map_or(true, |e| e >= USER_VA_END) { return; }
    const AF_VSOCK: u16 = 40;
    // SAFETY: 16 bytes inside validated range; caller's AS active.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_VSOCK);
        core::ptr::write_volatile((ptr + 2) as *mut u16, 0u16);
        core::ptr::write_volatile((ptr + 4) as *mut u32, port);
        core::ptr::write_volatile((ptr + 8) as *mut u32, cid as u32);
        core::ptr::write_volatile((ptr + 12) as *mut u32, 0u32);
    }
}

/// IPv4-mapped check (`::ffff:a.b.c.d`).
/// Used to thread V6 sockets through the V4 transport for v1. # C: O(1)
pub(crate) fn ipv4_from_v6_mapped(b: &[u8; 16]) -> Option<net::Ipv4Addr> {
    let prefix_zeros = b[0..10].iter().all(|&x| x == 0);
    let prefix_ff    = b[10] == 0xff && b[11] == 0xff;
    if prefix_zeros && prefix_ff {
        Some(net::Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else { None }
}

/// True for the IPv6 loopback address `::1`. # C: O(1)
pub(crate) fn ipv6_loopback(b: &[u8; 16]) -> bool {
    b[..15].iter().all(|&x| x == 0) && b[15] == 1
}

/// True for the IPv6 unspecified address `::`. # C: O(1)
pub(crate) fn ipv6_unspecified(b: &[u8; 16]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Read sockaddr_in (v4) or sockaddr_in6 (v6). Returns V4-equivalent
/// (V4 → as-is, ::1 → 127.0.0.1, :: → ANY, ::ffff:a.b.c.d → V4 mapped).
/// Native v6 returns None — caller routes through tcp_connect_ip. # C: O(1)
pub(crate) fn read_sockaddr_any(ptr: u64) -> Option<(u32, net::Ipv4Addr, u16)> {
    let fam = read_sa_family(ptr)? as u32;
    if fam == AF_INET {
        let (_, port, addr_host) = read_sockaddr_in(ptr)?;
        Some((fam, net::Ipv4Addr::from_u32(addr_host), port))
    } else if fam == AF_INET6 {
        let (_, port, b, _) = read_sockaddr_in6(ptr)?;
        if let Some(v4) = ipv4_from_v6_mapped(&b) { return Some((fam, v4, port)); }
        if ipv6_loopback(&b)    { return Some((fam, net::Ipv4Addr::LOOPBACK, port)); }
        if ipv6_unspecified(&b) { return Some((fam, net::Ipv4Addr::ANY, port)); }
        None
    } else { None }
}

/// Write sockaddr at `ptr` per sock family (V4 → in, V6 → in6 with
/// mapped/::1/:: synthesis when sock holds V4 state). # C: O(1)
pub(crate) fn write_sockaddr_for_socket(ptr: u64, sock: &InetSocket, ip: net::Ipv4Addr, port: u16) {
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if fam == net::sock::AF_UNIX {
        // getsockname on an AF_UNIX socket must report sa_family=AF_UNIX +
        // the bound sun_path. systemd-udevd's sd_is_socket(fd, AF_UNIX, …)
        // family check (listen_fds) fails — returning -EINVAL — if we fall
        // through to the AF_INET writer below.
        let path = net::sock::unix_local_path(sock);
        write_sockaddr_un(ptr, path.as_deref());
        return;
    }
    if fam == net::sock::AF_INET6 {
        let mut b = [0u8; 16];
        if ip == net::Ipv4Addr::LOOPBACK {
            b[15] = 1; // ::1
        } else if ip == net::Ipv4Addr::ANY {
            // :: stays all-zero.
        } else {
            // V4-mapped form: ::ffff:a.b.c.d
            b[10] = 0xff; b[11] = 0xff;
            let v = ip.as_u32();
            b[12] = (v >> 24) as u8;
            b[13] = (v >> 16) as u8;
            b[14] = (v >>  8) as u8;
            b[15] =  v        as u8;
        }
        write_sockaddr_in6(ptr, b, port.to_be(), 0);
    } else {
        write_sockaddr_in(ptr, ip.as_u32().to_be(), port.to_be());
    }
}

/// Write a sockaddr_in6 from a genuine IPv6 source address (the recv
/// path's `peer6`), as opposed to the V4-state synthesis above.
/// # C: O(1)
pub(crate) fn write_sockaddr_in6_peer(ptr: u64, ip: net::Ipv6Addr, port: u16) {
    write_sockaddr_in6(ptr, ip.0, port.to_be(), 0);
}
