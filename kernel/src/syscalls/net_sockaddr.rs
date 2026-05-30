// P5-01: sockaddr parse/format helpers — extracted from net.rs to
// stay under the 1000-line cap (docs/08§7). All helpers are
// pub(crate); net.rs and net_recv.rs consume them.

use hal::USER_VA_END;
use net::sock::InetSocket;

const AF_INET:  u32 = 2;
const AF_INET6: u32 = 10;

/// Read sa_family (first 2 bytes) at user pointer `ptr`. # C: O(1)
pub(crate) fn read_sa_family(ptr: u64) -> Option<u16> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS).
    unsafe { Some(core::ptr::read_volatile(ptr as *const u16)) }
}

/// Read sockaddr_un path (NUL-terminated, ≤107 B). # C: O(108)
pub(crate) fn read_sockaddr_un_path(ptr: u64) -> Option<alloc::string::String> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 108-byte bounded read.
    unsafe {
        let p = (ptr + 2) as *const u8;
        let mut bytes = alloc::vec::Vec::new();
        for i in 0..108 {
            let b = core::ptr::read_volatile(p.add(i));
            if b == 0 { break; }
            bytes.push(b);
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
