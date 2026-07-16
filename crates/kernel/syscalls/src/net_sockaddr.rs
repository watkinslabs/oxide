// P5-01: sockaddr parse/format helpers — extracted from net.rs to
// stay under the 1000-line cap (docs/08§7). All helpers are
// pub(crate); net.rs and net_recv.rs consume them.

use hal::USER_VA_END;
use net::sock::InetSocket;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};
use syscall::errno::Errno;

const AF_INET:  u32 = 2;
const AF_INET6: u32 = 10;
const AF_UNIX:  u16 = 1;
const AF_NETLINK: u16 = 16;

const SOCKADDR_UN_LEN:    usize = 110;
const SOCKADDR_IN_LEN:    usize = 16;
const SOCKADDR_IN6_LEN:   usize = 28;
const SOCKADDR_NL_LEN:    usize = 12;
const SOCKADDR_VM_LEN:    usize = 16;
const SOCKADDR_STORAGE:   usize = SOCKADDR_UN_LEN;
const SA_FAMILY_LEN:      usize = 2;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `move_addr_to_kernel`: validate signed socklen, storage bound, and
/// readable user range before any family-specific parse. # C: O(N pages)
pub(crate) fn move_sockaddr_to_kernel_shape(ptr: u64, addrlen: u64) -> Result<usize, i64> {
    let len = addrlen as i32;
    if len < 0 { return Err(err(Errno::Einval)); }
    let len = len as usize;
    if len > 128 { return Err(err(Errno::Einval)); }
    if len != 0 { validate_user_buf_readable(ptr, len as u64, 1)?; }
    Ok(len)
}

/// Read `sa_family` after the Linux copyin-equivalent validation. # C: O(1)
pub(crate) fn read_sa_family_checked(ptr: u64, addrlen: usize) -> Result<u16, i64> {
    if addrlen < SA_FAMILY_LEN { return Err(err(Errno::Einval)); }
    read_sa_family(ptr).ok_or(err(Errno::Efault))
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_in(addrlen: usize) -> Result<(), i64> {
    if addrlen < SOCKADDR_IN_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_in6(addrlen: usize) -> Result<(), i64> {
    if addrlen < SOCKADDR_IN6_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}

/// Validate a copied sockaddr has the complete protocol struct. # C: O(1)
pub(crate) fn require_sockaddr_vm(addrlen: usize) -> Result<(), i64> {
    if addrlen < SOCKADDR_VM_LEN { Err(err(Errno::Einval)) } else { Ok(()) }
}

pub(crate) struct EncodedSockaddr {
    bytes: [u8; SOCKADDR_STORAGE],
    len:   usize,
}

impl EncodedSockaddr {
    fn new(len: usize) -> Self { Self { bytes: [0; SOCKADDR_STORAGE], len } }
    pub(crate) fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }
    pub(crate) fn len(&self) -> usize { self.len }
    fn put_u16(&mut self, off: usize, v: u16) { self.bytes[off..off + 2].copy_from_slice(&v.to_ne_bytes()); }
    fn put_u32(&mut self, off: usize, v: u32) { self.bytes[off..off + 4].copy_from_slice(&v.to_ne_bytes()); }
}

pub(crate) fn encoded_sockaddr_un(path: Option<&[u8]>) -> EncodedSockaddr {
    let bytes = path.unwrap_or(&[]);
    let path_len = bytes.len().min(108);
    let needs_nul = path_len > 0 && bytes.first().copied() != Some(0);
    let len = 2 + path_len + usize::from(needs_nul);
    let mut out = EncodedSockaddr::new(len.min(SOCKADDR_UN_LEN));
    out.put_u16(0, AF_UNIX);
    for i in 0..path_len { out.bytes[2 + i] = bytes[i]; }
    out
}

pub(crate) fn encoded_sockaddr_in(addr_be: u32, port_be: u16) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_IN_LEN);
    out.put_u16(0, AF_INET as u16);
    out.put_u16(2, port_be);
    out.put_u32(4, addr_be);
    out
}

pub(crate) fn encoded_sockaddr_in6(addr_bytes: [u8; 16], port_be: u16, scope_id: u32) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_IN6_LEN);
    out.put_u16(0, AF_INET6 as u16);
    out.put_u16(2, port_be);
    out.put_u32(4, 0);
    out.bytes[8..24].copy_from_slice(&addr_bytes);
    out.put_u32(24, scope_id);
    out
}

/// Encode Linux `struct sockaddr_nl`. # C: O(1)
pub(crate) fn encoded_sockaddr_nl(pid: u32, groups: u32) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_NL_LEN);
    out.put_u16(0, AF_NETLINK);
    out.put_u16(2, 0);
    out.put_u32(4, pid);
    out.put_u32(8, groups);
    out
}

/// Copy an encoded kernel sockaddr to `addr` using Linux value-result
/// `addrlen`: read caller length, copy min(caller, kernel), then write the
/// full kernel length back to `addrlen`. # C: O(sockaddr len)
pub(crate) fn copy_sockaddr_to_user(addr: u64, addrlen: u64, sa: &EncodedSockaddr) -> i64 {
    let mut raw_len = [0u8; 4];
    if uaccess::copy_from_user(&mut raw_len, addrlen).is_err() { return err(Errno::Efault); }
    let user_len = i32::from_ne_bytes(raw_len);
    if user_len < 0 { return err(Errno::Einval); }
    let copy_len = core::cmp::min(user_len as usize, sa.len);
    if uaccess::copy_to_user(addr, &sa.as_bytes()[..copy_len]).is_err() { return err(Errno::Efault); }
    if uaccess::copy_to_user(addrlen, &(sa.len as u32).to_ne_bytes()).is_err() { return err(Errno::Efault); }
    0
}

/// Write a `sockaddr_un` (family + sun_path) at user pointer `ptr`. An
/// abstract address (leading NUL) writes its name after the family with the
/// leading NUL preserved; a pathname address writes the path + a trailing
/// NUL. `None`/empty path writes the bare 2-byte family (unbound socket).
/// Direct writer for legacy recv/accept paths that validate addrlen at the
/// syscall boundary. # C: O(path len)
pub(crate) fn write_sockaddr_un(ptr: u64, path: Option<&[u8]>) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    // SAFETY: ptr validated in user range; caller AS active; bounded writes within sockaddr_un (2 + 108).
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_UNIX);
        let bytes = path.unwrap_or(&[]);
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
pub(crate) fn read_sockaddr_un_path_len(ptr: u64, addrlen: u64) -> Option<alloc::vec::Vec<u8>> {
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
        } else {
            bytes.push(first);
            for i in 1..path_len {
                let b = core::ptr::read_volatile(p.add(i));
                if b == 0 { break; }
                bytes.push(b);
            }
        }
        Some(bytes)
    }
}

/// Decode a snapshotted `sockaddr_un` with Linux pathname/abstract trimming. # C: O(108)
pub(crate) fn unix_path_from_kernel_sockaddr(addr: &[u8]) -> Result<alloc::vec::Vec<u8>, i64> {
    if addr.len() <= 2 { return Err(-(Errno::Einval.as_i32() as i64)); }
    let raw = &addr[2..core::cmp::min(addr.len(), 110)];
    if raw[0] == 0 {
        return Ok(raw.to_vec());
    }
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    Ok(raw[..end].to_vec())
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

/// Encode sockaddr for a socket's current family without touching user memory.
/// # C: O(1)
pub(crate) fn encoded_sockaddr_for_socket(sock: &InetSocket, ip: net::Ipv4Addr, port: u16) -> EncodedSockaddr {
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if fam == net::sock::AF_UNIX {
        let path = net::sock::unix_local_path(sock);
        return encoded_sockaddr_un(path.as_deref());
    }
    if fam == net::sock::AF_INET6 {
        let mut b = [0u8; 16];
        if ip == net::Ipv4Addr::LOOPBACK {
            b[15] = 1;
        } else if ip != net::Ipv4Addr::ANY {
            b[10] = 0xff; b[11] = 0xff;
            let v = ip.as_u32();
            b[12] = (v >> 24) as u8;
            b[13] = (v >> 16) as u8;
            b[14] = (v >>  8) as u8;
            b[15] =  v        as u8;
        }
        encoded_sockaddr_in6(b, port.to_be(), 0)
    } else {
        encoded_sockaddr_in(ip.as_u32().to_be(), port.to_be())
    }
}

/// Encode AF_UNIX sockaddr for a peer/local path without touching user memory.
/// # C: O(path len)
pub(crate) fn encoded_sockaddr_un_path(path: Option<&[u8]>) -> EncodedSockaddr {
    encoded_sockaddr_un(path)
}

/// Encode `struct sockaddr_vm` without touching user memory. # C: O(1)
pub(crate) fn encoded_sockaddr_vm(port: u32, cid: u64) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_VM_LEN);
    out.put_u16(0, net::socket_args::AF_VSOCK as u16);
    out.put_u16(2, 0);
    out.put_u32(4, port);
    out.put_u32(8, cid as u32);
    out.put_u32(12, 0);
    out
}

/// Write a sockaddr_in6 from a genuine IPv6 source address (the recv
/// path's `peer6`), as opposed to the V4-state synthesis above.
/// # C: O(1)
pub(crate) fn write_sockaddr_in6_peer(ptr: u64, ip: net::Ipv6Addr, port: u16) {
    write_sockaddr_in6(ptr, ip.0, port.to_be(), 0);
}

/// Encode a genuine IPv6 peer address. # C: O(1)
pub(crate) fn encoded_sockaddr_in6_peer(ip: net::Ipv6Addr, port: u16) -> EncodedSockaddr {
    encoded_sockaddr_in6(ip.0, port.to_be(), 0)
}
