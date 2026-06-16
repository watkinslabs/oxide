// inet — byte order + presentation/network address conversion (docs/59§6
// G13). Pure parsing/formatting (htons/htonl, inet_pton/inet_ntop for AF_INET
// + AF_INET6), differentially tested against host glibc; freestanding C-ABI
// exports wrap the inner impls. Targets are little-endian so host order swaps.
#![allow(clippy::upper_case_acronyms)]

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

// # C: const struct in6_addr in6addr_any / in6addr_loopback — exported data
// (struct in6_addr is { uint8_t s6_addr[16] }; ABI-identical to [u8;16]).
#[cfg(feature = "freestanding")]
#[no_mangle]
pub static in6addr_any: [u8; 16] = [0; 16];
#[cfg(feature = "freestanding")]
#[no_mangle]
pub static in6addr_loopback: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;

/// # C: htons — host(LE)→network(BE) 16-bit
pub(crate) fn bswap16(x: u16) -> u16 { x.swap_bytes() }
/// # C: htonl — host(LE)→network(BE) 32-bit
pub(crate) fn bswap32(x: u32) -> u32 { x.swap_bytes() }

/// Parse an IPv4 dotted-quad into 4 network-order bytes. Strict like glibc:
/// exactly 4 decimal octets 0..=255, no leading zeros. Returns false on bad.
/// # C: int inet_pton(AF_INET, const char *src, void *dst)
pub(crate) fn pton4(src: &[u8], out: &mut [u8; 4]) -> bool {
    let mut parts = 0usize;
    let mut i = 0usize;
    while parts < 4 {
        let start = i;
        let mut val: u32 = 0;
        while i < src.len() && src[i].is_ascii_digit() {
            val = val * 10 + (src[i] - b'0') as u32;
            if val > 255 { return false; }
            i += 1;
        }
        let len = i - start;
        if len == 0 || len > 3 { return false; }
        if len > 1 && src[start] == b'0' { return false; } // no leading zero
        out[parts] = val as u8;
        parts += 1;
        if parts < 4 {
            if i >= src.len() || src[i] != b'.' { return false; }
            i += 1;
        }
    }
    i == src.len()
}

/// Format 4 network-order bytes as a dotted-quad into `out`; returns the len.
/// # C: const char *inet_ntop(AF_INET, const void *src, char *dst, socklen_t)
pub(crate) fn ntop4(addr: &[u8; 4], out: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    for (k, &b) in addr.iter().enumerate() {
        if k > 0 { *out.get_mut(n)? = b'.'; n += 1; }
        n += write_dec(b as u32, out.get_mut(n..)?);
    }
    Some(n)
}

fn write_dec(mut v: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
    let mut k = 0;
    if v == 0 { tmp[0] = b'0'; k = 1; } else { while v > 0 { tmp[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; } }
    for j in 0..k { out[j] = tmp[k - 1 - j]; }
    k
}

/// Parse an IPv6 text address into 16 network-order bytes (supports "::"
/// zero compression and a trailing embedded IPv4). Returns false on bad.
/// # C: int inet_pton(AF_INET6, const char *src, void *dst)
pub(crate) fn pton6(src: &[u8], out: &mut [u8; 16]) -> bool {
    *out = [0; 16];
    let mut groups = [0u16; 8];
    let mut ng = 0usize;
    let mut dcolon: Option<usize> = None; // group index where :: sits
    let mut i = 0usize;
    // leading "::"
    if src.starts_with(b"::") { dcolon = Some(0); i = 2; }
    else if src.first() == Some(&b':') { return false; }
    while i < src.len() {
        if ng >= 8 { return false; }
        // an embedded IPv4 tail?
        if src[i..].iter().take_while(|&&c| c != b':').any(|&c| c == b'.') {
            let mut v4 = [0u8; 4];
            if !pton4(&src[i..], &mut v4) || ng > 6 { return false; }
            groups[ng] = ((v4[0] as u16) << 8) | v4[1] as u16;
            groups[ng + 1] = ((v4[2] as u16) << 8) | v4[3] as u16;
            ng += 2;
            break;
        }
        let start = i;
        let mut val: u32 = 0;
        while i < src.len() && src[i].is_ascii_hexdigit() {
            val = (val << 4) | hexval(src[i]) as u32;
            if val > 0xffff { return false; }
            i += 1;
        }
        if i == start { return false; }
        groups[ng] = val as u16;
        ng += 1;
        if i == src.len() { break; }
        if src[i] != b':' { return false; }
        i += 1;
        if i < src.len() && src[i] == b':' {
            if dcolon.is_some() { return false; } // only one ::
            dcolon = Some(ng);
            i += 1;
            if i == src.len() { break; }
        } else if i == src.len() {
            return false; // trailing single ':'
        }
    }
    // place groups, expanding :: with zeros
    match dcolon {
        None => {
            if ng != 8 { return false; }
            for (k, g) in groups[..8].iter().enumerate() { out[k * 2..k * 2 + 2].copy_from_slice(&g.to_be_bytes()); }
        }
        Some(d) => {
            if ng >= 8 { return false; }
            let tail = ng - d;
            for k in 0..d { out[k * 2..k * 2 + 2].copy_from_slice(&groups[k].to_be_bytes()); }
            for k in 0..tail { let dst = 8 - tail + k; out[dst * 2..dst * 2 + 2].copy_from_slice(&groups[d + k].to_be_bytes()); }
        }
    }
    true
}

fn hexval(c: u8) -> u8 {
    match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, b'A'..=b'F' => c - b'A' + 10, _ => 0 }
}

/// Format 16 network-order bytes as canonical IPv6 text (RFC5952: lowercase,
/// no leading zeros, longest zero-run ≥2 compressed to "::"). Returns len.
/// # C: const char *inet_ntop(AF_INET6, const void *src, char *dst, socklen_t)
pub(crate) fn ntop6(addr: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let mut g = [0u16; 8];
    for (gk, c) in g.iter_mut().zip(addr.chunks_exact(2)) { *gk = ((c[0] as u16) << 8) | c[1] as u16; }
    // longest run of zeros (len >= 2)
    let (mut best_s, mut best_l, mut cur_s, mut cur_l) = (0usize, 0usize, 0usize, 0usize);
    for (k, &gk) in g.iter().enumerate() {
        if gk == 0 { if cur_l == 0 { cur_s = k; } cur_l += 1; if cur_l > best_l { best_l = cur_l; best_s = cur_s; } }
        else { cur_l = 0; }
    }
    if best_l < 2 { best_l = 0; }
    let mut n = 0;
    let mut k = 0;
    while k < 8 {
        if best_l > 0 && k == best_s {
            *out.get_mut(n)? = b':'; n += 1;
            if best_s + best_l == 8 { *out.get_mut(n)? = b':'; n += 1; }
            k += best_l;
            continue;
        }
        if k > 0 { *out.get_mut(n)? = b':'; n += 1; }
        n += write_hex(g[k] as u32, out.get_mut(n..)?);
        k += 1;
    }
    Some(n)
}

fn write_hex(mut v: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 8];
    let mut k = 0;
    if v == 0 { tmp[0] = b'0'; k = 1; } else { while v > 0 { let d = (v & 0xf) as u8; tmp[k] = if d < 10 { b'0' + d } else { b'a' + d - 10 }; v >>= 4; k += 1; } }
    for j in 0..k { out[j] = tmp[k - 1 - j]; }
    k
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::string::len::strlen_impl;

    /// # C: uint16_t htons(uint16_t)
    #[no_mangle]
    pub extern "C" fn htons(x: u16) -> u16 { bswap16(x) }
    /// # C: uint16_t ntohs(uint16_t)
    #[no_mangle]
    pub extern "C" fn ntohs(x: u16) -> u16 { bswap16(x) }
    /// # C: uint32_t htonl(uint32_t)
    #[no_mangle]
    pub extern "C" fn htonl(x: u32) -> u32 { bswap32(x) }
    /// # C: uint32_t ntohl(uint32_t)
    #[no_mangle]
    pub extern "C" fn ntohl(x: u32) -> u32 { bswap32(x) }

    #[repr(C)]
    pub struct in_addr { pub s_addr: u32 } // network byte order

    struct Ntoa(core::cell::UnsafeCell<[u8; 16]>);
    // SAFETY: process-global inet_ntoa buffer; single-threaded until TLS.
    unsafe impl Sync for Ntoa {}
    static NTOA: Ntoa = Ntoa(core::cell::UnsafeCell::new([0u8; 16]));

    // parse one numeric component (C inet: 0x→hex, 0→octal, else decimal);
    // returns (value, bytes consumed) or None if no digit.
    unsafe fn num(p: *const u8) -> Option<(u64, usize)> {
        // SAFETY: p points into a NUL-terminated string; digits stop at a
        // non-digit, always within the string.
        unsafe {
            let (mut base, mut i): (u64, usize) = (10, 0);
            if *p == b'0' {
                if *p.add(1) == b'x' || *p.add(1) == b'X' { base = 16; i = 2; } else { base = 8; i = 1; }
            }
            let start = i;
            let mut v = 0u64;
            loop {
                let c = *p.add(i);
                let d = match c {
                    b'0'..=b'9' => (c - b'0') as u64,
                    b'a'..=b'f' if base == 16 => (c - b'a' + 10) as u64,
                    b'A'..=b'F' if base == 16 => (c - b'A' + 10) as u64,
                    _ => break,
                };
                if d >= base { break; }
                v = v * base + d; i += 1;
            }
            if i == start && base != 8 { return None; } // "0x" with no hex digit
            if i == 0 { return None; }
            Some((v, i))
        }
    }

    // # C: int inet_aton(const char *cp, struct in_addr *inp)
    #[no_mangle]
    pub unsafe extern "C" fn inet_aton(cp: *const u8, inp: *mut in_addr) -> i32 {
        // SAFETY: cp NUL-terminated; inp null or writable. Parses the classic
        // a / a.b / a.b.c / a.b.c.d forms (octal/hex/decimal parts).
        unsafe {
            let mut parts = [0u64; 4];
            let mut n = 0usize;
            let mut p = cp;
            loop {
                let (v, adv) = match num(p) { Some(x) => x, None => return 0 };
                parts[n] = v; n += 1; p = p.add(adv);
                if *p == b'.' { if n == 4 { return 0; } p = p.add(1); continue; }
                break;
            }
            while *p == b' ' || *p == b'\t' || *p == b'\n' { p = p.add(1); }
            if *p != 0 { return 0; }
            let addr: u64 = match n {
                1 => parts[0],
                2 => { if parts[0] > 0xff || parts[1] > 0xff_ffff { return 0; } (parts[0] << 24) | parts[1] }
                3 => { if parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff { return 0; } (parts[0] << 24) | (parts[1] << 16) | parts[2] }
                4 => { if parts.iter().take(4).any(|&x| x > 0xff) { return 0; } (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3] }
                _ => return 0,
            };
            if addr > 0xffff_ffff { return 0; }
            if !inp.is_null() { (*inp).s_addr = (addr as u32).to_be(); }
            1
        }
    }
    // # C: in_addr_t inet_addr(const char *cp)
    #[no_mangle]
    pub unsafe extern "C" fn inet_addr(cp: *const u8) -> u32 {
        // SAFETY: cp NUL-terminated; INADDR_NONE (0xffffffff) on parse failure.
        unsafe { let mut a = in_addr { s_addr: 0 }; if inet_aton(cp, &mut a) != 0 { a.s_addr } else { 0xffff_ffff } }
    }
    // # C: in_addr_t inet_network(const char *cp) — host byte order, -1 on error
    #[no_mangle]
    pub unsafe extern "C" fn inet_network(cp: *const u8) -> u32 {
        // SAFETY: cp NUL-terminated; returns the parsed value in host order.
        unsafe { let mut a = in_addr { s_addr: 0 }; if inet_aton(cp, &mut a) != 0 { u32::from_be(a.s_addr) } else { 0xffff_ffff } }
    }
    // # C: char *inet_ntoa(struct in_addr in)
    #[no_mangle]
    pub unsafe extern "C" fn inet_ntoa(addr: in_addr) -> *mut u8 {
        // SAFETY: format the 4 network-order bytes into a process-global buffer.
        unsafe {
            let b = u32::from_be(addr.s_addr).to_be_bytes();
            let buf = NTOA.0.get();
            let mut k = 0;
            for (i, &octet) in b.iter().enumerate() {
                if i > 0 { (*buf)[k] = b'.'; k += 1; }
                if octet >= 100 { (*buf)[k] = b'0' + octet / 100; k += 1; }
                if octet >= 10 { (*buf)[k] = b'0' + (octet / 10) % 10; k += 1; }
                (*buf)[k] = b'0' + octet % 10; k += 1;
            }
            (*buf)[k] = 0;
            (*buf).as_mut_ptr()
        }
    }
    // # C: struct in_addr inet_makeaddr(in_addr_t net, in_addr_t host) — classful
    #[no_mangle]
    pub extern "C" fn inet_makeaddr(net: u32, host: u32) -> in_addr {
        let a = if net < 128 { (net << 24) | (host & 0xff_ffff) }
            else if net < 65536 { (net << 16) | (host & 0xffff) }
            else if net < 0x100_0000 { (net << 8) | (host & 0xff) }
            else { net | host };
        in_addr { s_addr: a.to_be() }
    }
    // # C: in_addr_t inet_lnaof(struct in_addr in) — classful local (host) part
    #[no_mangle]
    pub extern "C" fn inet_lnaof(addr: in_addr) -> u32 {
        let a = u32::from_be(addr.s_addr);
        if a >> 24 < 128 { a & 0xff_ffff } else if a >> 24 < 192 { a & 0xffff } else { a & 0xff }
    }
    // # C: in_addr_t inet_netof(struct in_addr in) — classful network part
    #[no_mangle]
    pub extern "C" fn inet_netof(addr: in_addr) -> u32 {
        let a = u32::from_be(addr.s_addr);
        if a >> 24 < 128 { (a >> 24) & 0xff } else if a >> 24 < 192 { (a >> 16) & 0xffff } else { (a >> 8) & 0xff_ffff }
    }

    // # C: int inet_pton(int af, const char *src, void *dst)
    #[no_mangle]
    pub unsafe extern "C" fn inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32 {
        // SAFETY: src is a NUL-terminated string; dst holds 4 (v4) or 16 (v6)
        // writable bytes per the caller's address family.
        unsafe {
            let s = core::slice::from_raw_parts(src, strlen_impl(src));
            match af {
                AF_INET => { let mut o = [0u8; 4]; if pton4(s, &mut o) { core::ptr::copy_nonoverlapping(o.as_ptr(), dst, 4); 1 } else { 0 } }
                AF_INET6 => { let mut o = [0u8; 16]; if pton6(s, &mut o) { core::ptr::copy_nonoverlapping(o.as_ptr(), dst, 16); 1 } else { 0 } }
                _ => -1,
            }
        }
    }

    // # C: const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
    #[no_mangle]
    pub unsafe extern "C" fn inet_ntop(af: i32, src: *const u8, dst: *mut u8, size: u32) -> *const u8 {
        // SAFETY: src holds 4/16 bytes per af; dst is writable for `size`.
        unsafe {
            let cap = size as usize;
            let mut buf = [0u8; INET6_ADDRSTRLEN];
            let n = match af {
                AF_INET => { let mut a = [0u8; 4]; core::ptr::copy_nonoverlapping(src, a.as_mut_ptr(), 4); ntop4(&a, &mut buf) }
                AF_INET6 => { let mut a = [0u8; 16]; core::ptr::copy_nonoverlapping(src, a.as_mut_ptr(), 16); ntop6(&a, &mut buf) }
                _ => return core::ptr::null(),
            };
            match n {
                Some(len) if len < cap => { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, len); *dst.add(len) = 0; dst }
                _ => core::ptr::null(),
            }
        }
    }

    use crate::internal::errno::set as set_errno;
    const EAFNOSUPPORT: i32 = 97;
    const EMSGSIZE: i32 = 90;
    const ENOENT: i32 = 2;
    const EINVAL: i32 = 22;

    // # C: int inet_net_pton(int af, const char *cp, void *buf, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn inet_net_pton(af: i32, cp: *const u8, buf: *mut u8, size: usize) -> i32 {
        // SAFETY: cp NUL-terminated; buf writable for `size` bytes. AF_INET only
        // (glibc). Returns the network width in bits, or -1 with errno set.
        unsafe {
            if af != AF_INET { set_errno(EAFNOSUPPORT); return -1; }
            let s = core::slice::from_raw_parts(cp, strlen_impl(cp));
            let mut octets = [0u8; 4];
            let mut nbytes = 0usize;
            let mut bits: i32 = -1;
            if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
                // hex: nibble pairs into bytes, odd trailing nibble → high nibble
                let mut tmp = 0u8; let mut dirty = 0;
                let mut i = 2;
                while i < s.len() {
                    let h = match hexval_opt(s[i]) { Some(v) => v, None => { set_errno(ENOENT); return -1; } };
                    if dirty == 0 { tmp = h; dirty = 1; } else { tmp = (tmp << 4) | h; dirty = 0;
                        if nbytes >= 4 { set_errno(EMSGSIZE); return -1; } octets[nbytes] = tmp; nbytes += 1; }
                    i += 1;
                }
                if dirty == 1 { if nbytes >= 4 { set_errno(EMSGSIZE); return -1; } octets[nbytes] = tmp << 4; nbytes += 1; }
            } else if !s.is_empty() && s[0].is_ascii_digit() {
                // dotted decimal, optional /bits
                let mut i = 0;
                loop {
                    let mut v = 0u32; let mut got = false;
                    while i < s.len() && s[i].is_ascii_digit() { v = v * 10 + (s[i] - b'0') as u32; got = true; i += 1; if v > 255 { set_errno(ENOENT); return -1; } }
                    if !got { set_errno(ENOENT); return -1; }
                    if nbytes >= 4 { set_errno(EMSGSIZE); return -1; }
                    octets[nbytes] = v as u8; nbytes += 1;
                    if i < s.len() && s[i] == b'.' { i += 1; continue; }
                    break;
                }
                if i < s.len() && s[i] == b'/' {
                    i += 1; let mut b = 0i32; let mut got = false;
                    while i < s.len() && s[i].is_ascii_digit() { b = b * 10 + (s[i] - b'0') as i32; got = true; i += 1; }
                    if !got || i != s.len() || b > 32 { set_errno(ENOENT); return -1; }
                    bits = b;
                } else if i != s.len() { set_errno(ENOENT); return -1; }
            } else { set_errno(ENOENT); return -1; }
            if bits == -1 {
                // classful default; class D (224-239) is fixed at 4 bits and not
                // widened, everyone else widens to cover the octets actually given.
                let f = octets[0];
                if f >= 240 { bits = 32; }
                else if f >= 224 { bits = 4; }
                else {
                    bits = if f >= 192 { 24 } else if f >= 128 { 16 } else { 8 };
                    if bits < (nbytes as i32) * 8 { bits = (nbytes as i32) * 8; }
                }
            }
            // glibc writes max(nbytes, ceil(bits/8)) octets: the parsed ones plus
            // zero-fill out to the mask width.
            let need = core::cmp::max(nbytes, ((bits as usize) + 7) / 8);
            if need > size { set_errno(EMSGSIZE); return -1; }
            for j in 0..need { *buf.add(j) = if j < nbytes { octets[j] } else { 0 }; }
            bits
        }
    }

    // # C: char *inet_net_ntop(int af, const void *cp, int bits, char *buf, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn inet_net_ntop(af: i32, cp: *const u8, bits: i32, buf: *mut u8, size: usize) -> *const u8 {
        // SAFETY: cp holds ≥ ceil(bits/8) bytes; buf writable for `size`. AF_INET
        // only. Prints ceil(bits/8) octets (min 1) + "/bits". NULL + errno on error.
        unsafe {
            if af != AF_INET { set_errno(EAFNOSUPPORT); return core::ptr::null(); }
            if !(0..=32).contains(&bits) { set_errno(EINVAL); return core::ptr::null(); }
            let mut octets = ((bits as usize) + 7) / 8;
            if octets == 0 { octets = 1; }
            let mut out = [0u8; 32]; let mut k = 0;
            for i in 0..octets {
                if i > 0 { out[k] = b'.'; k += 1; }
                k += u8_dec(*cp.add(i), &mut out[k..]);
            }
            out[k] = b'/'; k += 1;
            k += u8_dec(bits as u8, &mut out[k..]);
            if k + 1 > size { set_errno(EMSGSIZE); return core::ptr::null(); }
            core::ptr::copy_nonoverlapping(out.as_ptr(), buf, k); *buf.add(k) = 0;
            buf
        }
    }

    // # C: char *inet_neta(in_addr_t src, char *dst, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn inet_neta(src: u32, dst: *mut u8, size: usize) -> *const u8 {
        // SAFETY: dst writable for `size`. Emits the nonzero octets (MSB→LSB)
        // joined by '.', dropping zero octets; all-zero → "0.0.0.0".
        unsafe {
            let b = src.to_be_bytes();
            let mut out = [0u8; 16]; let mut k = 0; let mut first = true;
            if src == 0 {
                let z = b"0.0.0.0"; out[..7].copy_from_slice(z); k = 7;
            } else {
                for &octet in b.iter() {
                    if octet == 0 { continue; }
                    if !first { out[k] = b'.'; k += 1; }
                    first = false;
                    k += u8_dec(octet, &mut out[k..]);
                }
            }
            if k + 1 > size { set_errno(EMSGSIZE); return core::ptr::null(); }
            core::ptr::copy_nonoverlapping(out.as_ptr(), dst, k); *dst.add(k) = 0;
            dst
        }
    }

    // # C: unsigned int inet_nsap_addr(const char *cp, unsigned char *buf, int len)
    #[no_mangle]
    pub unsafe extern "C" fn inet_nsap_addr(cp: *const u8, buf: *mut u8, len: i32) -> u32 {
        // SAFETY: cp NUL-terminated; buf writable for `len` bytes. Parses hex
        // nibble pairs, skipping '.', '+', '/' and whitespace. 0 on malformed.
        unsafe {
            let max = if len < 0 { 0 } else { len as usize };
            let s = core::slice::from_raw_parts(cp, strlen_impl(cp));
            let mut n = 0usize; let mut i = 0;
            while i < s.len() && n < max {
                let c = s[i];
                if c == b'.' || c == b'+' || c == b'/' || c == b' ' || c == b'\t' || c == b'\n' { i += 1; continue; }
                let hi = match hexval_opt(c) { Some(v) => v, None => return 0 };
                i += 1;
                if i >= s.len() { return 0; }
                let lo = match hexval_opt(s[i]) { Some(v) => v, None => return 0 };
                i += 1;
                *buf.add(n) = (hi << 4) | lo; n += 1;
            }
            n as u32
        }
    }

    // # C: char *inet_nsap_ntoa(int binlen, const unsigned char *binary, char *ascii)
    #[no_mangle]
    pub unsafe extern "C" fn inet_nsap_ntoa(binlen: i32, binary: *const u8, ascii: *mut u8) -> *const u8 {
        // SAFETY: binary holds binlen bytes; ascii writable for the formatted
        // output (≤ 3*binlen + 1). Uppercase hex, a '.' before each odd index.
        unsafe {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let n = if binlen < 0 { 0 } else { binlen as usize };
            let mut k = 0;
            for i in 0..n {
                if i & 1 == 1 { *ascii.add(k) = b'.'; k += 1; }
                let c = *binary.add(i);
                *ascii.add(k) = HEX[(c >> 4) as usize]; k += 1;
                *ascii.add(k) = HEX[(c & 0xf) as usize]; k += 1;
            }
            *ascii.add(k) = 0;
            ascii
        }
    }
}

// Hex digit value, or None for a non-hex byte.
#[inline] fn hexval_opt(c: u8) -> Option<u8> {
    match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), b'A'..=b'F' => Some(c - b'A' + 10), _ => None }
}
// Write the decimal of `v` (0..=255) into `out`; returns the digit count.
#[inline] fn u8_dec(v: u8, out: &mut [u8]) -> usize {
    let mut k = 0;
    if v >= 100 { out[k] = b'0' + v / 100; k += 1; }
    if v >= 10 { out[k] = b'0' + (v / 10) % 10; k += 1; }
    out[k] = b'0' + v % 10; k += 1;
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // host glibc oracle (the `libc` crate doesn't re-export these); the test
    // binary links the system libc so the externs resolve.
    extern "C" {
        fn inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32;
        fn inet_ntop(af: i32, src: *const u8, dst: *mut u8, size: u32) -> *const u8;
    }

    fn host_pton(af: i32, s: &str) -> Option<std::vec::Vec<u8>> {
        let c = std::ffi::CString::new(s).unwrap();
        let n = if af == AF_INET { 4 } else { 16 };
        let mut buf = std::vec![0u8; n];
        // SAFETY: c is NUL-terminated; buf holds n bytes for the family.
        let r = unsafe { inet_pton(af, c.as_ptr() as *const u8, buf.as_mut_ptr()) };
        if r == 1 { Some(buf) } else { None }
    }
    fn host_ntop(af: i32, bytes: &[u8]) -> Option<std::string::String> {
        let mut buf = std::vec![0u8; 64];
        // SAFETY: bytes has the right length for af; buf is 64 bytes.
        let p = unsafe { inet_ntop(af, bytes.as_ptr(), buf.as_mut_ptr(), 64) };
        if p.is_null() { return None; }
        let end = buf.iter().position(|&b| b == 0).unwrap();
        Some(std::string::String::from_utf8(buf[..end].to_vec()).unwrap())
    }

    proptest! {
        #[test]
        fn pton4_matches_host(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let s = std::format!("{a}.{b}.{c}.{d}");
            let mut o = [0u8; 4];
            prop_assert!(pton4(s.as_bytes(), &mut o));
            prop_assert_eq!(&o[..], &host_pton(AF_INET, &s).unwrap()[..]);
        }
        #[test]
        fn ntop4_matches_host(bytes in any::<[u8; 4]>()) {
            let mut o = [0u8; 16];
            let n = ntop4(&bytes, &mut o).unwrap();
            prop_assert_eq!(std::str::from_utf8(&o[..n]).unwrap(), host_ntop(AF_INET, &bytes).unwrap());
        }
        #[test]
        fn v6_roundtrip_matches_host(g in any::<[u16; 8]>()) {
            let mut bytes = [0u8; 16];
            for k in 0..8 { bytes[k*2..k*2+2].copy_from_slice(&g[k].to_be_bytes()); }
            // our ntop6 must equal host inet_ntop
            let mut o = [0u8; 46];
            let n = ntop6(&bytes, &mut o).unwrap();
            let ours = std::str::from_utf8(&o[..n]).unwrap();
            prop_assert_eq!(ours, host_ntop(AF_INET6, &bytes).unwrap());
            // and our pton6 of the host string must reproduce the bytes
            let hs = host_ntop(AF_INET6, &bytes).unwrap();
            let mut back = [0u8; 16];
            prop_assert!(pton6(hs.as_bytes(), &mut back));
            prop_assert_eq!(&back[..], &bytes[..]);
        }
    }

    #[test]
    fn pton_rejects_bad() {
        let mut o4 = [0u8; 4];
        assert!(!pton4(b"1.2.3", &mut o4));
        assert!(!pton4(b"1.2.3.256", &mut o4));
        assert!(!pton4(b"1.2.3.04", &mut o4)); // leading zero
        assert!(!pton4(b"1.2.3.4.5", &mut o4));
        let mut o6 = [0u8; 16];
        assert!(pton6(b"::1", &mut o6));
        assert_eq!(o6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(pton6(b"2001:db8::1", &mut o6));
        assert!(!pton6(b"1::2::3", &mut o6)); // two ::
    }
}
