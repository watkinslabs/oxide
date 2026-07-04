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
    // # C: int __inet_aton_exact(const char *cp, struct in_addr *inp)
    #[no_mangle]
    pub unsafe extern "C" fn __inet_aton_exact(cp: *const u8, inp: *mut in_addr) -> i32 {
        // SAFETY: cp is NUL-terminated; inp is null or writable for in_addr.
        unsafe {
            let s = core::slice::from_raw_parts(cp, strlen_impl(cp));
            let mut o = [0u8; 4];
            if !pton4(s, &mut o) { return 0; }
            if !inp.is_null() { (*inp).s_addr = u32::from_be_bytes(o).to_be(); }
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
    // # C: int __inet_pton_length(int af, const char *src, size_t len, void *dst)
    #[no_mangle]
    pub unsafe extern "C" fn __inet_pton_length(af: i32, src: *const u8, len: usize, dst: *mut u8) -> i32 {
        // SAFETY: src points to len readable bytes; dst holds 4/16 writable bytes.
        unsafe {
            let s = core::slice::from_raw_parts(src, len);
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
