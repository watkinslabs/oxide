// inet — byte order + presentation/network address conversion (docs/59§6
// G13). Pure parsing/formatting (htons/htonl, inet_pton/inet_ntop for AF_INET
// + AF_INET6), differentially tested against host glibc; freestanding C-ABI
// exports wrap the inner impls. Targets are little-endian so host order swaps.
#![allow(clippy::upper_case_acronyms)]

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
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
