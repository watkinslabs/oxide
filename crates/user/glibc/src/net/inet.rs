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

// Module manifest: exports owns C ABI wrappers; tests owns host inet parity.
#[cfg(feature = "freestanding")]
mod exports;
#[cfg(feature = "freestanding")]
pub use exports::*;
#[cfg(test)]
mod tests;
