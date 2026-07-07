use core::ffi::c_void;

use super::cstr::{c_strlen, is_space, to_lower};

const LINUX_EINVAL: i32 = 22;

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("hex_to_bin",   hex_to_bin   as *const () as usize),
        ("hex2bin",      hex2bin      as *const () as usize),
        ("bin2hex",      bin2hex      as *const () as usize),
        ("simple_strtoul", simple_strtoul as *const () as usize),
        ("kstrtobool",   kstrtobool   as *const () as usize),
        ("kstrtoint",    kstrtoint    as *const () as usize),
        ("kstrtou8",     kstrtou8     as *const () as usize),
        ("kstrtou16",    kstrtou16    as *const () as usize),
        ("kstrtouint",   kstrtouint   as *const () as usize),
        ("kstrtoull",    kstrtoull    as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn hex_to_bin(ch: i32) -> i32 {
    match ch as u8 {
        b'0'..=b'9' => ch - b'0' as i32,
        b'a'..=b'f' => ch - b'a' as i32 + 10,
        b'A'..=b'F' => ch - b'A' as i32 + 10,
        _ => -1,
    }
}

pub(crate) unsafe extern "C" fn hex2bin(dst: *mut u8, src: *const u8, count: usize) -> i32 {
    if count != 0 && (dst.is_null() || src.is_null()) { return -LINUX_EINVAL; }
    for i in 0..count {
        // SAFETY: src contains two hex characters for each output byte.
        let hi = hex_to_bin(unsafe { *src.add(i * 2) } as i32);
        // SAFETY: src contains two hex characters for each output byte.
        let lo = hex_to_bin(unsafe { *src.add(i * 2 + 1) } as i32);
        if hi < 0 || lo < 0 { return -LINUX_EINVAL; }
        // SAFETY: dst contains count writable bytes.
        unsafe { *dst.add(i) = ((hi << 4) | lo) as u8; }
    }
    0
}

pub(crate) unsafe extern "C" fn bin2hex(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if dst.is_null() || src.is_null() { return dst; }
    for i in 0..count {
        // SAFETY: src has count readable bytes.
        let b = unsafe { *src.add(i) };
        // SAFETY: dst has two writable bytes per source byte.
        unsafe { *dst.add(i * 2) = HEX[(b >> 4) as usize]; *dst.add(i * 2 + 1) = HEX[(b & 0xf) as usize]; }
    }
    // SAFETY: pointer arithmetic returns the Linux end pointer.
    unsafe { dst.add(count * 2) }
}

pub(crate) unsafe extern "C" fn simple_strtoul(cp: *const u8, endp: *mut *mut u8, base: u32) -> u64 {
    let (v, end, _) = unsafe { parse_unsigned(cp, base, u64::MAX) };
    if !endp.is_null() {
        // SAFETY: optional end pointer is caller-owned.
        unsafe { *endp = end as *mut u8; }
    }
    v
}

pub(crate) unsafe extern "C" fn kstrtobool(s: *const u8, res: *mut bool) -> i32 {
    if s.is_null() || res.is_null() { return -LINUX_EINVAL; }
    let len = unsafe { trim_len(s) };
    let b0 = to_lower(unsafe { *s });
    let yes = len == 1 && matches!(b0, b'y' | b'1');
    let no = len == 1 && matches!(b0, b'n' | b'0');
    let yes_long = eq_nocase(s, len, b"yes") || eq_nocase(s, len, b"true") || eq_nocase(s, len, b"on");
    let no_long = eq_nocase(s, len, b"no") || eq_nocase(s, len, b"false") || eq_nocase(s, len, b"off");
    if yes || yes_long {
        // SAFETY: res is caller-owned bool storage.
        unsafe { *res = true; }
        0
    } else if no || no_long {
        // SAFETY: res is caller-owned bool storage.
        unsafe { *res = false; }
        0
    } else { -LINUX_EINVAL }
}

pub(crate) unsafe extern "C" fn kstrtoint(s: *const u8, base: u32, res: *mut i32) -> i32 {
    if res.is_null() { return -LINUX_EINVAL; }
    match unsafe { parse_signed(s, base, i32::MIN as i64, i32::MAX as i64) } {
        Ok(v) => { unsafe { *res = v as i32; } 0 }
        Err(e) => e,
    }
}

pub(crate) unsafe extern "C" fn kstrtou8(s: *const u8, base: u32, res: *mut u8) -> i32 {
    // SAFETY: res is caller-owned u8 storage.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u8::MAX as u64, 1) }
}

pub(crate) unsafe extern "C" fn kstrtou16(s: *const u8, base: u32, res: *mut u16) -> i32 {
    // SAFETY: res is caller-owned u16 storage.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u16::MAX as u64, 2) }
}

pub(crate) unsafe extern "C" fn kstrtouint(s: *const u8, base: u32, res: *mut u32) -> i32 {
    // SAFETY: res is caller-owned u32 storage.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u32::MAX as u64, 4) }
}

pub(crate) unsafe extern "C" fn kstrtoull(s: *const u8, base: u32, res: *mut u64) -> i32 {
    // SAFETY: res is caller-owned u64 storage.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u64::MAX, 8) }
}

unsafe fn parse_uint_store(s: *const u8, base: u32, res: *mut c_void, max: u64, bytes: usize) -> i32 {
    if res.is_null() { return -LINUX_EINVAL; }
    let (v, end, ok) = unsafe { parse_unsigned(s, base, max) };
    if !ok || !only_ws_or_nul(end) { return -LINUX_EINVAL; }
    match bytes {
        1 => unsafe { *(res as *mut u8) = v as u8; },
        2 => unsafe { *(res as *mut u16) = v as u16; },
        4 => unsafe { *(res as *mut u32) = v as u32; },
        _ => unsafe { *(res as *mut u64) = v; },
    }
    0
}

unsafe fn parse_signed(s: *const u8, base: u32, min: i64, max: i64) -> Result<i64, i32> {
    if s.is_null() { return Err(-LINUX_EINVAL); }
    let mut p = skip_ws(s);
    let mut neg = false;
    let c = unsafe { *p };
    if c == b'-' || c == b'+' {
        neg = c == b'-';
        p = unsafe { p.add(1) };
    }
    let limit = if neg { (max as u64) + 1 } else { max as u64 };
    let (u, end, ok) = unsafe { parse_unsigned(p, base, limit) };
    if !ok || !only_ws_or_nul(end) { return Err(-LINUX_EINVAL); }
    if neg {
        if u == limit { Ok(min) } else { Ok(-(u as i64)) }
    } else { Ok(u as i64) }
}

unsafe fn parse_unsigned(mut s: *const u8, mut base: u32, max: u64) -> (u64, *const u8, bool) {
    if s.is_null() { return (0, s, false); }
    s = skip_ws(s);
    if unsafe { *s } == b'+' { s = unsafe { s.add(1) }; }
    if unsafe { *s } == b'-' { return (0, s, false); }
    if base == 0 {
        base = 10;
        if unsafe { *s } == b'0' {
            base = 8;
            if to_lower(unsafe { *s.add(1) }) == b'x' {
                base = 16; s = unsafe { s.add(2) };
            }
        }
    } else if base == 16 && unsafe { *s } == b'0' && to_lower(unsafe { *s.add(1) }) == b'x' {
        s = unsafe { s.add(2) };
    }
    if !(2..=36).contains(&base) { return (0, s, false); }
    let mut v = 0u64;
    let mut any = false;
    loop {
        let d = digit(unsafe { *s });
        if d < 0 || d as u32 >= base { break; }
        any = true;
        let d = d as u64;
        if v > (max - d) / base as u64 { return (max, s, false); }
        v = v * base as u64 + d;
        s = unsafe { s.add(1) };
    }
    (v, s, any)
}

unsafe fn trim_len(s: *const u8) -> usize {
    let len = unsafe { c_strlen(s) };
    if len != 0 && unsafe { *s.add(len - 1) } == b'\n' { len - 1 } else { len }
}

fn eq_nocase(s: *const u8, len: usize, pat: &[u8]) -> bool {
    if len != pat.len() { return false; }
    for (i, want) in pat.iter().copied().enumerate() {
        if to_lower(unsafe { *s.add(i) }) != want { return false; }
    }
    true
}

fn only_ws_or_nul(mut p: *const u8) -> bool {
    loop {
        let b = unsafe { *p };
        if b == 0 { return true; }
        if !is_space(b) { return false; }
        p = unsafe { p.add(1) };
    }
}

fn skip_ws(mut p: *const u8) -> *const u8 {
    while is_space(unsafe { *p }) { p = unsafe { p.add(1) }; }
    p
}

fn digit(b: u8) -> i32 {
    match b {
        b'0'..=b'9' => (b - b'0') as i32,
        b'a'..=b'z' => (b - b'a') as i32 + 10,
        b'A'..=b'Z' => (b - b'A') as i32 + 10,
        _ => -1,
    }
}
