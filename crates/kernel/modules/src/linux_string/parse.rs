use core::ffi::{c_void, VaList};

use super::cstr::{c_strlen, is_space, to_lower};

const LINUX_EINVAL: i32 = 22;

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("hex_to_bin",   hex_to_bin   as *const () as usize),
        ("hex2bin",      hex2bin      as *const () as usize),
        ("bin2hex",      bin2hex      as *const () as usize),
        ("simple_strtoul", simple_strtoul as *const () as usize),
        ("sscanf",       sscanf       as *const () as usize),
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
        // SAFETY: hex2bin's ABI contract gives src at least 2*count readable bytes; i < count so i*2+1 < 2*count.
        let hi = hex_to_bin(unsafe { *src.add(i * 2) } as i32);
        // SAFETY: same src buffer bound as the high nibble read one line above; i*2+1 stays under 2*count.
        let lo = hex_to_bin(unsafe { *src.add(i * 2 + 1) } as i32);
        if hi < 0 || lo < 0 { return -LINUX_EINVAL; }
        // SAFETY: hex2bin's contract gives dst count writable bytes and the loop bound keeps i < count.
        unsafe { *dst.add(i) = ((hi << 4) | lo) as u8; }
    }
    0
}

pub(crate) unsafe extern "C" fn bin2hex(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if dst.is_null() || src.is_null() { return dst; }
    for i in 0..count {
        // SAFETY: bin2hex's contract gives src count readable bytes; the loop bound keeps i < count.
        let b = unsafe { *src.add(i) };
        // SAFETY: bin2hex's contract gives dst 2*count writable bytes, so i*2 and i*2+1 are in bounds for i < count.
        unsafe { *dst.add(i * 2) = HEX[(b >> 4) as usize]; *dst.add(i * 2 + 1) = HEX[(b & 0xf) as usize]; }
    }
    // SAFETY: dst holds 2*count bytes, so add(count*2) is the one-past-end pointer Linux's bin2hex returns.
    unsafe { dst.add(count * 2) }
}

pub(crate) unsafe extern "C" fn simple_strtoul(cp: *const u8, endp: *mut *mut u8, base: u32) -> u64 {
    // SAFETY: simple_strtoul's contract gives cp as a NUL-terminated C string, which is parse_unsigned's precondition.
    let (v, end, _) = unsafe { parse_unsigned(cp, base, u64::MAX) };
    if !endp.is_null() {
        // SAFETY: endp was null-checked and points to caller-owned pointer storage; end is inside cp's own allocation.
        unsafe { *endp = end as *mut u8; }
    }
    v
}

pub(crate) unsafe extern "C" fn sscanf(s: *const u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: sscanf's contract gives NUL-terminated s and fmt plus one output pointer per conversion, which scan_c consumes in order.
    unsafe { scan_c(s, fmt, &mut ap) }
}

pub(crate) unsafe extern "C" fn kstrtobool(s: *const u8, res: *mut bool) -> i32 {
    if s.is_null() || res.is_null() { return -LINUX_EINVAL; }
    // SAFETY: s was null-checked and kstrtobool's contract makes it NUL-terminated, so c_strlen inside trim_len terminates.
    let len = unsafe { trim_len(s) };
    // SAFETY: s was null-checked and is NUL-terminated, so byte 0 is readable even for the empty string.
    let b0 = to_lower(unsafe { *s });
    let yes = len == 1 && matches!(b0, b'y' | b'1');
    let no = len == 1 && matches!(b0, b'n' | b'0');
    // SAFETY: len came from trim_len(s) so it never exceeds strlen(s); eq_nocase only reads indexes below len.
    let yes_long = unsafe { eq_nocase(s, len, b"yes") || eq_nocase(s, len, b"true") || eq_nocase(s, len, b"on") };
    // SAFETY: same trim_len(s) bound as yes_long; every index eq_nocase reads is below strlen(s).
    let no_long = unsafe { eq_nocase(s, len, b"no") || eq_nocase(s, len, b"false") || eq_nocase(s, len, b"off") };
    if yes || yes_long {
        // SAFETY: res was null-checked and kstrtobool's contract makes it aligned, writable bool storage.
        unsafe { *res = true; }
        0
    } else if no || no_long {
        // SAFETY: res was null-checked and kstrtobool's contract makes it aligned, writable bool storage.
        unsafe { *res = false; }
        0
    } else { -LINUX_EINVAL }
}

pub(crate) unsafe extern "C" fn kstrtoint(s: *const u8, base: u32, res: *mut i32) -> i32 {
    if res.is_null() { return -LINUX_EINVAL; }
    // SAFETY: kstrtoint's contract gives s as a NUL-terminated C string; parse_signed null-checks it before any read.
    match unsafe { parse_signed(s, base, i32::MIN as i64, i32::MAX as i64) } {
        // SAFETY: res was null-checked above and kstrtoint's contract makes it aligned, writable i32 storage.
        Ok(v) => { unsafe { *res = v as i32; } 0 }
        Err(e) => e,
    }
}

pub(crate) unsafe extern "C" fn kstrtou8(s: *const u8, base: u32, res: *mut u8) -> i32 {
    // SAFETY: kstrtou8 promises res is aligned, writable u8 storage, matching the 1-byte width passed to parse_uint_store.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u8::MAX as u64, 1) }
}

pub(crate) unsafe extern "C" fn kstrtou16(s: *const u8, base: u32, res: *mut u16) -> i32 {
    // SAFETY: kstrtou16 promises res is aligned, writable u16 storage, matching the 2-byte width passed to parse_uint_store.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u16::MAX as u64, 2) }
}

pub(crate) unsafe extern "C" fn kstrtouint(s: *const u8, base: u32, res: *mut u32) -> i32 {
    // SAFETY: kstrtouint promises res is aligned, writable u32 storage, matching the 4-byte width passed to parse_uint_store.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u32::MAX as u64, 4) }
}

pub(crate) unsafe extern "C" fn kstrtoull(s: *const u8, base: u32, res: *mut u64) -> i32 {
    // SAFETY: kstrtoull promises res is aligned, writable u64 storage, matching the 8-byte width passed to parse_uint_store.
    unsafe { parse_uint_store(s, base, res as *mut c_void, u64::MAX, 8) }
}

// `bytes` selects the store width and must match the type `res` really points at;
// every caller is a kstrto* wrapper above that passes size_of its own out-param.
unsafe fn parse_uint_store(s: *const u8, base: u32, res: *mut c_void, max: u64, bytes: usize) -> i32 {
    if res.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the kstrto* caller's contract makes s NUL-terminated; parse_unsigned null-checks it before any read.
    let (v, end, ok) = unsafe { parse_unsigned(s, base, max) };
    // SAFETY: end points into s's own allocation at or before its NUL, so only_ws_or_nul terminates at that NUL.
    if !ok || !unsafe { only_ws_or_nul(end) } { return -LINUX_EINVAL; }
    match bytes {
        // SAFETY: bytes==1 is only passed by kstrtou8, whose res is aligned, writable u8 storage.
        1 => unsafe { *(res as *mut u8) = v as u8; },
        // SAFETY: bytes==2 is only passed by kstrtou16, whose res is aligned, writable u16 storage.
        2 => unsafe { *(res as *mut u16) = v as u16; },
        // SAFETY: bytes==4 is only passed by kstrtouint, whose res is aligned, writable u32 storage.
        4 => unsafe { *(res as *mut u32) = v as u32; },
        // SAFETY: the default arm is only reached for bytes==8 from kstrtoull, whose res is aligned, writable u64 storage.
        _ => unsafe { *(res as *mut u64) = v; },
    }
    0
}

unsafe fn parse_signed(s: *const u8, base: u32, min: i64, max: i64) -> Result<i64, i32> {
    if s.is_null() { return Err(-LINUX_EINVAL); }
    // SAFETY: s was null-checked and is NUL-terminated; is_space(0) is false so skip_ws halts at the terminator.
    let mut p = unsafe { skip_ws(s) };
    let mut neg = false;
    // SAFETY: skip_ws leaves p at or before s's NUL, so this byte is inside the string.
    let c = unsafe { *p };
    if c == b'-' || c == b'+' {
        neg = c == b'-';
        // SAFETY: c is a sign byte, not the NUL, so p+1 is still inside the string (worst case the terminator).
        p = unsafe { p.add(1) };
    }
    let limit = if neg { (max as u64) + 1 } else { max as u64 };
    // SAFETY: p indexes into the same NUL-terminated string s, which is parse_unsigned's precondition.
    let (u, end, ok) = unsafe { parse_unsigned(p, base, limit) };
    // SAFETY: end points into s's allocation at or before its NUL, so only_ws_or_nul terminates at that NUL.
    if !ok || !unsafe { only_ws_or_nul(end) } { return Err(-LINUX_EINVAL); }
    if neg {
        if u == limit { Ok(min) } else { Ok(-(u as i64)) }
    } else { Ok(u as i64) }
}

pub(crate) unsafe fn parse_decimal_i32(s: *const u8) -> Result<i32, i32> {
    // SAFETY: caller passes a NUL-terminated C string, parse_signed's precondition; it null-checks s itself.
    unsafe { parse_signed(s, 0, i32::MIN as i64, i32::MAX as i64).map(|v| v as i32) }
}

pub(crate) unsafe fn parse_decimal_u64(s: *const u8) -> Result<u64, i32> {
    // SAFETY: caller passes a NUL-terminated C string, parse_unsigned's precondition; it null-checks s itself.
    let (v, end, ok) = unsafe { parse_unsigned(s, 0, u64::MAX) };
    // SAFETY: end points into s's allocation at or before its NUL, so only_ws_or_nul terminates at that NUL.
    if !ok || !unsafe { only_ws_or_nul(end) } { Err(-LINUX_EINVAL) } else { Ok(v) }
}

// Precondition: `s` is null or a NUL-terminated C string. Every read below either
// sits at a byte already proven non-NUL or is the terminator itself, so the scan
// never walks past the end of the caller's buffer.
unsafe fn parse_unsigned(mut s: *const u8, mut base: u32, max: u64) -> (u64, *const u8, bool) {
    if s.is_null() { return (0, s, false); }
    // SAFETY: s was null-checked and is NUL-terminated; is_space(0) is false so skip_ws halts at the terminator.
    s = unsafe { skip_ws(s) };
    // SAFETY: skip_ws left s at or before the NUL, and a '+' byte is not the NUL so s+1 stays inside the string.
    if unsafe { *s } == b'+' { s = unsafe { s.add(1) }; }
    // SAFETY: s is at or before the NUL of the caller's string, so this byte is readable.
    if unsafe { *s } == b'-' { return (0, s, false); }
    if base == 0 {
        base = 10;
        // SAFETY: s is at or before the NUL of the caller's string, so this byte is readable.
        if unsafe { *s } == b'0' {
            base = 8;
            // SAFETY: byte 0 was proven to be '0' rather than the NUL, so index 1 is at worst the terminator.
            if to_lower(unsafe { *s.add(1) }) == b'x' {
                // SAFETY: bytes 0 and 1 were proven non-NUL ('0' then 'x'), so index 2 is at worst the terminator.
                base = 16; s = unsafe { s.add(2) };
            }
        }
    // SAFETY: s is at or before the NUL; the '0' test short-circuits before index 1 is read, and '0' is not the NUL.
    } else if base == 16 && unsafe { *s } == b'0' && to_lower(unsafe { *s.add(1) }) == b'x' {
        // SAFETY: bytes 0 and 1 were proven non-NUL ('0' then 'x'), so index 2 is at worst the terminator.
        s = unsafe { s.add(2) };
    }
    if !(2..=36).contains(&base) { return (0, s, false); }
    let mut v = 0u64;
    let mut any = false;
    loop {
        // SAFETY: s is at or before the NUL; digit(0) is -1, so the loop breaks at the terminator before advancing further.
        let d = digit(unsafe { *s });
        if d < 0 || d as u32 >= base { break; }
        any = true;
        let d = d as u64;
        if v > (max - d) / base as u64 { return (max, s, false); }
        v = v * base as u64 + d;
        // SAFETY: the byte at s parsed as a digit so it is not the NUL, leaving s+1 at worst the terminator.
        s = unsafe { s.add(1) };
    }
    (v, s, any)
}

unsafe fn trim_len(s: *const u8) -> usize {
    // SAFETY: caller passes a NUL-terminated C string, c_strlen's precondition; it null-checks s itself.
    let len = unsafe { c_strlen(s) };
    // SAFETY: len is strlen(s), so for len != 0 index len-1 is the last byte before the terminator.
    if len != 0 && unsafe { *s.add(len - 1) } == b'\n' { len - 1 } else { len }
}

// Precondition: `s` is a NUL-terminated C string with at least `len` bytes before its terminator.
unsafe fn eq_nocase(s: *const u8, len: usize, pat: &[u8]) -> bool {
    if len != pat.len() { return false; }
    for (i, want) in pat.iter().copied().enumerate() {
        // SAFETY: the length guard makes i < pat.len() == len, and the caller's len never exceeds strlen(s).
        if to_lower(unsafe { *s.add(i) }) != want { return false; }
    }
    true
}

// Precondition: `p` points into a NUL-terminated C string.
unsafe fn only_ws_or_nul(mut p: *const u8) -> bool {
    loop {
        // SAFETY: p starts inside the caller's NUL-terminated string and only advances past bytes proven non-NUL.
        let b = unsafe { *p };
        if b == 0 { return true; }
        if !is_space(b) { return false; }
        // SAFETY: b was whitespace, so it was not the terminator and p+1 is at worst the NUL itself.
        p = unsafe { p.add(1) };
    }
}

// Precondition: `p` points into a NUL-terminated C string.
unsafe fn skip_ws(mut p: *const u8) -> *const u8 {
    // SAFETY: is_space(0) is false, so the scan stops at the caller's terminator and p+1 is only taken past a whitespace byte.
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

// Precondition: `s` and `fmt` are NUL-terminated C strings and `ap` carries one
// output pointer per conversion in `fmt`, each pointing at storage of the width
// the conversion's length modifier selects. Both scans stop at their terminator.
unsafe fn scan_c(mut s: *const u8, fmt: *const u8, ap: &mut VaList) -> i32 {
    if s.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    let mut assigned = 0i32;
    let mut fi = 0usize;
    loop {
        // SAFETY: fi only advances past format bytes proven non-NUL, so fmt+fi is at worst the terminator.
        let fc = unsafe { *fmt.add(fi) };
        if fc == 0 { return assigned; }
        if is_space(fc) {
            // SAFETY: is_space(0) is false, so this scan halts at fmt's NUL rather than running past it.
            while is_space(unsafe { *fmt.add(fi) }) { fi += 1; }
            // SAFETY: s points into the caller's NUL-terminated input, which is skip_ws's precondition.
            s = unsafe { skip_ws(s) };
            continue;
        }
        if fc != b'%' {
            // SAFETY: s is at or before its NUL; a mismatch returns before s advances, and fc != 0 so a match proves the byte is not the terminator.
            if unsafe { *s } != fc { return assigned; }
            // SAFETY: the byte at s equalled the non-NUL fc, so s+1 is at worst the terminator.
            s = unsafe { s.add(1) };
            fi += 1;
            continue;
        }
        fi += 1;
        // SAFETY: fmt[fi-1] was '%' so it was not the terminator, leaving fmt+fi at worst the NUL.
        let mut c = unsafe { *fmt.add(fi) };
        let mut width = usize::MAX;
        if c.is_ascii_digit() {
            width = 0;
            while c.is_ascii_digit() {
                width = width.saturating_mul(10).saturating_add((c - b'0') as usize);
                // SAFETY: c was a digit so fmt[fi] was not the terminator, leaving fmt+fi+1 at worst the NUL.
                fi += 1; c = unsafe { *fmt.add(fi) };
            }
        }
        let mut long = 0u8;
        while c == b'l' {
            long = long.saturating_add(1);
            // SAFETY: c was 'l' so fmt[fi] was not the terminator, leaving fmt+fi+1 at worst the NUL.
            fi += 1; c = unsafe { *fmt.add(fi) };
        }
        // SAFETY: s points into the caller's NUL-terminated input, which is skip_ws's precondition.
        s = unsafe { skip_ws(s) };
        match c {
            b'd' | b'i' => {
                // SAFETY: s points into the caller's NUL-terminated input, which is scan_signed_token's precondition.
                let (v, end, ok) = unsafe { scan_signed_token(s, 0) };
                if !ok { return assigned; }
                if long >= 2 {
                    // SAFETY: "%lld" obliges the caller to have pushed a pointer to i64 storage as this conversion's argument.
                    let out = unsafe { ap.next_arg::<*mut i64>() };
                    // SAFETY: out was null-checked and the "%lld" contract makes it aligned, writable i64 storage.
                    if !out.is_null() { unsafe { *out = v; } }
                } else if long == 1 {
                    // SAFETY: "%ld" obliges the caller to have pushed a pointer to long storage, which is i64 on both kernel targets.
                    let out = unsafe { ap.next_arg::<*mut i64>() };
                    // SAFETY: out was null-checked and the "%ld" contract makes it aligned, writable i64 storage.
                    if !out.is_null() { unsafe { *out = v; } }
                } else {
                    // SAFETY: "%d" obliges the caller to have pushed a pointer to int storage as this conversion's argument.
                    let out = unsafe { ap.next_arg::<*mut i32>() };
                    // SAFETY: out was null-checked and the "%d" contract makes it aligned, writable i32 storage.
                    if !out.is_null() { unsafe { *out = v as i32; } }
                }
                s = end; assigned += 1;
            }
            b'u' | b'x' => {
                let base = if c == b'x' { 16 } else { 10 };
                // SAFETY: s points into the caller's NUL-terminated input, which is parse_unsigned's precondition.
                let (v, end, ok) = unsafe { parse_unsigned(s, base, u64::MAX) };
                if !ok { return assigned; }
                if long >= 2 {
                    // SAFETY: "%llu"/"%llx" oblige the caller to have pushed a pointer to u64 storage for this conversion.
                    let out = unsafe { ap.next_arg::<*mut u64>() };
                    // SAFETY: out was null-checked and the long-long contract makes it aligned, writable u64 storage.
                    if !out.is_null() { unsafe { *out = v; } }
                } else {
                    // SAFETY: "%u"/"%x" oblige the caller to have pushed a pointer to unsigned-int storage for this conversion.
                    let out = unsafe { ap.next_arg::<*mut u32>() };
                    // SAFETY: out was null-checked and the "%u"/"%x" contract makes it aligned, writable u32 storage.
                    if !out.is_null() { unsafe { *out = v as u32; } }
                }
                s = end; assigned += 1;
            }
            b's' => {
                // SAFETY: "%s" obliges the caller to have pushed a char buffer able to hold the field width plus a terminator.
                let out = unsafe { ap.next_arg::<*mut u8>() };
                let mut n = 0usize;
                // SAFETY: s is at or before its NUL and the loop stops on that NUL, so every byte read is inside the input.
                while unsafe { *s } != 0 && !is_space(unsafe { *s }) && n < width {
                    // SAFETY: n < width and the "%s" contract sizes out for the field width; s is on a proven non-NUL byte.
                    if !out.is_null() { unsafe { *out.add(n) = *s; } }
                    // SAFETY: the byte at s was proven non-NUL by the loop condition, so s+1 is at worst the terminator.
                    n += 1; s = unsafe { s.add(1) };
                }
                if n == 0 { return assigned; }
                // SAFETY: n bytes were written, so index n is the terminator slot the "%s" contract reserves in out.
                if !out.is_null() { unsafe { *out.add(n) = 0; } }
                assigned += 1;
            }
            b'%' => {
                // SAFETY: s is at or before its NUL; a mismatch returns before s advances.
                if unsafe { *s } != b'%' { return assigned; }
                // SAFETY: the byte at s equalled '%' so it was not the terminator, leaving s+1 at worst the NUL.
                s = unsafe { s.add(1) };
            }
            _ => return assigned,
        }
        fi += 1;
    }
}

// Precondition: `s` points into a NUL-terminated C string.
unsafe fn scan_signed_token(s: *const u8, base: u32) -> (i64, *const u8, bool) {
    // SAFETY: s points into the caller's NUL-terminated string, which is skip_ws's precondition.
    let mut p = unsafe { skip_ws(s) };
    let mut neg = false;
    // SAFETY: skip_ws leaves p at or before the string's NUL, so this byte is readable.
    let c = unsafe { *p };
    if c == b'-' || c == b'+' {
        neg = c == b'-';
        // SAFETY: c is a sign byte, not the NUL, so p+1 is at worst the terminator.
        p = unsafe { p.add(1) };
    }
    // SAFETY: p indexes into the same NUL-terminated string, which is parse_unsigned's precondition.
    let (u, end, ok) = unsafe { parse_unsigned(p, base, i64::MAX as u64 + if neg { 1 } else { 0 }) };
    if !ok { return (0, s, false); }
    let v = if neg {
        if u == i64::MAX as u64 + 1 { i64::MIN } else { -(u as i64) }
    } else { u as i64 };
    (v, end, true)
}
