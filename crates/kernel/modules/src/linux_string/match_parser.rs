use core::ptr::{copy_nonoverlapping, null_mut};

use crate::linux_alloc::alloc_bytes;
use super::cstr::{c_strlen, strcmp};
use super::parse::{parse_decimal_i32, parse_decimal_u64};
use crate::linux_errno;
use syscall::errno::Errno;

#[repr(C)]
pub(crate) struct Substring {
    pub(crate) from: *const u8,
    pub(crate) to: *const u8,
}

// Widest `args` array a match_token caller is obliged to provide; patterns carrying more
// conversions than this never match, so the fill below can never run off the array.
const MAX_OPT_ARGS: usize = 3;

#[repr(C)]
pub(crate) struct MatchToken {
    pub(crate) token: i32,
    pub(crate) pattern: *const u8,
}

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("match_token",  match_token  as *const () as usize),
        ("match_strdup", match_strdup as *const () as usize),
        ("match_int",    match_int    as *const () as usize),
        ("match_u64",    match_u64    as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) unsafe extern "C" fn match_token(s: *const u8, table: *const MatchToken, args: *mut Substring) -> i32 {
    if s.is_null() || table.is_null() { return -1; }
    let mut i = 0usize;
    loop {
        // SAFETY: table was null-checked and its contract terminates it with a null-pattern entry; i only advances past entries whose pattern was non-null.
        let ent = unsafe { table.add(i) };
        // SAFETY: ent is entry i of the caller's token table, so its pattern field is initialized.
        let pat = unsafe { (*ent).pattern };
        if pat.is_null() { return -1; }
        // SAFETY: s was null-checked and pat is this entry's NUL-terminated pattern; args is the caller's MAX_OPT_ARGS substring array, and the token read is the same in-bounds entry.
        if unsafe { pattern_match(s, pat, args) } { return unsafe { (*ent).token }; }
        i += 1;
    }
}

unsafe extern "C" fn match_strdup(sub: *const Substring) -> *mut u8 {
    if sub.is_null() { return null_mut(); }
    // SAFETY: sub was null-checked and match_strdup's contract makes it a substring previously filled in by match_token.
    let (from, to) = unsafe { ((*sub).from, (*sub).to) };
    if from.is_null() || to < from { return null_mut(); }
    let len = to as usize - from as usize;
    let p = alloc_bytes(len + 1, core::mem::align_of::<usize>(), false);
    if p.is_null() { return null_mut(); }
    // SAFETY: len is to-from with to >= from, so from..to is the match_token-recorded slice of the option string; p was just allocated with len+1 bytes, making index len its terminator slot.
    unsafe { copy_nonoverlapping(from, p, len); *p.add(len) = 0; }
    p
}

pub(crate) unsafe extern "C" fn match_int(sub: *const Substring, out: *mut i32) -> i32 {
    if sub.is_null() || out.is_null() { return linux_errno(Errno::Einval); }
    let mut tmp = [0u8; 32];
    // SAFETY: sub was null-checked, and tmp.len() is the true capacity of the stack buffer copy_substring bounds its write by.
    let len = unsafe { copy_substring(sub, tmp.as_mut_ptr(), tmp.len()) };
    if len == 0 { return linux_errno(Errno::Einval); }
    // SAFETY: copy_substring wrote a terminator at index len, so tmp is the NUL-terminated string parse_decimal_i32 requires.
    match unsafe { parse_decimal_i32(tmp.as_ptr()) } {
        // SAFETY: out was null-checked and match_int's contract makes it aligned, writable int storage.
        Ok(v) => { unsafe { *out = v; } 0 }
        Err(e) => e,
    }
}

unsafe extern "C" fn match_u64(sub: *const Substring, out: *mut u64) -> i32 {
    if sub.is_null() || out.is_null() { return linux_errno(Errno::Einval); }
    let mut tmp = [0u8; 40];
    // SAFETY: sub was null-checked, and tmp.len() is the true capacity of the stack buffer copy_substring bounds its write by.
    let len = unsafe { copy_substring(sub, tmp.as_mut_ptr(), tmp.len()) };
    if len == 0 { return linux_errno(Errno::Einval); }
    // SAFETY: copy_substring wrote a terminator at index len, so tmp is the NUL-terminated string parse_decimal_u64 requires.
    match unsafe { parse_decimal_u64(tmp.as_ptr()) } {
        // SAFETY: out was null-checked and match_u64's contract makes it aligned, writable u64 storage.
        Ok(v) => { unsafe { *out = v; } 0 }
        Err(e) => e,
    }
}

// Precondition: `s` and `pat` are NUL-terminated C strings and `args` is null or an array
// of at least MAX_OPT_ARGS substrings. Reads below are bounded by strlen of the two
// strings, and the recorded substrings point into `s` itself.
unsafe fn pattern_match(s: *const u8, pat: *const u8, args: *mut Substring) -> bool {
    // SAFETY: pattern_match's precondition makes both s and pat NUL-terminated, which is what strcmp scans for.
    if unsafe { strcmp(s, pat) } == 0 { return true; }
    // SAFETY: pat is the token table's NUL-terminated pattern, which is c_strlen's precondition.
    let plen = unsafe { c_strlen(pat) };
    // SAFETY: s is the caller's NUL-terminated option string, which is c_strlen's precondition.
    let slen = unsafe { c_strlen(s) };
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut ai = 0usize;
    while pi < plen {
        // SAFETY: pi < plen keeps this read before pat's terminator.
        if unsafe { *pat.add(pi) } != b'%' {
            // SAFETY: si < slen is checked before this read, and pi < plen is the loop invariant.
            if si >= slen || unsafe { *s.add(si) } != unsafe { *pat.add(pi) } { return false; }
            pi += 1;
            si += 1;
            continue;
        }
        pi += 1;
        let mut width = None;
        while pi < plen {
            // SAFETY: pi < plen keeps this read before pat's terminator.
            let digit = unsafe { *pat.add(pi) };
            if !digit.is_ascii_digit() { break; }
            width = Some(width.unwrap_or(0usize).saturating_mul(10).saturating_add((digit - b'0') as usize));
            pi += 1;
        }
        if pi >= plen { return false; }
        // SAFETY: pi < plen keeps this read before pat's terminator.
        let kind = unsafe { *pat.add(pi) };
        pi += 1;
        if kind == b'%' {
            if width.is_some() { return false; }
            // SAFETY: si < slen is checked before this read.
            if si >= slen || unsafe { *s.add(si) } != b'%' { return false; }
            si += 1;
            continue;
        }
        if ai >= MAX_OPT_ARGS { return false; }
        let start = si;
        let end = match kind {
            b's' => {
                if si == slen { return false; }
                Some(core::cmp::min(slen, si.saturating_add(width.unwrap_or(slen))))
            }
            // SAFETY: s is NUL-terminated and si..slen is its validated contents.
            b'd' => unsafe { scan_number(s, si, slen, 0, true) },
            // SAFETY: s is NUL-terminated and si..slen is its validated contents.
            b'u' => unsafe { scan_number(s, si, slen, 0, false) },
            // SAFETY: s is NUL-terminated and si..slen is its validated contents.
            b'o' => unsafe { scan_number(s, si, slen, 8, false) },
            // SAFETY: s is NUL-terminated and si..slen is its validated contents.
            b'x' => unsafe { scan_number(s, si, slen, 16, false) },
            _ => return false,
        };
        let Some(end) = end else { return false; };
        if !args.is_null() {
            // SAFETY: ai < MAX_OPT_ARGS was checked and start..end lies within s's NUL-terminated contents.
            unsafe { (*args.add(ai)).from = s.add(start); (*args.add(ai)).to = s.add(end); }
        }
        si = end;
        ai += 1;
    }
    si == slen
}

// Returns the end of the simple_strto* compatible numeric prefix, if any.
unsafe fn scan_number(s: *const u8, mut at: usize, slen: usize, mut base: u8, signed: bool) -> Option<usize> {
    if at < slen {
        // SAFETY: at < slen keeps this sign read before s's terminator.
        let sign = unsafe { *s.add(at) };
        if sign == b'+' || (signed && sign == b'-') { at += 1; }
    }
    let start = at;
    if base == 0 {
        base = 10;
        if at < slen {
            // SAFETY: at < slen keeps this radix-prefix read before s's terminator.
            let first = unsafe { *s.add(at) };
            if first == b'0' {
                base = 8;
                if at + 1 < slen {
                    // SAFETY: at + 1 < slen keeps this radix tag read before s's terminator.
                    let tag = unsafe { *s.add(at + 1) };
                    if matches!(tag, b'x' | b'X') { base = 16; at += 2; }
                }
            }
        }
    } else if base == 16 && at + 1 < slen {
        // SAFETY: at + 1 < slen keeps both hexadecimal-prefix reads before s's terminator.
        let (first, tag) = unsafe { (*s.add(at), *s.add(at + 1)) };
        if first == b'0' && matches!(tag, b'x' | b'X') { at += 2; }
    }
    let digits = at;
    while at < slen {
        // SAFETY: at < slen keeps this read before s's terminator.
        let c = unsafe { *s.add(at) };
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        if value >= base { break; }
        at += 1;
    }
    if at == digits || (digits == start && at == start) { None } else { Some(at) }
}

// Precondition: `sub` is a readable Substring and `dst` is writable for `cap` bytes.
unsafe fn copy_substring(sub: *const Substring, dst: *mut u8, cap: usize) -> usize {
    // SAFETY: both callers null-check sub before passing it, and its fields were filled in by match_token.
    let (from, to) = unsafe { ((*sub).from, (*sub).to) };
    if from.is_null() || to < from || cap == 0 { return 0; }
    let len = core::cmp::min(to as usize - from as usize, cap - 1);
    // SAFETY: len <= to-from so the read stays inside the recorded substring, and len <= cap-1 so index len is the last of dst's cap bytes.
    unsafe { copy_nonoverlapping(from, dst, len); *dst.add(len) = 0; }
    len
}
