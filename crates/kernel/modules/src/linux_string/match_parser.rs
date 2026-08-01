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
        // SAFETY: the loop guard keeps pi < plen == strlen(pat), so this byte precedes pat's terminator.
        let pc = unsafe { *pat.add(pi) };
        if pc != b'%' {
            // SAFETY: si >= slen short-circuits first, so si < strlen(s) and this byte precedes s's terminator.
            if si >= slen || unsafe { *s.add(si) } != pc { return false; }
            pi += 1; si += 1; continue;
        }
        pi += 1;
        // SAFETY: pat[pi-1] was '%' so pi is at most plen, the index of pat's own terminator.
        let kind = unsafe { *pat.add(pi) };
        if !matches!(kind, b's' | b'd' | b'u') { return false; }
        pi += 1;
        let start = si;
        while si < slen {
            // SAFETY: si < slen bounds the s read, and the pi < plen guard short-circuits before the pat read, so both precede their terminators.
            if pi < plen && unsafe { *s.add(si) } == unsafe { *pat.add(pi) } { break; }
            si += 1;
        }
        if start == si { return false; }
        if ai >= MAX_OPT_ARGS { return false; }
        if !args.is_null() {
            // SAFETY: ai < MAX_OPT_ARGS was just checked and the caller's args array holds that many substrings; start and si are both <= strlen(s), so the recorded bounds stay inside s.
            unsafe {
                (*args.add(ai)).from = s.add(start);
                (*args.add(ai)).to = s.add(si);
            }
        }
        ai += 1;
    }
    si == slen
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
