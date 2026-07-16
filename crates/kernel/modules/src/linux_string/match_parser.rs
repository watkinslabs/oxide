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
        let ent = unsafe { table.add(i) };
        let pat = unsafe { (*ent).pattern };
        if pat.is_null() { return -1; }
        if unsafe { pattern_match(s, pat, args) } { return unsafe { (*ent).token }; }
        i += 1;
    }
}

unsafe extern "C" fn match_strdup(sub: *const Substring) -> *mut u8 {
    if sub.is_null() { return null_mut(); }
    let (from, to) = unsafe { ((*sub).from, (*sub).to) };
    if from.is_null() || to < from { return null_mut(); }
    let len = to as usize - from as usize;
    let p = alloc_bytes(len + 1, core::mem::align_of::<usize>(), false);
    if p.is_null() { return null_mut(); }
    // SAFETY: p has len+1 bytes and substring bounds came from match_token.
    unsafe { copy_nonoverlapping(from, p, len); *p.add(len) = 0; }
    p
}

pub(crate) unsafe extern "C" fn match_int(sub: *const Substring, out: *mut i32) -> i32 {
    if sub.is_null() || out.is_null() { return linux_errno(Errno::Einval); }
    let mut tmp = [0u8; 32];
    let len = unsafe { copy_substring(sub, tmp.as_mut_ptr(), tmp.len()) };
    if len == 0 { return linux_errno(Errno::Einval); }
    match unsafe { parse_decimal_i32(tmp.as_ptr()) } {
        Ok(v) => { unsafe { *out = v; } 0 }
        Err(e) => e,
    }
}

unsafe extern "C" fn match_u64(sub: *const Substring, out: *mut u64) -> i32 {
    if sub.is_null() || out.is_null() { return linux_errno(Errno::Einval); }
    let mut tmp = [0u8; 40];
    let len = unsafe { copy_substring(sub, tmp.as_mut_ptr(), tmp.len()) };
    if len == 0 { return linux_errno(Errno::Einval); }
    match unsafe { parse_decimal_u64(tmp.as_ptr()) } {
        Ok(v) => { unsafe { *out = v; } 0 }
        Err(e) => e,
    }
}

unsafe fn pattern_match(s: *const u8, pat: *const u8, args: *mut Substring) -> bool {
    if unsafe { strcmp(s, pat) } == 0 { return true; }
    let plen = unsafe { c_strlen(pat) };
    let slen = unsafe { c_strlen(s) };
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut ai = 0usize;
    while pi < plen {
        let pc = unsafe { *pat.add(pi) };
        if pc != b'%' {
            if si >= slen || unsafe { *s.add(si) } != pc { return false; }
            pi += 1; si += 1; continue;
        }
        pi += 1;
        let kind = unsafe { *pat.add(pi) };
        if !matches!(kind, b's' | b'd' | b'u') { return false; }
        pi += 1;
        let start = si;
        while si < slen {
            if pi < plen && unsafe { *s.add(si) } == unsafe { *pat.add(pi) } { break; }
            si += 1;
        }
        if start == si { return false; }
        if !args.is_null() {
            unsafe {
                (*args.add(ai)).from = s.add(start);
                (*args.add(ai)).to = s.add(si);
            }
        }
        ai += 1;
    }
    si == slen
}

unsafe fn copy_substring(sub: *const Substring, dst: *mut u8, cap: usize) -> usize {
    let (from, to) = unsafe { ((*sub).from, (*sub).to) };
    if from.is_null() || to < from || cap == 0 { return 0; }
    let len = core::cmp::min(to as usize - from as usize, cap - 1);
    unsafe { copy_nonoverlapping(from, dst, len); *dst.add(len) = 0; }
    len
}
