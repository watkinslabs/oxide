//! regex — POSIX <regex.h> (docs/59§6). ERE engine in engine.rs (VM approach);
//! this is the C ABI: regcomp/regexec/regfree/regerror over the glibc-layout
//! regex_t/regmatch_t. ERE (REG_EXTENDED) is fully supported; BRE maps to the
//! same operators (a pragmatic first pass). Leftmost match, greedy quantifiers.
pub mod engine;

// cflags (glibc values)
pub const REG_EXTENDED: i32 = 1;
pub const REG_ICASE: i32 = 2;
pub const REG_NEWLINE: i32 = 4;
pub const REG_NOSUB: i32 = 8;
// eflags
pub const REG_NOTBOL: i32 = 1;
pub const REG_NOTEOL: i32 = 2;
// error codes (glibc <regex.h> enum values)
pub const REG_NOMATCH: i32 = 1;
pub const REG_BADPAT: i32 = 2;
pub const REG_EESCAPE: i32 = 5;
pub const REG_EBRACK: i32 = 7;
pub const REG_EPAREN: i32 = 8;
pub const RE_SYNTAX_POSIX_BASIC: u64 = 16843462;

// glibc re_pattern_buffer (LP64, 64 bytes); programs read re_nsub (offset 48).
#[repr(C)]
pub struct regex_t {
    buffer: *mut core::ffi::c_void, // we stash a *mut engine::Prog here
    allocated: usize,
    used: usize,
    syntax: u64,
    fastmap: *mut u8,
    translate: *mut u8,
    pub re_nsub: usize,
    flags: u32,
    _pad: u32,
}

// regmatch_t { regoff_t rm_so; regoff_t rm_eo; } — regoff_t is int.
#[repr(C)]
pub struct regmatch_t { pub rm_so: i32, pub rm_eo: i32 }

#[repr(C)]
pub struct re_registers {
    pub num_regs: u32,
    pub start: *mut i32,
    pub end: *mut i32,
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::string::len::strlen_impl;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

    static RE_COMP_PROG: AtomicPtr<engine::Prog> = AtomicPtr::new(core::ptr::null_mut());
    #[no_mangle]
    pub static re_syntax_options: AtomicU64 = AtomicU64::new(0);

    #[repr(transparent)]
    struct PtrCell(UnsafeCell<*mut u8>);
    // SAFETY: loc1/loc2/locs are historical writable regexp C data symbols.
    unsafe impl Sync for PtrCell {}

    #[no_mangle]
    static loc1: PtrCell = PtrCell(UnsafeCell::new(core::ptr::null_mut()));
    #[no_mangle]
    static loc2: PtrCell = PtrCell(UnsafeCell::new(core::ptr::null_mut()));
    #[no_mangle]
    static locs: PtrCell = PtrCell(UnsafeCell::new(core::ptr::null_mut()));

    unsafe fn fill_registers(regs: *mut re_registers, caps: &[usize], base: i32) {
        // SAFETY: regs is null or a writable GNU re_registers. If its arrays
        // are absent or too small, allocate glibc-compatible int offset arrays.
        unsafe {
            if regs.is_null() {
                return;
            }
            let n = core::cmp::max(2, caps.len() / 2) as u32;
            if (*regs).start.is_null() || (*regs).end.is_null() || (*regs).num_regs < n {
                let bytes = n as usize * core::mem::size_of::<i32>();
                (*regs).start = crate::malloc::heap::malloc(bytes) as *mut i32;
                (*regs).end = crate::malloc::heap::malloc(bytes) as *mut i32;
                if (*regs).start.is_null() || (*regs).end.is_null() {
                    (*regs).num_regs = 0;
                    return;
                }
                (*regs).num_regs = n;
            }
            for i in 0..(*regs).num_regs as usize {
                let so = caps.get(2 * i).copied().unwrap_or(usize::MAX);
                let eo = caps.get(2 * i + 1).copied().unwrap_or(usize::MAX);
                if so == usize::MAX || eo == usize::MAX {
                    *(*regs).start.add(i) = -1;
                    *(*regs).end.add(i) = -1;
                } else {
                    *(*regs).start.add(i) = base + so as i32;
                    *(*regs).end.add(i) = base + eo as i32;
                }
            }
        }
    }

    unsafe fn concat_pair(s1: *const u8, len1: i32, s2: *const u8, len2: i32) -> Option<Vec<u8>> {
        // SAFETY: callers pass readable buffers for len1/len2 bytes.
        unsafe {
            if len1 < 0 || len2 < 0 {
                return None;
            }
            let mut out = Vec::with_capacity(len1 as usize + len2 as usize);
            out.extend_from_slice(core::slice::from_raw_parts(s1, len1 as usize));
            out.extend_from_slice(core::slice::from_raw_parts(s2, len2 as usize));
            Some(out)
        }
    }

    // # C: int regcomp(regex_t *preg, const char *pattern, int cflags)
    #[no_mangle]
    pub unsafe extern "C" fn regcomp(preg: *mut regex_t, pattern: *const u8, cflags: i32) -> i32 {
        // SAFETY: preg is writable; pattern is a NUL-terminated regex. Compile
        // into a heap engine::Prog whose pointer lives in preg->buffer.
        unsafe {
            let pat = core::slice::from_raw_parts(pattern, strlen_impl(pattern));
            match engine::compile_pattern(pat, cflags & REG_ICASE != 0, cflags & REG_NEWLINE != 0, cflags & REG_EXTENDED != 0) {
                Ok(prog) => {
                    let ng = prog.ngroup;
                    (*preg).buffer = Box::into_raw(Box::new(prog)) as *mut core::ffi::c_void;
                    (*preg).re_nsub = ng;
                    (*preg).flags = (cflags & REG_NOSUB) as u32;
                    0
                }
                Err(e) => e,
            }
        }
    }

    // # C: int regexec(const regex_t *preg, const char *string, size_t nmatch,
    //                  regmatch_t pmatch[], int eflags)
    #[no_mangle]
    pub unsafe extern "C" fn regexec(preg: *const regex_t, string: *const u8, nmatch: usize, pmatch: *mut regmatch_t, eflags: i32) -> i32 {
        // SAFETY: preg was filled by regcomp; string NUL-terminated; pmatch has
        // nmatch entries (or is null when nmatch==0 / REG_NOSUB).
        unsafe {
            let prog = &*((*preg).buffer as *const engine::Prog);
            let s = core::slice::from_raw_parts(string, strlen_impl(string));
            let notbol = eflags & REG_NOTBOL != 0;
            let noteol = eflags & REG_NOTEOL != 0;
            match engine::exec(prog, s, notbol, noteol) {
                None => REG_NOMATCH,
                Some(caps) => {
                    let nosub = (*preg).flags & REG_NOSUB as u32 != 0;
                    if !nosub && !pmatch.is_null() {
                        for k in 0..nmatch {
                            let (so, eo) = (caps.get(2 * k).copied(), caps.get(2 * k + 1).copied());
                            let m = &mut *pmatch.add(k);
                            match (so, eo) {
                                (Some(a), Some(b)) if a != usize::MAX && b != usize::MAX => { m.rm_so = a as i32; m.rm_eo = b as i32; }
                                _ => { m.rm_so = -1; m.rm_eo = -1; }
                            }
                        }
                    }
                    0
                }
            }
        }
    }

    // # C: void regfree(regex_t *preg)
    #[no_mangle]
    pub unsafe extern "C" fn regfree(preg: *mut regex_t) {
        // SAFETY: preg->buffer is a Box<Prog> from regcomp (or null); reclaim it.
        unsafe {
            if !(*preg).buffer.is_null() {
                drop(Box::from_raw((*preg).buffer as *mut engine::Prog));
                (*preg).buffer = core::ptr::null_mut();
            }
        }
    }

    // # C: size_t regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
    #[no_mangle]
    pub unsafe extern "C" fn regerror(errcode: i32, _preg: *const regex_t, errbuf: *mut u8, errbuf_size: usize) -> usize {
        // SAFETY: errbuf is writable for errbuf_size bytes (or 0). Copy the
        // C-locale message + NUL, truncating to fit; return the full length+1.
        unsafe {
            let msg: &[u8] = match errcode {
                REG_NOMATCH => b"No match",
                REG_BADPAT => b"Invalid regular expression",
                REG_EBRACK => b"Unmatched [, [^, [:, [., or [=",
                REG_EPAREN => b"Unmatched ( or \\(",
                REG_EESCAPE => b"Trailing backslash",
                _ => b"regex error",
            };
            let need = msg.len() + 1;
            if errbuf_size > 0 && !errbuf.is_null() {
                let n = core::cmp::min(msg.len(), errbuf_size - 1);
                core::ptr::copy_nonoverlapping(msg.as_ptr(), errbuf, n);
                *errbuf.add(n) = 0;
            }
            need
        }
    }

    // # C: const char *re_compile_pattern(const char *pattern, size_t length, struct re_pattern_buffer *buffer)
    #[no_mangle]
    pub unsafe extern "C" fn re_compile_pattern(pattern: *const u8, length: usize, buffer: *mut regex_t) -> *const u8 {
        // SAFETY: pattern is readable for length bytes and buffer is writable.
        // The compiled engine program is stored in buffer->buffer for re_match.
        unsafe {
            let pat = core::slice::from_raw_parts(pattern, length);
            let ere = re_syntax_options.load(Ordering::Acquire) != RE_SYNTAX_POSIX_BASIC;
            match engine::compile_pattern(pat, false, false, ere) {
                Ok(prog) => {
                    let ng = prog.ngroup;
                    (*buffer).buffer = Box::into_raw(Box::new(prog)) as *mut core::ffi::c_void;
                    (*buffer).re_nsub = ng;
                    (*buffer).flags = 0;
                    core::ptr::null()
                }
                Err(_) => b"Invalid regular expression\0".as_ptr(),
            }
        }
    }

    // # C: int re_compile_fastmap(struct re_pattern_buffer *buffer)
    #[no_mangle]
    pub unsafe extern "C" fn re_compile_fastmap(buffer: *mut regex_t) -> i32 {
        // SAFETY: buffer is a compiled pattern; fastmap is caller-owned storage
        // for 256 bytes when non-null. A conservative all-ones map is valid.
        unsafe {
            if buffer.is_null() || (*buffer).buffer.is_null() {
                return -2;
            }
            if !(*buffer).fastmap.is_null() {
                core::ptr::write_bytes((*buffer).fastmap, 1, 256);
            }
            0
        }
    }

    // # C: regoff_t re_match(struct re_pattern_buffer *buffer, const char *string, regoff_t length, regoff_t start, struct re_registers *regs)
    #[no_mangle]
    pub unsafe extern "C" fn re_match(buffer: *mut regex_t, string: *const u8, length: i32, start: i32, regs: *mut re_registers) -> i32 {
        // SAFETY: buffer holds an engine::Prog from re_compile_pattern; string
        // is readable for length bytes. regs is null or writable.
        unsafe {
            if buffer.is_null() || (*buffer).buffer.is_null() || start < 0 || length < start {
                return -2;
            }
            let prog = &*((*buffer).buffer as *const engine::Prog);
            let s = core::slice::from_raw_parts(string.add(start as usize), (length - start) as usize);
            match engine::exec(prog, s, false, false) {
                Some(caps) if caps.first().copied() == Some(0) => {
                    fill_registers(regs, &caps, start);
                    (caps.get(1).copied().unwrap_or(0)) as i32
                }
                _ => -1,
            }
        }
    }

    // # C: regoff_t re_search(struct re_pattern_buffer *buffer, const char *string, regoff_t length, regoff_t start, regoff_t range, struct re_registers *regs)
    #[no_mangle]
    pub unsafe extern "C" fn re_search(buffer: *mut regex_t, string: *const u8, length: i32, start: i32, range: i32, regs: *mut re_registers) -> i32 {
        // SAFETY: buffer holds an engine::Prog; string is readable for length
        // bytes. This supports the common forward-search range used by glibc.
        unsafe {
            if buffer.is_null() || (*buffer).buffer.is_null() || start < 0 || range < 0 || length < start {
                return -2;
            }
            let avail = core::cmp::min(length - start, range) as usize;
            let prog = &*((*buffer).buffer as *const engine::Prog);
            let s = core::slice::from_raw_parts(string.add(start as usize), avail);
            match engine::exec(prog, s, false, false) {
                Some(caps) => {
                    let off = caps.first().copied().unwrap_or(usize::MAX);
                    if off == usize::MAX {
                        return -1;
                    }
                    fill_registers(regs, &caps, start);
                    start + off as i32
                }
                None => -1,
            }
        }
    }

    // # C: regoff_t re_search_2(struct re_pattern_buffer *buffer, const char *s1, regoff_t len1, const char *s2, regoff_t len2, regoff_t start, regoff_t range, struct re_registers *regs, regoff_t stop)
    #[no_mangle]
    pub unsafe extern "C" fn re_search_2(buffer: *mut regex_t, s1: *const u8, len1: i32, s2: *const u8, len2: i32, start: i32, range: i32, regs: *mut re_registers, stop: i32) -> i32 {
        // SAFETY: s1/s2 are readable for len1/len2 bytes; buffer holds an
        // engine::Prog from re_compile_pattern.
        unsafe {
            let Some(joined) = concat_pair(s1, len1, s2, len2) else {
                return -2;
            };
            if buffer.is_null() || (*buffer).buffer.is_null() || start < 0 || range < 0 || stop < start || joined.len() < start as usize {
                return -2;
            }
            let end = core::cmp::min(joined.len(), core::cmp::min(stop as usize, (start + range) as usize));
            let prog = &*((*buffer).buffer as *const engine::Prog);
            match engine::exec(prog, &joined[start as usize..end], false, false) {
                Some(caps) => {
                    let off = caps.first().copied().unwrap_or(usize::MAX);
                    if off == usize::MAX {
                        return -1;
                    }
                    fill_registers(regs, &caps, start);
                    start + off as i32
                }
                None => -1,
            }
        }
    }

    // # C: regoff_t re_match_2(struct re_pattern_buffer *buffer, const char *s1, regoff_t len1, const char *s2, regoff_t len2, regoff_t start, struct re_registers *regs, regoff_t stop)
    #[no_mangle]
    pub unsafe extern "C" fn re_match_2(buffer: *mut regex_t, s1: *const u8, len1: i32, s2: *const u8, len2: i32, start: i32, regs: *mut re_registers, stop: i32) -> i32 {
        // SAFETY: s1/s2 are readable for len1/len2 bytes; buffer holds an
        // engine::Prog from re_compile_pattern.
        unsafe {
            let Some(joined) = concat_pair(s1, len1, s2, len2) else {
                return -2;
            };
            if buffer.is_null() || (*buffer).buffer.is_null() || start < 0 || stop < start || joined.len() < start as usize {
                return -2;
            }
            let end = core::cmp::min(joined.len(), stop as usize);
            let prog = &*((*buffer).buffer as *const engine::Prog);
            match engine::exec(prog, &joined[start as usize..end], false, false) {
                Some(caps) if caps.first().copied() == Some(0) => {
                    fill_registers(regs, &caps, start);
                    (caps.get(1).copied().unwrap_or(0)) as i32
                }
                _ => -1,
            }
        }
    }

    // # C: void re_set_registers(struct re_pattern_buffer *buffer, struct re_registers *regs, size_t num_regs, regoff_t *starts, regoff_t *ends)
    #[no_mangle]
    pub unsafe extern "C" fn re_set_registers(_buffer: *mut regex_t, regs: *mut re_registers, num_regs: usize, starts: *mut i32, ends: *mut i32) {
        // SAFETY: regs is writable; starts/ends are caller-owned arrays.
        unsafe {
            if !regs.is_null() {
                (*regs).num_regs = num_regs as u32;
                (*regs).start = starts;
                (*regs).end = ends;
            }
        }
    }

    // # C: reg_syntax_t re_set_syntax(reg_syntax_t syntax)
    #[no_mangle]
    pub extern "C" fn re_set_syntax(syntax: u64) -> u64 {
        re_syntax_options.swap(syntax, Ordering::AcqRel)
    }

    // # C: char *re_comp(const char *pattern)
    #[no_mangle]
    pub unsafe extern "C" fn re_comp(pattern: *const u8) -> *const u8 {
        // SAFETY: pattern is null or a NUL-terminated regex. The obsolete BSD
        // API stores one process-global compiled program for re_exec.
        unsafe {
            if pattern.is_null() {
                return core::ptr::null();
            }
            let pat = core::slice::from_raw_parts(pattern, strlen_impl(pattern));
            match engine::compile_pattern(pat, false, false, true) {
                Ok(prog) => {
                    let new = Box::into_raw(Box::new(prog));
                    let old = RE_COMP_PROG.swap(new, Ordering::AcqRel);
                    if !old.is_null() {
                        drop(Box::from_raw(old));
                    }
                    core::ptr::null()
                }
                Err(_) => b"Invalid regular expression\0".as_ptr(),
            }
        }
    }

    // # C: int re_exec(const char *string)
    #[no_mangle]
    pub unsafe extern "C" fn re_exec(string: *const u8) -> i32 {
        // SAFETY: string is NUL-terminated; RE_COMP_PROG is the process-global
        // compiled program from re_comp. glibc returns 1 for match, 0 otherwise.
        unsafe {
            let prog = RE_COMP_PROG.load(Ordering::Acquire);
            if prog.is_null() {
                return 0;
            }
            let s = core::slice::from_raw_parts(string, strlen_impl(string));
            if engine::exec(&*prog, s, false, false).is_some() { 1 } else { 0 }
        }
    }

    unsafe fn legacy_regex(string: *const u8, expbuf: *const u8, anchored: bool) -> i32 {
        // SAFETY: string and expbuf are NUL-terminated byte strings supplied by
        // the caller. The obsolete API stores match bounds in loc1/loc2.
        unsafe {
            if string.is_null() || expbuf.is_null() {
                return 0;
            }
            let pat = core::slice::from_raw_parts(expbuf, strlen_impl(expbuf));
            let s = core::slice::from_raw_parts(string, strlen_impl(string));
            let Ok(prog) = engine::compile_pattern(pat, false, false, true) else {
                return 0;
            };
            let Some(caps) = engine::exec(&prog, s, false, false) else {
                return 0;
            };
            let start = caps.first().copied().unwrap_or(usize::MAX);
            let end = caps.get(1).copied().unwrap_or(usize::MAX);
            if start == usize::MAX || end == usize::MAX || (anchored && start != 0) {
                return 0;
            }
            *loc1.0.get() = string.add(start) as *mut u8;
            *loc2.0.get() = string.add(end) as *mut u8;
            1
        }
    }

    // # C: int step(const char *string, const char *expbuf)
    #[no_mangle]
    pub unsafe extern "C" fn step(string: *const u8, expbuf: *const u8) -> i32 {
        // SAFETY: forwards the NUL-terminated legacy regexp operands to the
        // shared compatibility matcher.
        unsafe { legacy_regex(string, expbuf, false) }
    }

    // # C: int advance(const char *string, const char *expbuf)
    #[no_mangle]
    pub unsafe extern "C" fn advance(string: *const u8, expbuf: *const u8) -> i32 {
        // SAFETY: forwards the NUL-terminated legacy regexp operands to the
        // shared compatibility matcher, requiring a match at string start.
        unsafe { legacy_regex(string, expbuf, true) }
    }

    // # C: void tr_break(void)
    #[no_mangle]
    pub extern "C" fn tr_break() {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_layout() {
        assert_eq!(core::mem::size_of::<super::regex_t>(), 64);
        assert_eq!(core::mem::offset_of!(super::regex_t, re_nsub), 48);
        assert_eq!(core::mem::size_of::<super::regmatch_t>(), 8);
    }
}
