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

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::string::len::strlen_impl;
    use alloc::boxed::Box;

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
