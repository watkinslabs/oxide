// getsubopt(3) (docs/59§6 G7). Parse the next comma-separated sub-option from
// *optionp in place: split name/value at '=', NUL the separators, advance
// *optionp. On a match against `tokens` return the index and set *valuep to the
// value (or NULL); on no match return -1 and set *valuep to the token text. C ABI.
#![cfg(feature = "freestanding")]
use crate::string::cmp::strcmp_impl;

// # C: int getsubopt(char **optionp, char *const *tokens, char **valuep)
#[no_mangle]
pub unsafe extern "C" fn getsubopt(optionp: *mut *mut u8, tokens: *const *const u8, valuep: *mut *mut u8) -> i32 {
    // SAFETY: *optionp is a mutable NUL-terminated string we may write NULs into;
    // tokens is a NULL-terminated array of NUL-terminated names; valuep is a
    // writable out-param. All scans stop at the option string's terminator.
    unsafe {
        let start = *optionp;
        if start.is_null() || *start == 0 { *valuep = core::ptr::null_mut(); return -1; }
        // scan to the end of this sub-option, noting the first '='
        let mut p = start;
        let mut eq: *mut u8 = core::ptr::null_mut();
        while *p != 0 && *p != b',' { if *p == b'=' && eq.is_null() { eq = p; } p = p.add(1); }
        if *p == b',' { *p = 0; *optionp = p.add(1); } else { *optionp = p; }
        let value = if !eq.is_null() { *eq = 0; eq.add(1) } else { core::ptr::null_mut() };
        let mut i = 0;
        loop {
            let tok = *tokens.add(i);
            if tok.is_null() { break; }
            if strcmp_impl(start, tok) == 0 { *valuep = value; return i as i32; }
            i += 1;
        }
        *valuep = start; // unrecognised: hand back the token text
        -1
    }
}
