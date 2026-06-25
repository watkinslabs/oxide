// getopt / getopt_long (docs/59§6 G8). Clustered short opts, required (x:) and
// optional (x::) args, "--" terminator, leading ':' error mode, '+'/'-'
// optstring prefixes, GNU argv permutation (options after operands move to the
// front; non-options gather at the end), and getopt_long unambiguous
// abbreviation. optind==0 fully reinitializes (GNU reset).
//
// The parse core is a state machine over a &mut [*const u8] argv (permuted in
// place) + an `St` cursor (unit-tested); the #[no_mangle] exports drive it
// through the C globals optarg/optind/opterr/optopt.

const REQUIRE_ORDER: u8 = 1; // optstring "+...": POSIX, stop at first operand
const RETURN_IN_ORDER: u8 = 2; // optstring "-...": operands returned as code 1
const PERMUTE: u8 = 0; // default: permute argv so options precede operands

pub(crate) struct St { pub optind: i32, pub optarg: *mut u8, pub optopt: i32, pub pos: usize, pub first_nonopt: i32, pub last_nonopt: i32 }
impl St {
    /// # C: initial getopt cursor (optind=1)
    pub(crate) const fn new() -> St { St { optind: 1, optarg: core::ptr::null_mut(), optopt: 0, pos: 0, first_nonopt: 1, last_nonopt: 1 } }
}

unsafe fn cstr_byte(p: *const u8, i: usize) -> u8 {
    // SAFETY: p is NUL-terminated; callers index within its length.
    unsafe { *p.add(i) }
}
unsafe fn is_opt(a: *const u8) -> bool {
    // SAFETY: a is null or a NUL-terminated C string; "-x" (not "-" alone).
    unsafe { !a.is_null() && cstr_byte(a, 0) == b'-' && cstr_byte(a, 1) != 0 }
}
unsafe fn is_ddash(a: *const u8) -> bool {
    // SAFETY: a is null or NUL-terminated; matches exactly "--".
    unsafe { !a.is_null() && cstr_byte(a, 0) == b'-' && cstr_byte(a, 1) == b'-' && cstr_byte(a, 2) == 0 }
}
/// # C: scanning mode from the optstring leading flag (+/-/none)
pub(crate) fn opt_mode(optstring: *const u8) -> u8 {
    // SAFETY: optstring is NUL-terminated; read the leading mode flag.
    match unsafe { cstr_byte(optstring, 0) } { b'+' => REQUIRE_ORDER, b'-' => RETURN_IN_ORDER, _ => PERMUTE }
}

// Rotate the skipped non-option block [first_nonopt,last_nonopt) past the
// options [last_nonopt,optind) just consumed, so options stay left-packed.
fn exchange(argv: &mut [*const u8], st: &mut St) {
    let (bottom, middle, top) = (st.first_nonopt as usize, st.last_nonopt as usize, st.optind as usize);
    argv[bottom..top].rotate_left(middle - bottom);
    st.first_nonopt += (top - middle) as i32;
    st.last_nonopt = st.optind;
}

// Position optind at the next option (permuting/skipping operands per mode).
// Returns Some(rv) if the scan is finished for this step (-1 end, or 1 for a
// RETURN_IN_ORDER operand with optarg set), or None when optind now points at
// an option and pos has been set to 1.
pub(crate) unsafe fn advance(argv: &mut [*const u8], mode: u8, st: &mut St) -> Option<i32> {
    // SAFETY: argv entries are NUL-terminated; permutation only reorders the
    // pointer array within bounds.
    unsafe {
        let argc = argv.len() as i32;
        if mode == PERMUTE {
            if st.first_nonopt != st.last_nonopt && st.last_nonopt != st.optind { exchange(argv, st); }
            else if st.last_nonopt != st.optind { st.first_nonopt = st.optind; }
            while st.optind < argc {
                let a = argv[st.optind as usize];
                if is_opt(a) || is_ddash(a) { break; }
                st.optind += 1;
            }
            st.last_nonopt = st.optind;
        }
        // "--" terminator
        if st.optind < argc && is_ddash(argv[st.optind as usize]) {
            st.optind += 1;
            if mode == PERMUTE {
                if st.first_nonopt != st.last_nonopt && st.last_nonopt != st.optind { exchange(argv, st); }
                else if st.first_nonopt == st.last_nonopt { st.first_nonopt = st.optind; }
                st.last_nonopt = argc;
                st.optind = argc;
            }
        }
        if st.optind >= argc {
            if st.first_nonopt != st.last_nonopt { st.optind = st.first_nonopt; }
            return Some(-1);
        }
        let arg = argv[st.optind as usize];
        if !is_opt(arg) {
            // reachable only in non-PERMUTE modes (PERMUTE skipped operands)
            if mode == RETURN_IN_ORDER { st.optarg = arg as *mut u8; st.optind += 1; return Some(1); }
            return Some(-1); // REQUIRE_ORDER
        }
        st.pos = 1;
        None
    }
}

// Find `c` in optstring; return Some(index) of the char (so the caller can
// peek the following ':' markers), or None.
unsafe fn find_opt(optstr: *const u8, c: u8) -> Option<usize> {
    // SAFETY: optstr is NUL-terminated; scan stops at the terminator.
    unsafe {
        if c == b':' { return None; }
        let mut i = 0;
        loop {
            let o = *optstr.add(i);
            if o == 0 { return None; }
            if o == c { return Some(i); }
            i += 1;
        }
    }
}

// One getopt step over argv. Returns the option char, or -1 at end, '?'/':' on
// error. Permutes argv and updates `st`.
pub(crate) unsafe fn getopt_core(argv: &mut [*const u8], optstring: *const u8, st: &mut St) -> i32 {
    // SAFETY: argv entries are NUL-terminated C strings; optstring too.
    unsafe {
        st.optarg = core::ptr::null_mut();
        let argc = argv.len() as i32;
        let mut optstr = optstring;
        let mode = opt_mode(optstr);
        if mode != PERMUTE { optstr = optstr.add(1); }
        let colon_mode = cstr_byte(optstr, 0) == b':';

        if st.pos == 0 {
            if let Some(rv) = advance(argv, mode, st) { return rv; }
        }
        let arg = argv[st.optind as usize];
        let c = cstr_byte(arg, st.pos);
        st.pos += 1;
        let at_end = cstr_byte(arg, st.pos) == 0;
        match find_opt(optstr, c) {
            None => {
                st.optopt = c as i32;
                if at_end { st.optind += 1; st.pos = 0; }
                b'?' as i32 // unknown option is '?' in both modes
            }
            Some(oi) => {
                let next = cstr_byte(optstr, oi + 1);
                if next == b':' {
                    let optional = cstr_byte(optstr, oi + 2) == b':';
                    if !at_end {
                        // rest of this arg is the option-arg
                        st.optarg = arg.add(st.pos) as *mut u8;
                        st.optind += 1;
                        st.pos = 0;
                    } else if optional {
                        st.optarg = core::ptr::null_mut(); // optional, none given
                        st.optind += 1;
                        st.pos = 0;
                    } else {
                        // required arg = next argv element
                        st.optind += 1;
                        st.pos = 0;
                        if st.optind >= argc {
                            st.optopt = c as i32;
                            return if colon_mode { b':' as i32 } else { b'?' as i32 };
                        }
                        st.optarg = argv[st.optind as usize] as *mut u8;
                        st.optind += 1;
                    }
                } else if at_end {
                    st.optind += 1;
                    st.pos = 0;
                }
                c as i32
            }
        }
    }
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::string::len::strlen_impl;
    use core::cell::UnsafeCell;

    #[repr(transparent)]
    struct I32(UnsafeCell<i32>);
    // SAFETY: getopt is single-threaded per its contract; the globals are
    // process-wide and only touched from getopt.
    unsafe impl Sync for I32 {}
    #[repr(transparent)]
    struct Ptr(UnsafeCell<*mut u8>);
    unsafe impl Sync for Ptr {}

    // # C: char *optarg; int optind=1, opterr=1, optopt;
    #[no_mangle]
    static optarg: Ptr = Ptr(UnsafeCell::new(core::ptr::null_mut()));
    #[no_mangle]
    static optind: I32 = I32(UnsafeCell::new(1));
    #[no_mangle]
    static opterr: I32 = I32(UnsafeCell::new(1));
    #[no_mangle]
    static optopt: I32 = I32(UnsafeCell::new(0));

    // internal cursor position within a clustered short-opt arg, plus the
    // permutation bookkeeping (the skipped non-option run [FIRST,LAST)).
    static POS: I32 = I32(UnsafeCell::new(0));
    static FIRST_NONOPT: I32 = I32(UnsafeCell::new(1));
    static LAST_NONOPT: I32 = I32(UnsafeCell::new(1));

    // Load the global cursor into an St; optind==0 fully reinitializes (GNU
    // reset, used by callers to restart scanning over a new argv).
    unsafe fn load_st() -> St {
        // SAFETY: reads the process-global getopt cursor.
        unsafe {
            if *optind.0.get() == 0 {
                *optind.0.get() = 1; *POS.0.get() = 0; *FIRST_NONOPT.0.get() = 1; *LAST_NONOPT.0.get() = 1;
            }
            St { optind: *optind.0.get(), optarg: core::ptr::null_mut(), optopt: *optopt.0.get(),
                 pos: *POS.0.get() as usize, first_nonopt: *FIRST_NONOPT.0.get(), last_nonopt: *LAST_NONOPT.0.get() }
        }
    }
    unsafe fn store_st(st: &St) {
        // SAFETY: writes the process-global getopt cursor back.
        unsafe {
            *optind.0.get() = st.optind; *optarg.0.get() = st.optarg; *optopt.0.get() = st.optopt;
            *POS.0.get() = st.pos as i32; *FIRST_NONOPT.0.get() = st.first_nonopt; *LAST_NONOPT.0.get() = st.last_nonopt;
        }
    }

    unsafe fn run(argc: i32, argv: *mut *mut u8, optstring: *const u8) -> i32 {
        // SAFETY: argv is the program's argv (argc entries); the core may
        // permute the pointer array in place.
        unsafe {
            let slice = core::slice::from_raw_parts_mut(argv as *mut *const u8, argc as usize);
            let mut st = load_st();
            let r = getopt_core(slice, optstring, &mut st);
            store_st(&st);
            r
        }
    }

    // # C: int getopt(int argc, char *const argv[], const char *optstring)
    #[no_mangle]
    pub unsafe extern "C" fn getopt(argc: i32, argv: *mut *mut u8, optstring: *const u8) -> i32 {
        // SAFETY: standard getopt(3) contract; argv has argc entries.
        unsafe { run(argc, argv, optstring) }
    }
    // # C: int __posix_getopt(int argc, char *const argv[], const char *optstring)
    #[no_mangle]
    pub unsafe extern "C" fn __posix_getopt(argc: i32, argv: *mut *mut u8, optstring: *const u8) -> i32 {
        // SAFETY: POSIX getopt alias; same argv/optstring contract as getopt.
        unsafe { run(argc, argv, optstring) }
    }

    #[repr(C)]
    pub struct option { pub name: *const u8, pub has_arg: i32, pub flag: *mut i32, pub val: i32 }

    // # C: int getopt_long(argc, argv, optstring, longopts, longindex)
    #[no_mangle]
    pub unsafe extern "C" fn getopt_long(argc: i32, argv: *mut *mut u8, optstring: *const u8, longopts: *const option, longindex: *mut i32) -> i32 {
        // SAFETY: getopt_long(3) contract; longopts NULL-terminated (name=NULL).
        unsafe { getopt_long_impl(argc, argv, optstring, longopts, longindex, false) }
    }
    // # C: int getopt_long_only(...)
    #[no_mangle]
    pub unsafe extern "C" fn getopt_long_only(argc: i32, argv: *mut *mut u8, optstring: *const u8, longopts: *const option, longindex: *mut i32) -> i32 {
        // SAFETY: getopt_long_only(3) contract; argv has argc entries.
        unsafe { getopt_long_impl(argc, argv, optstring, longopts, longindex, true) }
    }

    unsafe fn getopt_long_impl(argc: i32, argv: *mut *mut u8, optstring: *const u8, longopts: *const option, longindex: *mut i32, _long_only: bool) -> i32 {
        // SAFETY: permute to the next option (shared with the short core), then
        // detect "--name[=val]" with unambiguous abbreviation; else short opt.
        unsafe {
            let slice = core::slice::from_raw_parts_mut(argv as *mut *const u8, argc as usize);
            let mut st = load_st();
            let mode = opt_mode(optstring);
            if st.pos == 0 {
                if let Some(rv) = advance(slice, mode, &mut st) { store_st(&st); return rv; }
            }
            let arg = slice[st.optind as usize];
            if st.pos == 1 && *arg == b'-' && *arg.add(1) == b'-' && *arg.add(2) != 0 {
                let body = arg.add(2);
                let mut nlen = 0usize;
                while *body.add(nlen) != 0 && *body.add(nlen) != b'=' { nlen += 1; }
                let has_eq = *body.add(nlen) == b'=';
                // match longopts: exact full name wins; else a single prefix
                // (unambiguous abbreviation); 0 or ≥2 prefixes → unknown/ambiguous.
                let (mut chosen, mut nmatch, mut exact) = (-1isize, 0i32, -1isize);
                let mut i = 0isize;
                loop {
                    let o = &*longopts.offset(i);
                    if o.name.is_null() { break; }
                    let olen = strlen_impl(o.name);
                    if olen >= nlen && (0..nlen).all(|k| *o.name.add(k) == *body.add(k)) {
                        if olen == nlen { exact = i; break; }
                        chosen = i; nmatch += 1;
                    }
                    i += 1;
                }
                let sel = if exact >= 0 { exact } else if nmatch == 1 { chosen } else { -1 };
                st.pos = 0;
                if sel < 0 { st.optind += 1; store_st(&st); return b'?' as i32; }
                let o = &*longopts.offset(sel);
                st.optind += 1;
                if !longindex.is_null() { *longindex = sel as i32; }
                st.optarg = core::ptr::null_mut();
                if o.has_arg != 0 {
                    if has_eq { st.optarg = body.add(nlen + 1) as *mut u8; }
                    else if o.has_arg == 1 {
                        if st.optind < argc { st.optarg = slice[st.optind as usize] as *mut u8; st.optind += 1; }
                        else { st.optopt = o.val; store_st(&st); return b'?' as i32; }
                    }
                }
                store_st(&st);
                if !o.flag.is_null() { *o.flag = o.val; return 0; }
                return o.val;
            }
            // short option: parse the char with the cursor already positioned.
            let r = getopt_core(slice, optstring, &mut st);
            store_st(&st);
            r
        }
    }
}

// Reusable table-driven long-opt scanner (shared with argp). `longopt` mirrors
// the C `struct option`; getopt_long_table is the slice-typed core of
// getopt_long without touching the C globals (argp keeps its own cursor).
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub(crate) struct longopt { pub name: *const u8, pub has_arg: i32, pub flag: *mut i32, pub val: i32 }

// One getopt_long step over a slice argv with an explicit longopts slice and
// cursor. Same semantics as getopt_long: returns the val, -1 at end, '?'/':'.
pub(crate) unsafe fn getopt_long_table(argv: &mut [*const u8], optstring: *const u8, longs: &[longopt], st: &mut St) -> i32 {
    // SAFETY: argv entries NUL-terminated; optstring/longs valid; cursor st.
    unsafe {
        let argc = argv.len() as i32;
        let mode = opt_mode(optstring);
        if st.pos == 0 {
            if let Some(rv) = advance(argv, mode, st) { return rv; }
        }
        let arg = argv[st.optind as usize];
        if st.pos == 1 && *arg == b'-' && *arg.add(1) == b'-' && *arg.add(2) != 0 {
            let body = arg.add(2);
            let mut nlen = 0usize;
            while *body.add(nlen) != 0 && *body.add(nlen) != b'=' { nlen += 1; }
            let has_eq = *body.add(nlen) == b'=';
            let (mut chosen, mut nmatch, mut exact) = (-1isize, 0i32, -1isize);
            for (i, o) in longs.iter().enumerate() {
                if o.name.is_null() { break; }
                let olen = strlen_impl(o.name);
                if olen >= nlen && (0..nlen).all(|k| *o.name.add(k) == *body.add(k)) {
                    if olen == nlen { exact = i as isize; break; }
                    chosen = i as isize; nmatch += 1;
                }
            }
            let sel = if exact >= 0 { exact } else if nmatch == 1 { chosen } else { -1 };
            st.pos = 0;
            if sel < 0 { st.optind += 1; return b'?' as i32; }
            let o = &longs[sel as usize];
            st.optind += 1;
            st.optarg = core::ptr::null_mut();
            if o.has_arg != 0 {
                if has_eq { st.optarg = body.add(nlen + 1) as *mut u8; }
                else if o.has_arg == 1 {
                    if st.optind < argc { st.optarg = argv[st.optind as usize] as *mut u8; st.optind += 1; }
                    else { st.optopt = o.val; return b'?' as i32; }
                }
            }
            if !o.flag.is_null() { *o.flag = o.val; return 0; }
            return o.val;
        }
        getopt_core(argv, optstring, st)
    }
}

use crate::string::len::strlen_impl;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{ffi::CString, vec::Vec};

    fn drive(args: &[&str], optstring: &str) -> Vec<(char, Option<alloc::string::String>)> {
        let cs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
        let mut argv: Vec<*const u8> = cs.iter().map(|c| c.as_ptr() as *const u8).collect();
        let os = CString::new(optstring).unwrap();
        let mut st = St::new();
        let mut out = Vec::new();
        loop {
            // SAFETY: argv/os are live NUL-terminated strings for this call;
            // getopt_core may permute the argv pointer vec in place.
            let r = unsafe { getopt_core(&mut argv[..], os.as_ptr() as *const u8, &mut st) };
            if r == -1 { break; }
            let oa = if st.optarg.is_null() { None } else {
                // SAFETY: optarg points into a live argv string.
                let s = unsafe { core::ffi::CStr::from_ptr(st.optarg as *const i8) };
                Some(s.to_string_lossy().into_owned())
            };
            out.push((r as u8 as char, oa));
            if out.len() > 50 { break; }
        }
        out
    }

    #[test]
    fn clustered_and_args() {
        let r = drive(&["prog", "-abc", "-o", "file", "-xval"], "abco:x:");
        assert_eq!(r, alloc::vec![
            ('a', None), ('b', None), ('c', None),
            ('o', Some("file".into())),
            ('x', Some("val".into())),
        ]);
    }
    #[test]
    fn optional_arg_and_missing() {
        // x:: optional — attached only
        let r = drive(&["prog", "-xfoo", "-x"], "x::");
        assert_eq!(r, alloc::vec![('x', Some("foo".into())), ('x', None)]);
    }
    #[test]
    fn missing_required_is_query() {
        let r = drive(&["prog", "-o"], "o:");
        assert_eq!(r, alloc::vec![('?', None)]); // missing required arg → '?'
        let r2 = drive(&["prog", "-o"], ":o:");
        assert_eq!(r2[0].0, ':'); // leading ':' mode → ':'
    }
    #[test]
    fn unknown_option_is_query() {
        let r = drive(&["prog", "-z"], "ab");
        assert_eq!(r, alloc::vec![('?', None)]);
    }
    #[test]
    fn permutes_options_after_operands() {
        // GNU default: -b after "file" is still found; "file" gathers at the end.
        let r = drive(&["prog", "-a", "file", "-b"], "ab");
        assert_eq!(r, alloc::vec![('a', None), ('b', None)]);
    }
    #[test]
    fn plus_prefix_stops_at_operand() {
        // '+' = REQUIRE_ORDER (POSIX): stop at the first non-option.
        let r = drive(&["prog", "-a", "file", "-b"], "+ab");
        assert_eq!(r, alloc::vec![('a', None)]);
    }
}
