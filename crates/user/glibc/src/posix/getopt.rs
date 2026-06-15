// getopt / getopt_long (docs/59§6 G8). POSIX scanning order (stop at the
// first non-option); clustered short opts, required (x:) and optional
// (x::) args, "--" terminator, leading ':' error mode, '+'/'-' optstring
// prefixes. GNU argv permutation (options after operands) is a tracked
// follow-up — getopt is fully functional in POSIX order meanwhile.
//
// The parse core is a pure state machine over a &[*const u8] argv + a
// `St` cursor (unit-tested); the #[no_mangle] exports drive it through the
// C globals optarg/optind/opterr/optopt.

pub(crate) struct St { pub optind: i32, pub optarg: *mut u8, pub optopt: i32, pub pos: usize }
impl St {
    /// # C: initial getopt cursor (optind=1)
    pub(crate) const fn new() -> St { St { optind: 1, optarg: core::ptr::null_mut(), optopt: 0, pos: 0 } }
}

unsafe fn cstr_byte(p: *const u8, i: usize) -> u8 {
    // SAFETY: p is NUL-terminated; callers index within its length.
    unsafe { *p.add(i) }
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

// One getopt step over argv (POSIX order). Returns the option char, or -1
// at end, '?'/':' on error. Updates `st`.
pub(crate) unsafe fn getopt_core(argv: &[*const u8], optstring: *const u8, st: &mut St) -> i32 {
    // SAFETY: argv entries are NUL-terminated C strings; optstring too.
    unsafe {
        st.optarg = core::ptr::null_mut();
        let argc = argv.len() as i32;
        // skip optstring mode prefix
        let mut optstr = optstring;
        if cstr_byte(optstr, 0) == b'+' || cstr_byte(optstr, 0) == b'-' { optstr = optstr.add(1); }
        let colon_mode = cstr_byte(optstr, 0) == b':';

        if st.pos == 0 {
            // fresh argv element
            if st.optind >= argc { return -1; }
            let arg = argv[st.optind as usize];
            if arg.is_null() || cstr_byte(arg, 0) != b'-' || cstr_byte(arg, 1) == 0 {
                return -1; // non-option → stop (POSIX)
            }
            if cstr_byte(arg, 1) == b'-' && cstr_byte(arg, 2) == 0 {
                st.optind += 1; // "--"
                return -1;
            }
            st.pos = 1;
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

    // internal cursor position within a clustered short-opt arg
    static POS: I32 = I32(UnsafeCell::new(0));

    unsafe fn run(argc: i32, argv: *mut *mut u8, optstring: *const u8) -> i32 {
        // SAFETY: argv is the program's NULL-or-len argv; we view argc
        // entries as a slice and drive the pure core over them.
        unsafe {
            let slice = core::slice::from_raw_parts(argv as *const *const u8, argc as usize);
            let mut st = St { optind: *optind.0.get(), optarg: core::ptr::null_mut(), optopt: *optopt.0.get(), pos: *POS.0.get() as usize };
            let r = getopt_core(slice, optstring, &mut st);
            *optind.0.get() = st.optind;
            *optarg.0.get() = st.optarg;
            *optopt.0.get() = st.optopt;
            *POS.0.get() = st.pos as i32;
            r
        }
    }

    // # C: int getopt(int argc, char *const argv[], const char *optstring)
    #[no_mangle]
    pub unsafe extern "C" fn getopt(argc: i32, argv: *mut *mut u8, optstring: *const u8) -> i32 {
        // SAFETY: standard getopt(3) contract; argv has argc entries.
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
        // SAFETY: at a fresh arg, detect "--name[=val]" and match longopts;
        // otherwise fall back to short getopt. POSIX order.
        unsafe {
            if *POS.0.get() == 0 && *optind.0.get() < argc {
                let arg = *argv.add(*optind.0.get() as usize);
                if !arg.is_null() && *arg == b'-' && *arg.add(1) == b'-' && *arg.add(2) != 0 {
                    // long option "--name" or "--name=value"
                    let body = arg.add(2);
                    let mut nlen = 0usize;
                    while *body.add(nlen) != 0 && *body.add(nlen) != b'=' { nlen += 1; }
                    let has_eq = *body.add(nlen) == b'=';
                    // find matching longopt by name
                    let mut i = 0isize;
                    loop {
                        let o = &*longopts.offset(i);
                        if o.name.is_null() { break; }
                        if strlen_impl(o.name) == nlen && {
                            let mut eq = true;
                            for k in 0..nlen { if *o.name.add(k) != *body.add(k) { eq = false; break; } }
                            eq
                        } {
                            *optind.0.get() += 1;
                            if !longindex.is_null() { *longindex = i as i32; }
                            // argument
                            if o.has_arg != 0 {
                                if has_eq {
                                    *optarg.0.get() = body.add(nlen + 1);
                                } else if o.has_arg == 1 {
                                    // required: next argv
                                    if *optind.0.get() < argc { let a = *argv.add(*optind.0.get() as usize); *optind.0.get() += 1; *optarg.0.get() = a; }
                                    else { *optopt.0.get() = o.val; return b'?' as i32; }
                                } else {
                                    *optarg.0.get() = core::ptr::null_mut(); // optional
                                }
                            } else {
                                *optarg.0.get() = core::ptr::null_mut();
                            }
                            if !o.flag.is_null() { *o.flag = o.val; return 0; }
                            return o.val;
                        }
                        i += 1;
                    }
                    // unknown long option
                    *optind.0.get() += 1;
                    return b'?' as i32;
                }
            }
            run(argc, argv, optstring)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{ffi::CString, vec::Vec};

    fn drive(args: &[&str], optstring: &str) -> Vec<(char, Option<alloc::string::String>)> {
        let cs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
        let argv: Vec<*const u8> = cs.iter().map(|c| c.as_ptr() as *const u8).collect();
        let os = CString::new(optstring).unwrap();
        let mut st = St::new();
        let mut out = Vec::new();
        loop {
            // SAFETY: argv/os are live NUL-terminated strings for this call.
            let r = unsafe { getopt_core(&argv, os.as_ptr() as *const u8, &mut st) };
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
    fn stops_at_nonoption() {
        let r = drive(&["prog", "-a", "file", "-b"], "ab");
        assert_eq!(r, alloc::vec![('a', None)]); // POSIX: stops at "file"
    }
}
