// <argp.h> GNU argument parser (docs/59§6 G8). Drives a struct argp's option
// table through a getopt-style scan, dispatching to the user parser callback
// with ARGP_KEY_* events (INIT, per-option key, ARG, NO_ARGS, END, SUCCESS,
// FINI). Generates --help/--usage/--version, and argp_error/argp_failure
// reporting. struct argp/argp_option/argp_state match host /usr/include/argp.h.
// Single-argp (no child-argp recursion); children pointer is read but unused.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![allow(clippy::manual_c_str_literals)]
use crate::stdio::file::{self, FILE};
use crate::string::len::strlen_impl;
use core::ffi::{c_void, VaList};

mod help;
pub use help::{argp_help, argp_state_help, argp_usage};

// ---- ABI structs (match host argp.h) ----
#[repr(C)]
pub struct argp_option {
    pub name: *const u8,
    pub key: i32,
    pub arg: *const u8,
    pub flags: i32,
    pub doc: *const u8,
    pub group: i32,
}
pub type argp_parser_t = Option<unsafe extern "C" fn(key: i32, arg: *mut u8, state: *mut argp_state) -> i32>;
#[repr(C)]
pub struct argp {
    pub options: *const argp_option,
    pub parser: argp_parser_t,
    pub args_doc: *const u8,
    pub doc: *const u8,
    pub children: *const c_void,
    pub help_filter: *const c_void,
    pub argp_domain: *const u8,
}
#[repr(C)]
pub struct argp_state {
    pub root_argp: *const argp,
    pub argc: i32,
    pub argv: *mut *mut u8,
    pub next: i32,
    pub flags: u32,
    pub arg_num: u32,
    pub quoted: i32,
    pub input: *mut c_void,
    pub child_inputs: *mut *mut c_void,
    pub hook: *mut c_void,
    pub name: *mut u8,
    pub err_stream: *mut FILE,
    pub out_stream: *mut FILE,
    pub pstate: *mut c_void,
}

// ---- constants ----
pub(crate) const ARGP_KEY_ARG: i32 = 0;
pub(crate) const ARGP_KEY_END: i32 = 0x1000001;
pub(crate) const ARGP_KEY_NO_ARGS: i32 = 0x1000002;
pub(crate) const ARGP_KEY_INIT: i32 = 0x1000003;
pub(crate) const ARGP_KEY_SUCCESS: i32 = 0x1000004;
pub(crate) const ARGP_KEY_ERROR: i32 = 0x1000005;
pub(crate) const ARGP_KEY_FINI: i32 = 0x1000007;
const ARGP_ERR_UNKNOWN: i32 = 7; // E2BIG

const OPTION_ARG_OPTIONAL: i32 = 0x1;
const OPTION_HIDDEN: i32 = 0x2;
const OPTION_ALIAS: i32 = 0x4;
const OPTION_DOC: i32 = 0x8;

const ARGP_PARSE_ARGV0: u32 = 0x01;
const ARGP_NO_ERRS: u32 = 0x02;
const ARGP_NO_ARGS: u32 = 0x04;
const ARGP_IN_ORDER: u32 = 0x08;
const ARGP_NO_HELP: u32 = 0x10;
const ARGP_NO_EXIT: u32 = 0x20;
#[allow(dead_code)]
const ARGP_LONG_ONLY: u32 = 0x40;

const EINVAL: i32 = 22;

// program name + bug address globals (referenced by help)
pub(crate) mod globals {
    use core::cell::UnsafeCell;
    #[repr(transparent)]
    pub(crate) struct Ptr(pub UnsafeCell<*const u8>);
    // SAFETY: process-wide argp config; single-threaded argp use per contract.
    unsafe impl Sync for Ptr {}
    #[repr(transparent)]
    pub(crate) struct I32(pub UnsafeCell<i32>);
    unsafe impl Sync for I32 {}
    // # C: const char *argp_program_version;
    #[no_mangle]
    pub static argp_program_version: Ptr = Ptr(UnsafeCell::new(core::ptr::null()));
    // # C: const char *argp_program_bug_address;
    #[no_mangle]
    pub static argp_program_bug_address: Ptr = Ptr(UnsafeCell::new(core::ptr::null()));
    // # C: error_t argp_err_exit_status;
    #[no_mangle]
    pub static argp_err_exit_status: I32 = I32(UnsafeCell::new(64)); // EX_USAGE
}

// Test if an argp_option entry is the terminating (all-zero) sentinel.
unsafe fn is_end(o: *const argp_option) -> bool {
    // SAFETY: o points at an array element; terminator has name/key/doc/group 0.
    unsafe { (*o).key == 0 && (*o).name.is_null() && (*o).doc.is_null() && (*o).group == 0 }
}

// Build the short optstring from the option table: each printable short key,
// followed by ':' (req arg) or "::" (optional arg). Leading '-' so non-options
// come back as ARGP_KEY_ARG via getopt code 1 (we drive permutation ourselves).
unsafe fn build_optstring(opts: *const argp_option, buf: &mut [u8]) -> usize {
    // SAFETY: opts is a sentinel-terminated table; buf is large enough
    // (≤ 1 + 3*N + 1). We append the leading '-' mode flag then per-option.
    unsafe {
        let mut w = 0;
        buf[w] = b'-'; w += 1;
        let mut i = 0;
        loop {
            let o = opts.add(i);
            if is_end(o) { break; }
            let k = (*o).key;
            if (*o).flags & (OPTION_DOC | OPTION_ALIAS) == 0 && k > 0 && k < 256 && (k as u8).is_ascii_graphic() {
                buf[w] = k as u8; w += 1;
                if !(*o).arg.is_null() {
                    buf[w] = b':'; w += 1;
                    if (*o).flags & OPTION_ARG_OPTIONAL != 0 { buf[w] = b':'; w += 1; }
                }
            }
            i += 1;
        }
        buf[w] = 0;
        w
    }
}

// Count user options (for the longopts array sizing).
unsafe fn count_opts(opts: *const argp_option) -> usize {
    // SAFETY: opts sentinel-terminated; counts named long options.
    unsafe {
        let mut n = 0; let mut i = 0;
        loop {
            let o = opts.add(i);
            if is_end(o) { break; }
            if !(*o).name.is_null() { n += 1; }
            i += 1;
        }
        n
    }
}

// ---- the parse driver ----
struct Driver { exit_on_err: bool, in_order: bool, no_args: bool }

// Invoke the user parser, mapping the return per argp semantics. Returns
// Some(rv) if parsing should stop with rv, else None.
unsafe fn call_parser(p: argp_parser_t, key: i32, arg: *mut u8, st: *mut argp_state) -> Option<i32> {
    // SAFETY: p is the user callback or None; st is our live argp_state.
    unsafe {
        let r = match p { Some(f) => f(key, arg, st), None => ARGP_ERR_UNKNOWN };
        if r == ARGP_ERR_UNKNOWN { return None; }
        if r != 0 { return Some(r); }
        None
    }
}

unsafe fn run(argp: *const argp, st: *mut argp_state, d: &Driver) -> i32 {
    // SAFETY: argp/st valid; drive getopt over (*st).argv, dispatching keys.
    unsafe {
        let p = (*argp).parser;
        let opts = (*argp).options;
        // INIT
        if let Some(rv) = call_parser(p, ARGP_KEY_INIT, core::ptr::null_mut(), st) { return finish_err(p, st, rv); }

        // optstring + longopts
        let mut osbuf = [0u8; 512];
        build_optstring(opts, &mut osbuf);
        let nlong = count_opts(opts);
        let mut longs: alloc::vec::Vec<crate::posix::getopt::longopt> = alloc::vec::Vec::with_capacity(nlong + 4);
        let mut keymap: alloc::vec::Vec<i32> = alloc::vec::Vec::with_capacity(nlong + 4);
        {
            let mut i = 0; let mut last_key = 0;
            loop {
                let o = opts.add(i);
                if is_end(o) { break; }
                if (*o).flags & OPTION_ALIAS != 0 { /* alias inherits prev key below */ }
                let k = if (*o).flags & OPTION_ALIAS != 0 { last_key } else { (*o).key };
                if (*o).flags & OPTION_ALIAS == 0 { last_key = (*o).key; }
                if !(*o).name.is_null() && (*o).flags & OPTION_DOC == 0 {
                    let has = if (*o).arg.is_null() { 0 } else if (*o).flags & OPTION_ARG_OPTIONAL != 0 { 2 } else { 1 };
                    longs.push(crate::posix::getopt::longopt { name: (*o).name, has_arg: has, flag: core::ptr::null_mut(), val: k });
                    keymap.push(k);
                }
                i += 1;
            }
            // built-in --help/--usage/--version
            longs.push(crate::posix::getopt::longopt { name: b"help\0".as_ptr(), has_arg: 0, flag: core::ptr::null_mut(), val: -1 });
            keymap.push(-1);
            longs.push(crate::posix::getopt::longopt { name: b"usage\0".as_ptr(), has_arg: 0, flag: core::ptr::null_mut(), val: -2 });
            keymap.push(-2);
            longs.push(crate::posix::getopt::longopt { name: b"version\0".as_ptr(), has_arg: 0, flag: core::ptr::null_mut(), val: -3 });
            keymap.push(-3);
            longs.push(crate::posix::getopt::longopt { name: core::ptr::null(), has_arg: 0, flag: core::ptr::null_mut(), val: 0 });
        }

        // getopt cursor over argv
        let argc = (*st).argc;
        let slice = core::slice::from_raw_parts_mut((*st).argv as *mut *const u8, argc as usize);
        let mut gs = crate::posix::getopt::St::new();
        let mut arg_num = 0u32;
        let mut had_arg = false;
        loop {
            let c = crate::posix::getopt::getopt_long_table(slice, osbuf.as_ptr(), &longs, &mut gs);
            if c == -1 { break; }
            (*st).next = gs.optind;
            let arg = gs.optarg;
            match c {
                1 => {
                    // non-option operand (we used '-' optstring → code 1)
                    let _ = d.in_order;
                    (*st).arg_num = arg_num;
                    had_arg = true;
                    if let Some(rv) = call_parser(p, ARGP_KEY_ARG, arg, st) { return finish_err(p, st, rv); }
                    arg_num += 1;
                }
                v if v == '?' as i32 => {
                    // unknown option: "invalid option -- 'x'"
                    do_invalid_opt(st, gs.optopt as u8);
                    return finish_help_err(argp, st, d);
                }
                v if v == ':' as i32 => {
                    do_reqarg(st, gs.optopt as u8);
                    return finish_help_err(argp, st, d);
                }
                key => {
                    if key == -1 { // --help
                        help::do_std_help(argp, st, d.exit_on_err);
                        return 0;
                    } else if key == -2 { // --usage
                        help::do_std_usage(argp, st, d.exit_on_err);
                        return 0;
                    } else if key == -3 { // --version
                        help::do_version(st, d.exit_on_err);
                        return 0;
                    }
                    if let Some(rv) = call_parser(p, key, arg, st) { return finish_err(p, st, rv); }
                }
            }
        }
        (*st).next = gs.optind;
        // NO_ARGS / END
        if !had_arg && !d.no_args {
            if let Some(rv) = call_parser(p, ARGP_KEY_NO_ARGS, core::ptr::null_mut(), st) { return finish_err(p, st, rv); }
        }
        if let Some(rv) = call_parser(p, ARGP_KEY_END, core::ptr::null_mut(), st) { return finish_err(p, st, rv); }
        let _ = call_parser(p, ARGP_KEY_SUCCESS, core::ptr::null_mut(), st);
        let _ = call_parser(p, ARGP_KEY_FINI, core::ptr::null_mut(), st);
        0
    }
}

unsafe fn finish_err(p: argp_parser_t, st: *mut argp_state, rv: i32) -> i32 {
    // SAFETY: signal the parser of the error then return the propagated code.
    unsafe { let _ = call_parser(p, ARGP_KEY_ERROR, core::ptr::null_mut(), st); if rv == ARGP_ERR_UNKNOWN { EINVAL } else { rv } }
}

unsafe fn finish_help_err(argp: *const argp, st: *mut argp_state, d: &Driver) -> i32 {
    // SAFETY: emit the standard "Try --help" line then exit/return EINVAL.
    unsafe {
        if (*st).flags & ARGP_NO_HELP == 0 { help::do_see(argp, st); }
        if d.exit_on_err { crate::stdlib::exit::exit_group(globals_exit_status()); }
        EINVAL
    }
}

fn globals_exit_status() -> i32 {
    // SAFETY: read the process-global argp_err_exit_status.
    unsafe { *globals::argp_err_exit_status.0.get() }
}

// Stream + "PROGNAME: " prefix for a diagnostic line.
unsafe fn err_prefix(st: *mut argp_state) -> *mut FILE {
    // SAFETY: st has a valid name + err_stream; emit "name: ".
    unsafe {
        let f = if (*st).err_stream.is_null() { file::stderr_ptr() } else { (*st).err_stream };
        crate::stdio::put::fputs((*st).name as *const u8, f);
        crate::stdio::put::fputs(b": \0".as_ptr(), f);
        f
    }
}

// "invalid option -- 'x'" (short) or "unrecognized option '--long'" (long).
unsafe fn do_invalid_opt(st: *mut argp_state, c: u8) {
    // SAFETY: st valid; inspect the offending argv token at next-1 to choose
    // the short vs long wording, matching glibc argp.
    unsafe {
        if (*st).flags & ARGP_NO_ERRS != 0 { return; }
        let f = err_prefix(st);
        let tok = if (*st).next >= 1 && (*st).next <= (*st).argc { *(*st).argv.add(((*st).next - 1) as usize) } else { core::ptr::null_mut() };
        if !tok.is_null() && *tok == b'-' && *tok.add(1) == b'-' {
            crate::stdio::put::fputs(b"unrecognized option '\0".as_ptr(), f);
            crate::stdio::put::fputs(tok as *const u8, f);
            crate::stdio::put::fputs(b"'\n\0".as_ptr(), f);
        } else {
            crate::stdio::put::fputs(b"invalid option -- '\0".as_ptr(), f);
            crate::stdio::put::fputc(c as i32, f);
            crate::stdio::put::fputs(b"'\n\0".as_ptr(), f);
        }
    }
}

// "option requires an argument -- 'x'".
unsafe fn do_reqarg(st: *mut argp_state, c: u8) {
    // SAFETY: st valid; emit the missing-required-arg diagnostic.
    unsafe {
        if (*st).flags & ARGP_NO_ERRS != 0 { return; }
        let f = err_prefix(st);
        crate::stdio::put::fputs(b"option requires an argument -- '\0".as_ptr(), f);
        crate::stdio::put::fputc(c as i32, f);
        crate::stdio::put::fputs(b"'\n\0".as_ptr(), f);
    }
}

// ---- public exports ----
// # C: error_t argp_parse(const struct argp *argp, int argc, char **argv, unsigned flags, int *arg_index, void *input)
#[no_mangle]
pub unsafe extern "C" fn argp_parse(argp: *const argp, argc: i32, argv: *mut *mut u8, flags: u32, arg_index: *mut i32, input: *mut c_void) -> i32 {
    // SAFETY: argp valid; argv has argc entries. Build the argp_state and run.
    unsafe {
        let name = if flags & ARGP_PARSE_ARGV0 == 0 && argc > 0 {
            // basename of argv[0]
            let a0 = *argv;
            let mut base = a0;
            let mut i = 0;
            while *a0.add(i) != 0 { if *a0.add(i) == b'/' { base = a0.add(i + 1); } i += 1; }
            base
        } else { *argv };
        let mut st = argp_state {
            root_argp: argp, argc, argv, next: 1, flags, arg_num: 0, quoted: 0,
            input, child_inputs: core::ptr::null_mut(), hook: core::ptr::null_mut(),
            name, err_stream: file::stderr_ptr(), out_stream: file::stdout_ptr(), pstate: core::ptr::null_mut(),
        };
        let d = Driver {
            exit_on_err: flags & ARGP_NO_EXIT == 0,
            in_order: flags & ARGP_IN_ORDER != 0,
            no_args: flags & ARGP_NO_ARGS != 0,
        };
        let r = run(argp, &mut st, &d);
        if !arg_index.is_null() { *arg_index = st.next; }
        r
    }
}

// # C: void argp_error(const struct argp_state *state, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn argp_error(state: *mut argp_state, fmt: *const u8, ap: ...) -> ! {
    // SAFETY: state valid; print "name: <fmt...>" then the see-help line +exit.
    unsafe { argp_error_v(state, fmt, ap); }
    // SAFETY: argp_error always exits per the GNU contract.
    crate::stdlib::exit::exit_group(globals_exit_status());
}

unsafe fn argp_error_v(state: *mut argp_state, fmt: *const u8, ap: VaList) {
    // SAFETY: state has a name + err_stream; format the message there.
    unsafe {
        if !state.is_null() && (*state).flags & ARGP_NO_ERRS != 0 { return; }
        let f = if state.is_null() || (*state).err_stream.is_null() { file::stderr_ptr() } else { (*state).err_stream };
        if !state.is_null() { crate::stdio::put::fputs((*state).name as *const u8, f); crate::stdio::put::fputs(b": \0".as_ptr(), f); }
        crate::stdio::printf::vfprintf(f, fmt, ap);
        crate::stdio::put::fputc('\n' as i32, f);
        if !state.is_null() { help::do_see((*state).root_argp, state); }
    }
}

// # C: void argp_failure(const struct argp_state *state, int status, int errnum, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn argp_failure(state: *mut argp_state, status: i32, errnum: i32, fmt: *const u8, ap: ...) {
    // SAFETY: like error() but no "see help"; respects ARGP_NO_EXIT/NO_ERRS.
    unsafe {
        if !state.is_null() && (*state).flags & ARGP_NO_ERRS == 0 {
            let f = if state.is_null() || (*state).err_stream.is_null() { file::stderr_ptr() } else { (*state).err_stream };
            crate::stdio::put::fputs((*state).name as *const u8, f);
            crate::stdio::put::fputs(b": \0".as_ptr(), f);
            crate::stdio::printf::vfprintf(f, fmt, ap);
            if errnum != 0 {
                extern "C" { fn strerror(e: i32) -> *mut u8; }
                crate::stdio::put::fputs(b": \0".as_ptr(), f);
                crate::stdio::put::fputs(strerror(errnum), f);
            }
            crate::stdio::put::fputc('\n' as i32, f);
        }
        if status != 0 && (state.is_null() || (*state).flags & ARGP_NO_EXIT == 0) {
            crate::stdlib::exit::exit_group(status);
        }
    }
}
