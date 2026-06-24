// argp help/usage/version generation (docs/59§6 G8). Renders the standard
// GNU help, short-usage, "Try --help", and --version output. Layout follows
// glibc argp-help.c for the common single-argp case.
#![allow(clippy::manual_c_str_literals)]
use super::*;
use crate::stdio::put::{fputc, fputs};

const ARGP_HELP_SHORT_USAGE: u32 = 0x02;
#[allow(dead_code)]
const ARGP_HELP_USAGE: u32 = 0x01;
const ARGP_HELP_SEE: u32 = 0x04;
const ARGP_HELP_LONG: u32 = 0x08;
const ARGP_HELP_PRE_DOC: u32 = 0x10;
const ARGP_HELP_POST_DOC: u32 = 0x20;
const ARGP_HELP_BUG_ADDR: u32 = 0x40;
const ARGP_HELP_EXIT_ERR: u32 = 0x100;
const ARGP_HELP_EXIT_OK: u32 = 0x200;
const ARGP_HELP_STD_USAGE: u32 = ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR;
const ARGP_HELP_STD_HELP: u32 = ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG | ARGP_HELP_EXIT_OK | ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC | ARGP_HELP_BUG_ADDR;

const OPTION_DOC_F: i32 = 0x8;
const OPTION_HIDDEN_F: i32 = 0x2;
const OPTION_ALIAS_F: i32 = 0x4;

unsafe fn prog_name(state: *const argp_state) -> *const u8 {
    // SAFETY: state has a NUL-terminated name set by argp_parse.
    unsafe { if state.is_null() { b"\0".as_ptr() } else { (*state).name as *const u8 } }
}

// Print "Usage: NAME [OPTION...] ARGS_DOC". args_doc may have alternative
// lines separated by '\n' ("  or: " prefix for subsequent lines).
unsafe fn print_short_usage(argp: *const argp, name: *const u8, f: *mut FILE) {
    // SAFETY: argp valid; name NUL-terminated; emit the usage synopsis.
    unsafe {
        fputs(b"Usage: \0".as_ptr(), f);
        fputs(name, f);
        fputs(b" [OPTION...]\0".as_ptr(), f);
        if !(*argp).args_doc.is_null() && *(*argp).args_doc != 0 {
            fputc(' ' as i32, f);
            fputs((*argp).args_doc, f);
        }
        fputc('\n' as i32, f);
    }
}

// Print "Try `NAME --help' or `NAME --usage' for more information."
unsafe fn print_see(name: *const u8, f: *mut FILE) {
    // SAFETY: name NUL-terminated; standard see-also line (glibc backtick form).
    unsafe {
        fputs(b"Try `\0".as_ptr(), f);
        fputs(name, f);
        fputs(b" --help' or `\0".as_ptr(), f);
        fputs(name, f);
        fputs(b" --usage' for more information.\n\0".as_ptr(), f);
    }
}

// Long help: print each documented option. Layout: "  -x, --name=ARG   doc".
unsafe fn print_options(argp: *const argp, f: *mut FILE) {
    // SAFETY: option table sentinel-terminated; emit one line per visible opt.
    unsafe {
        let opts = (*argp).options;
        if opts.is_null() { return; }
        let mut i = 0;
        let mut last_short: i32 = 0;
        loop {
            let o = opts.add(i);
            if super::is_end(o) { break; }
            i += 1;
            if (*o).flags & OPTION_HIDDEN_F != 0 { continue; }
            if (*o).flags & OPTION_DOC_F != 0 {
                if !(*o).doc.is_null() { fputs((*o).doc, f); fputc('\n' as i32, f); }
                continue;
            }
            // group header (name & key both 0 already handled by is_end miss)
            let short = (*o).key;
            let is_short = short > 0 && short < 256 && (short as u8).is_ascii_graphic();
            let alias = (*o).flags & OPTION_ALIAS_F != 0;
            if alias { /* keep grouping with previous; print on own line too */ }
            fputs(b"  \0".as_ptr(), f);
            let mut col = 2usize;
            if is_short {
                fputc('-' as i32, f); fputc(short, f); col += 2;
                last_short = short;
                if !(*o).name.is_null() { fputs(b", \0".as_ptr(), f); col += 2; }
            } else {
                fputs(b"    \0".as_ptr(), f); col += 4;
                let _ = last_short;
            }
            if !(*o).name.is_null() {
                fputs(b"--\0".as_ptr(), f); col += 2;
                let nl = strlen_impl((*o).name); fputs((*o).name, f); col += nl;
                if !(*o).arg.is_null() {
                    let optional = (*o).flags & OPTION_ARG_OPTIONAL != 0;
                    if optional { fputs(b"[=\0".as_ptr(), f); col += 2; } else { fputc('=' as i32, f); col += 1; }
                    let al = strlen_impl((*o).arg); fputs((*o).arg, f); col += al;
                    if optional { fputc(']' as i32, f); col += 1; }
                }
            } else if is_short && !(*o).arg.is_null() {
                let optional = (*o).flags & OPTION_ARG_OPTIONAL != 0;
                if optional { fputs(b"[\0".as_ptr(), f); col += 1; } else { fputc(' ' as i32, f); col += 1; }
                let al = strlen_impl((*o).arg); fputs((*o).arg, f); col += al;
                if optional { fputc(']' as i32, f); col += 1; }
            }
            // pad to doc column 30 (glibc default), at least 2 spaces
            if !(*o).doc.is_null() && *(*o).doc != 0 {
                let target = 30usize;
                if col + 1 >= target { fputc('\n' as i32, f); for _ in 0..target { fputc(' ' as i32, f); } }
                else { for _ in col..target { fputc(' ' as i32, f); } }
                fputs((*o).doc, f);
            }
            fputc('\n' as i32, f);
        }
    }
}

// Split doc on '\v': pre-doc before, post-doc after.
unsafe fn print_doc(doc: *const u8, pre: bool, f: *mut FILE) {
    // SAFETY: doc NUL-terminated or null; print the pre/post half.
    unsafe {
        if doc.is_null() { return; }
        let mut vt = -1isize; let mut i = 0;
        while *doc.add(i) != 0 { if *doc.add(i) == 0x0b { vt = i as isize; break; } i += 1; }
        if pre {
            let end = if vt >= 0 { vt as usize } else { strlen_impl(doc) };
            if end > 0 { for k in 0..end { fputc(*doc.add(k) as i32, f); } fputc('\n' as i32, f); }
        } else if vt >= 0 {
            let start = vt as usize + 1;
            if *doc.add(start) != 0 { fputs(doc.add(start), f); fputc('\n' as i32, f); }
        }
    }
}

// The full argp_help renderer.
// # C: void argp_help(const struct argp *argp, FILE *stream, unsigned flags, char *name)
#[no_mangle]
pub unsafe extern "C" fn argp_help(argp: *const argp, stream: *mut FILE, flags: u32, name: *mut u8) {
    // SAFETY: argp valid; stream a live FILE; name NUL-terminated. Emit the
    // requested help sections per the ARGP_HELP_* flags.
    unsafe {
        let f = if stream.is_null() { file::stderr_ptr() } else { stream };
        let nm: *const u8 = if name.is_null() { b"\0".as_ptr() } else { name };
        if flags & ARGP_HELP_SHORT_USAGE != 0 { print_short_usage(argp, nm, f); }
        if flags & ARGP_HELP_PRE_DOC != 0 { print_doc((*argp).doc, true, f); }
        if flags & ARGP_HELP_LONG != 0 {
            fputc('\n' as i32, f);
            print_options(argp, f);
        }
        if flags & ARGP_HELP_POST_DOC != 0 { print_doc((*argp).doc, false, f); }
        if flags & ARGP_HELP_BUG_ADDR != 0 {
            let addr = *globals::argp_program_bug_address.0.get();
            if !addr.is_null() { fputs(b"\nReport bugs to \0".as_ptr(), f); fputs(addr, f); fputs(b".\n\0".as_ptr(), f); }
        }
        if flags & ARGP_HELP_SEE != 0 { print_see(nm, f); }
        if flags & ARGP_HELP_EXIT_ERR != 0 { crate::stdlib::exit::exit_group(*globals::argp_err_exit_status.0.get()); }
        if flags & ARGP_HELP_EXIT_OK != 0 { crate::stdlib::exit::exit_group(0); }
    }
}

// # C: void argp_state_help(const struct argp_state *state, FILE *stream, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn argp_state_help(state: *mut argp_state, stream: *mut FILE, flags: u32) {
    // SAFETY: state valid; route to argp_help with the state's argp + name.
    unsafe {
        let argp = if state.is_null() { core::ptr::null() } else { (*state).root_argp };
        argp_help(argp, stream, flags, prog_name(state) as *mut u8);
    }
}

// # C: void argp_usage(const struct argp_state *state)
#[no_mangle]
pub unsafe extern "C" fn argp_usage(state: *mut argp_state) {
    // SAFETY: standard usage-to-stderr then exit, per the GNU contract.
    unsafe { argp_state_help(state, file::stderr_ptr(), ARGP_HELP_STD_USAGE); }
}

// internal helpers used by the parse driver
pub(crate) unsafe fn do_see(argp: *const argp, st: *mut argp_state) {
    // SAFETY: emit the "Try --help" line to the state's err stream.
    unsafe {
        let _ = argp;
        let f = if (*st).err_stream.is_null() { file::stderr_ptr() } else { (*st).err_stream };
        print_see(prog_name(st), f);
    }
}
pub(crate) unsafe fn do_std_help(argp: *const argp, st: *mut argp_state, exit: bool) {
    // SAFETY: full --help; respects exit flag (ARGP_NO_EXIT clears it).
    unsafe {
        let mut flags = ARGP_HELP_STD_HELP;
        if !exit { flags &= !ARGP_HELP_EXIT_OK; }
        argp_help(argp, (*st).out_stream, flags, prog_name(st) as *mut u8);
    }
}
pub(crate) unsafe fn do_std_usage(argp: *const argp, st: *mut argp_state, exit: bool) {
    // SAFETY: short --usage; respects exit flag.
    unsafe {
        let mut flags = ARGP_HELP_SHORT_USAGE;
        if exit { flags |= ARGP_HELP_EXIT_OK; }
        argp_help(argp, (*st).out_stream, flags, prog_name(st) as *mut u8);
    }
}
pub(crate) unsafe fn do_version(st: *mut argp_state, exit: bool) {
    // SAFETY: print argp_program_version (or version_hook) then exit.
    unsafe {
        let f = (*st).out_stream;
        if let Some(hook) = *globals::argp_program_version_hook.0.get() {
            hook(f, st);
        } else {
            let v = *globals::argp_program_version.0.get();
            if !v.is_null() { fputs(v, f); fputc('\n' as i32, f); }
        }
        if exit { crate::stdlib::exit::exit_group(0); }
    }
}
