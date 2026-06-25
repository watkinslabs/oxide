// Runtime configuration queries (docs/59§6 G8): sysconf, confstr, pathconf,
// fpathconf. _SC_/_CS_/_PC_ codes match host <bits/confname.h>. Dynamic
// values (page size, nprocs, RLIMIT_NOFILE) come from syscalls; the rest are
// the Linux fixed limits glibc reports.
#![cfg(feature = "freestanding")]
use crate::posix::resource::{Rlimit, getrlimit};
use crate::sysinfo::info::{get_nprocs, get_nprocs_conf, get_phys_pages, get_avphys_pages, getpagesize};

// _SC_* codes (<bits/confname.h>).
const SC_ARG_MAX: i32 = 0;
const SC_CHILD_MAX: i32 = 1;
const SC_CLK_TCK: i32 = 2;
const SC_NGROUPS_MAX: i32 = 3;
const SC_OPEN_MAX: i32 = 4;
const SC_STREAM_MAX: i32 = 5;
const SC_TZNAME_MAX: i32 = 6;
const SC_PAGESIZE: i32 = 30; // == _SC_PAGE_SIZE
const SC_RE_DUP_MAX: i32 = 44;
const SC_LINE_MAX: i32 = 43;
const SC_LOGIN_NAME_MAX: i32 = 71;
const SC_NPROCESSORS_CONF: i32 = 83;
const SC_NPROCESSORS_ONLN: i32 = 84;
const SC_PHYS_PAGES: i32 = 85;
const SC_AVPHYS_PAGES: i32 = 86;
const SC_ATEXIT_MAX: i32 = 87;
const SC_SYMLOOP_MAX: i32 = 173;
const SC_HOST_NAME_MAX: i32 = 180;
const SC_GETPW_R_SIZE_MAX: i32 = 70;
const SC_GETGR_R_SIZE_MAX: i32 = 69;

// Linux fixed limits glibc reports for these names.
const CLK_TCK: i64 = 100;
const NGROUPS_MAX: i64 = 65536;
const ARG_MAX: i64 = 2 * 1024 * 1024; // 2 MiB (legacy ARG_MAX floor)
const CHILD_MAX: i64 = 999; // RLIMIT_NPROC-ish default; glibc reports getrlimit
const OPEN_MAX_DFLT: i64 = 1024;
const STREAM_MAX: i64 = 16;
const TZNAME_MAX: i64 = 6;
const RE_DUP_MAX: i64 = 32767;
const LINE_MAX: i64 = 2048;
const LOGIN_NAME_MAX: i64 = 256;
const HOST_NAME_MAX: i64 = 64;
const SYMLOOP_MAX: i64 = -1; // unlimited → -1 (no errno) per POSIX
const PW_GR_R_SIZE_MAX: i64 = 1024;
const ATEXIT_MAX: i64 = 2147483647;

const RLIMIT_NOFILE: i32 = 7;
const RLIMIT_NPROC: i32 = 6;

// # C: long sysconf(int name)
#[no_mangle]
pub unsafe extern "C" fn sysconf(name: i32) -> i64 {
    // SAFETY: dynamic names hit getpagesize/get_nprocs/getrlimit (each safe,
    // no caller memory); the rest return Linux fixed limits. -1 (no errno) for
    // unbounded/unknown, matching glibc.
    unsafe {
        match name {
            SC_PAGESIZE => getpagesize() as i64,
            SC_NPROCESSORS_ONLN => get_nprocs() as i64,
            SC_NPROCESSORS_CONF => get_nprocs_conf() as i64,
            SC_PHYS_PAGES => get_phys_pages(),
            SC_AVPHYS_PAGES => get_avphys_pages(),
            SC_CLK_TCK => CLK_TCK,
            SC_NGROUPS_MAX => NGROUPS_MAX,
            SC_ARG_MAX => ARG_MAX,
            SC_STREAM_MAX => STREAM_MAX,
            SC_TZNAME_MAX => TZNAME_MAX,
            SC_RE_DUP_MAX => RE_DUP_MAX,
            SC_LINE_MAX => LINE_MAX,
            SC_LOGIN_NAME_MAX => LOGIN_NAME_MAX,
            SC_HOST_NAME_MAX => HOST_NAME_MAX,
            SC_SYMLOOP_MAX => SYMLOOP_MAX,
            SC_ATEXIT_MAX => ATEXIT_MAX,
            SC_GETPW_R_SIZE_MAX | SC_GETGR_R_SIZE_MAX => PW_GR_R_SIZE_MAX,
            SC_OPEN_MAX => rlim_cur(RLIMIT_NOFILE, OPEN_MAX_DFLT),
            SC_CHILD_MAX => rlim_cur(RLIMIT_NPROC, CHILD_MAX),
            _ => -1,
        }
    }
}
// # C: long __sysconf(int name)
#[no_mangle]
pub unsafe extern "C" fn __sysconf(name: i32) -> i64 {
    // SAFETY: __sysconf has the same scalar-name contract as sysconf.
    unsafe { sysconf(name) }
}

// rlim_cur of `res` (RLIM_INFINITY → fallback), else fallback on error.
unsafe fn rlim_cur(res: i32, fallback: i64) -> i64 {
    // SAFETY: getrlimit fills a stack rlimit; no caller memory dereferenced.
    unsafe {
        let mut rl = Rlimit { rlim_cur: 0, rlim_max: 0 };
        if getrlimit(res, &mut rl) != 0 || rl.rlim_cur == u64::MAX { return fallback; }
        rl.rlim_cur as i64
    }
}

// _CS_* codes.
const CS_PATH: i32 = 0;
const CS_GNU_LIBC_VERSION: i32 = 2;
const CS_GNU_LIBPTHREAD_VERSION: i32 = 3;

// confstr string values (NUL-terminated). _CS_PATH is glibc's default PATH.
const CS_PATH_STR: &[u8] = b"/usr/bin:/bin\0";
const CS_LIBC_STR: &[u8] = b"glibc 2.39\0";
const CS_LIBPTHREAD_STR: &[u8] = b"NPTL 2.39\0";

// # C: size_t confstr(int name, char *buf, size_t len)
#[no_mangle]
pub unsafe extern "C" fn confstr(name: i32, buf: *mut u8, len: usize) -> usize {
    // SAFETY: copies the selected NUL-terminated config string into buf (up to
    // len, always NUL-terminating when len>0); returns full length incl NUL.
    unsafe {
        let s: &[u8] = match name {
            CS_PATH => CS_PATH_STR,
            CS_GNU_LIBC_VERSION => CS_LIBC_STR,
            CS_GNU_LIBPTHREAD_VERSION => CS_LIBPTHREAD_STR,
            _ => return 0,
        };
        if !buf.is_null() && len > 0 {
            let n = core::cmp::min(len - 1, s.len() - 1);
            core::ptr::copy_nonoverlapping(s.as_ptr(), buf, n);
            *buf.add(n) = 0;
        }
        s.len() // includes the NUL
    }
}

// _PC_* codes (<bits/confname.h>).
const PC_LINK_MAX: i32 = 0;
const PC_MAX_CANON: i32 = 1;
const PC_MAX_INPUT: i32 = 2;
const PC_NAME_MAX: i32 = 3;
const PC_PATH_MAX: i32 = 4;
const PC_PIPE_BUF: i32 = 5;
const PC_CHOWN_RESTRICTED: i32 = 6;
const PC_NO_TRUNC: i32 = 7;
const PC_VDISABLE: i32 = 8;

// Linux fixed pathconf limits.
const LINK_MAX: i64 = 127;
const MAX_CANON: i64 = 255;
const MAX_INPUT: i64 = 255;
const NAME_MAX: i64 = 255;
const PATH_MAX: i64 = 4096;
const PIPE_BUF: i64 = 4096;
const POSIX_VDISABLE: i64 = 0;

fn pc_value(name: i32) -> i64 {
    match name {
        PC_LINK_MAX => LINK_MAX,
        PC_MAX_CANON => MAX_CANON,
        PC_MAX_INPUT => MAX_INPUT,
        PC_NAME_MAX => NAME_MAX,
        PC_PATH_MAX => PATH_MAX,
        PC_PIPE_BUF => PIPE_BUF,
        PC_CHOWN_RESTRICTED => 1,
        PC_NO_TRUNC => 1,
        PC_VDISABLE => POSIX_VDISABLE,
        _ => -1,
    }
}

// # C: long pathconf(const char *path, int name)
#[no_mangle]
pub unsafe extern "C" fn pathconf(_path: *const u8, name: i32) -> i64 {
    // SAFETY: returns Linux fixed limits independent of the path; path is read
    // by the caller's filesystem but we report the kernel-uniform values.
    pc_value(name)
}
// # C: long fpathconf(int fd, int name)
#[no_mangle]
pub unsafe extern "C" fn fpathconf(_fd: i32, name: i32) -> i64 {
    // SAFETY: same fixed Linux limits as pathconf; fd is not dereferenced.
    pc_value(name)
}
