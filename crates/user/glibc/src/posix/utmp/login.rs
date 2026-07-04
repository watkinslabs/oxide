use super::*;
// appending to wtmp, reusing pututline/updwtmp/getutline.

extern "C" {
    fn getpid() -> i32;
    fn ttyname_r(fd: i32, buf: *mut u8, n: usize) -> i32;
    fn gettimeofday(tv: *mut core::ffi::c_void, tz: *mut core::ffi::c_void) -> i32;
}

// Fill ut_tv from gettimeofday(2), narrowing into the 32-bit utmp time fields.
unsafe fn stamp(ut: *mut utmp) {
    // SAFETY: ut is a valid utmp; gettimeofday fills a {sec,usec} pair we narrow
    // into the 32-bit utmp time fields this glibc layout uses.
    unsafe {
        #[repr(C)] struct Tv { s: i64, u: i64 }
        let mut tv = Tv { s: 0, u: 0 };
        gettimeofday(core::ptr::addr_of_mut!(tv) as *mut core::ffi::c_void, core::ptr::null_mut());
        (*ut).ut_tv = ut_tv_t { tv_sec: tv.s as u32, tv_usec: tv.u as i32 };
    }
}

// # C: void login(const struct utmp *ut)
#[no_mangle]
pub unsafe extern "C" fn login(ut: *const utmp) {
    // SAFETY: ut is caller storage. Copy it, force USER_PROCESS + the calling
    // pid, derive ut_line from the controlling tty when empty, pututline, and
    // append to wtmp (glibc login(3)).
    unsafe {
        if ut.is_null() { return; }
        let mut rec = *ut;
        rec.ut_type = USER_PROCESS;
        rec.ut_pid = getpid();
        if rec.ut_line[0] == 0 {
            let mut path = [0u8; PATH_MAX];
            let mut fd = 0;
            while fd < 3 { if ttyname_r(fd, path.as_mut_ptr(), PATH_MAX) == 0 { break; } fd += 1; }
            if fd < 3 {
                let p: &[u8] = if path.starts_with(b"/dev/") { &path[5..] } else { &path[..] };
                let mut i = 0; while i < UT_LINESIZE && i < p.len() && p[i] != 0 { rec.ut_line[i] = p[i]; i += 1; }
            }
        }
        stamp(core::ptr::addr_of_mut!(rec));
        setutent();
        pututline(core::ptr::addr_of!(rec));
        endutent();
        updwtmp(WTMP_FILE.as_ptr(), core::ptr::addr_of!(rec));
    }
}

// # C: int logout(const char *line)
#[no_mangle]
pub unsafe extern "C" fn logout(line: *const u8) -> i32 {
    // SAFETY: line is a NUL-terminated tty name. Find the matching record,
    // rewrite it DEAD_PROCESS with cleared user/host + fresh time, write it
    // back via pututline. Returns 1 on success, 0 if no record matched.
    unsafe {
        if line.is_null() { return 0; }
        let mut q = EMPTY_UTMP;
        let mut i = 0; while i < UT_LINESIZE { let c = *line.add(i); if c == 0 { break; } q.ut_line[i] = c; i += 1; }
        setutent();
        let e = getutline(core::ptr::addr_of!(q));
        if e.is_null() { endutent(); return 0; }
        let mut rec = *e;
        rec.ut_type = DEAD_PROCESS;
        rec.ut_user = [0; UT_NAMESIZE];
        rec.ut_host = [0; UT_HOSTSIZE];
        stamp(core::ptr::addr_of_mut!(rec));
        pututline(core::ptr::addr_of!(rec));
        endutent();
        1
    }
}

// # C: void logwtmp(const char *line, const char *name, const char *host)
#[no_mangle]
pub unsafe extern "C" fn logwtmp(line: *const u8, name: *const u8, host: *const u8) {
    // SAFETY: line/name/host are NUL-terminated (any may be empty). Build a
    // record (USER_PROCESS when name non-empty, else DEAD_PROCESS) and append
    // it to the default wtmp via updwtmp — glibc logwtmp(3).
    unsafe {
        let mut rec = EMPTY_UTMP;
        rec.ut_pid = getpid();
        let cp = |dst: &mut [u8], src: *const u8| {
            if src.is_null() { return; }
            let mut i = 0; while i < dst.len() { let c = *src.add(i); if c == 0 { break; } dst[i] = c; i += 1; }
        };
        cp(&mut rec.ut_line, line);
        cp(&mut rec.ut_user, name);
        cp(&mut rec.ut_host, host);
        rec.ut_type = if !name.is_null() && *name != 0 { USER_PROCESS } else { DEAD_PROCESS };
        stamp(core::ptr::addr_of_mut!(rec));
        updwtmp(WTMP_FILE.as_ptr(), core::ptr::addr_of!(rec));
    }
}
