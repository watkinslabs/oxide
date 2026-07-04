use super::*;

// # C: void setutxent(void)
#[no_mangle]
pub unsafe extern "C" fn setutxent() {
    // SAFETY: utmpx alias of setutent over the shared global database.
    unsafe { setutent() }
}
// # C: void endutxent(void)
#[no_mangle]
pub unsafe extern "C" fn endutxent() {
    // SAFETY: utmpx alias of endutent over the shared global database.
    unsafe { endutent() }
}
// # C: struct utmpx *getutxent(void)
#[no_mangle]
pub unsafe extern "C" fn getutxent() -> *mut utmpx {
    // SAFETY: utmpx alias of getutent; same record layout and return buffer.
    unsafe { getutent() }
}
// # C: struct utmpx *getutxid(const struct utmpx *id)
#[no_mangle]
pub unsafe extern "C" fn getutxid(id: *const utmpx) -> *mut utmpx {
    // SAFETY: utmpx alias of getutid; id is caller storage with utmp layout.
    unsafe { getutid(id) }
}
// # C: struct utmpx *getutxline(const struct utmpx *line)
#[no_mangle]
pub unsafe extern "C" fn getutxline(line: *const utmpx) -> *mut utmpx {
    // SAFETY: utmpx alias of getutline; line is caller storage, utmp layout.
    unsafe { getutline(line) }
}
// # C: struct utmpx *pututxline(const struct utmpx *ut)
#[no_mangle]
pub unsafe extern "C" fn pututxline(ut: *const utmpx) -> *mut utmpx {
    // SAFETY: utmpx alias of pututline; ut is caller storage, utmp layout.
    unsafe { pututline(ut) }
}
// # C: int utmpxname(const char *file)
#[no_mangle]
pub unsafe extern "C" fn utmpxname(file: *const u8) -> i32 {
    // SAFETY: utmpx alias of utmpname; file is a NUL-terminated path.
    unsafe { utmpname(file) }
}

// updwtmp/updwtmpx — append one record to the named wtmp file.

// # C: void updwtmp(const char *wtmp_file, const struct utmp *ut)
#[no_mangle]
pub unsafe extern "C" fn updwtmp(wtmp_file: *const u8, ut: *const utmp) {
    // SAFETY: wtmp_file is a NUL-terminated path (default /var/log/wtmp); ut is
    // caller storage. Open O_WRONLY|O_CREAT|O_APPEND-equivalent (seek to end)
    // and append one fixed record.
    unsafe {
        if ut.is_null() { return; }
        let path = if wtmp_file.is_null() { WTMP_FILE.as_ptr() } else { wtmp_file };
        let fd = open(path, O_RDWR | O_CREAT, 0o644);
        if fd < 0 { return; }
        lseek(fd, 0, SEEK_END);
        write(fd, ut as *const u8, REC);
        close(fd);
    }
}
// # C: void updwtmpx(const char *wtmpx_file, const struct utmpx *utx)
#[no_mangle]
pub unsafe extern "C" fn updwtmpx(wtmpx_file: *const u8, utx: *const utmpx) {
    // SAFETY: utmpx alias of updwtmp; same path/record contract.
    unsafe { updwtmp(wtmpx_file, utx) }
}

// getutmp/getutmpx — convert between utmp and utmpx (identical layout here, so
// a straight byte copy, matching glibc's memcpy-equivalent on Linux).

// # C: void getutmp(const struct utmpx *ux, struct utmp *u)
#[no_mangle]
pub unsafe extern "C" fn getutmp(ux: *const utmpx, u: *mut utmp) {
    // SAFETY: ux/u are caller storage of identical (utmp==utmpx) layout; copy
    // one record's bytes from ux into u.
    unsafe { if !ux.is_null() && !u.is_null() { core::ptr::copy_nonoverlapping(ux as *const u8, u as *mut u8, REC); } }
}
// # C: void getutmpx(const struct utmp *u, struct utmpx *ux)
#[no_mangle]
pub unsafe extern "C" fn getutmpx(u: *const utmp, ux: *mut utmpx) {
    // SAFETY: u/ux are caller storage of identical layout; copy one record's
    // bytes from u into ux.
    unsafe { if !u.is_null() && !ux.is_null() { core::ptr::copy_nonoverlapping(u as *const u8, ux as *mut u8, REC); } }
}
