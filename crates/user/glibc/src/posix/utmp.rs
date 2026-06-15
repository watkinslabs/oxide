// <utmp.h> + <utmpx.h> (docs/59§6) — user-accounting database (utmp/wtmp).
// Fixed-record binary I/O over an internal fd, default "/var/run/utmp",
// overridable via utmpname/utmpxname. getutent/getutid/getutline return a
// pointer into one process-global static buffer; glibc is not thread-safe
// here and neither are we (single shared fd + buffer). C ABI only.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;

// struct utmp / utmpx, glibc x86_64 layout (sizeof = 384). On this sysroot the
// __WORDSIZE_TIME64_COMPAT32 variant applies: ut_session is int32 and ut_tv is
// {uint32 tv_sec; int32 tv_usec} so a file is shareable 32/64-bit. Offsets
// verified against /usr/include/bits/utmp.h: ut_type 0, ut_pid 4, ut_line 8,
// ut_id 40, ut_user 44, ut_host 76, ut_exit 332, ut_session 336, ut_tv 340,
// ut_addr_v6 348, __glibc_reserved 364..384.
pub const UT_LINESIZE: usize = 32;
pub const UT_NAMESIZE: usize = 32;
pub const UT_HOSTSIZE: usize = 256;

// ut_type values.
pub const EMPTY: i16 = 0;
pub const RUN_LVL: i16 = 1;
pub const BOOT_TIME: i16 = 2;
pub const NEW_TIME: i16 = 3;
pub const OLD_TIME: i16 = 4;
pub const INIT_PROCESS: i16 = 5;
pub const LOGIN_PROCESS: i16 = 6;
pub const USER_PROCESS: i16 = 7;
pub const DEAD_PROCESS: i16 = 8;
pub const ACCOUNTING: i16 = 9;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct exit_status { pub e_termination: i16, pub e_exit: i16 }

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ut_tv_t { pub tv_sec: u32, pub tv_usec: i32 }

#[repr(C)]
#[derive(Clone, Copy)]
pub struct utmp {
    pub ut_type: i16,
    pub ut_pid: i32,
    pub ut_line: [u8; UT_LINESIZE],
    pub ut_id: [u8; 4],
    pub ut_user: [u8; UT_NAMESIZE],
    pub ut_host: [u8; UT_HOSTSIZE],
    pub ut_exit: exit_status,
    pub ut_session: i32,
    pub ut_tv: ut_tv_t,
    pub ut_addr_v6: [i32; 4],
    pub __glibc_reserved: [u8; 20],
}

// utmpx is byte-identical to utmp on glibc; alias the layout. snake_case to
// match the C type name <utmpx.h> exports, like the mntent/dirent structs.
#[allow(non_camel_case_types)]
pub type utmpx = utmp;

const REC: usize = core::mem::size_of::<utmp>();

const EMPTY_UTMP: utmp = utmp {
    ut_type: 0, ut_pid: 0, ut_line: [0; UT_LINESIZE], ut_id: [0; 4],
    ut_user: [0; UT_NAMESIZE], ut_host: [0; UT_HOSTSIZE],
    ut_exit: exit_status { e_termination: 0, e_exit: 0 }, ut_session: 0,
    ut_tv: ut_tv_t { tv_sec: 0, tv_usec: 0 }, ut_addr_v6: [0; 4],
    __glibc_reserved: [0; 20],
};

extern "C" {
    fn open(path: *const u8, flags: i32, mode: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    fn lseek(fd: i32, off: i64, whence: i32) -> i64;
}
const O_RDWR: i32 = 2;
const O_RDONLY: i32 = 0;
const O_CREAT: i32 = 0o100;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

const DEFAULT_FILE: &[u8] = b"/var/run/utmp\0";
const WTMP_FILE: &[u8] = b"/var/log/wtmp\0";
const PATH_MAX: usize = 256;

// Process-global database state (path name + open fd + return buffer). glibc's
// utent is process-wide and not thread-safe; we match that exactly.
struct State { name: [u8; PATH_MAX], fd: i32, ret: utmp }
struct DbCell(UnsafeCell<State>);
// SAFETY: process-global utmp state mirrors glibc's single non-reentrant utent
// database; access is single-threaded by the same contract glibc documents.
unsafe impl Sync for DbCell {}
static DB: DbCell = DbCell(UnsafeCell::new(State {
    name: { let mut n = [0u8; PATH_MAX]; let mut i = 0; while i < DEFAULT_FILE.len() { n[i] = DEFAULT_FILE[i]; i += 1; } n },
    fd: -1, ret: EMPTY_UTMP,
}));

#[inline] fn db() -> *mut State { DB.0.get() }

// Open (or reuse) the database fd, seeking to start. Returns the fd or -1.
unsafe fn ensure_open(s: *mut State) -> i32 {
    // SAFETY: s is the process-global utmp State; (*s).name is a NUL-terminated
    // path buffer; we open it once and cache the fd, mirroring glibc setutent.
    unsafe {
        if (*s).fd >= 0 { return (*s).fd; }
        let p = (*s).name.as_ptr();
        let mut fd = open(p, O_RDWR, 0);
        if fd < 0 { fd = open(p, O_RDONLY, 0); }
        (*s).fd = fd;
        fd
    }
}

// # C: void setutent(void)
#[no_mangle]
pub unsafe extern "C" fn setutent() {
    // SAFETY: open the database (if needed) and rewind to the first record;
    // operates only on the process-global utmp State.
    unsafe { let s = db(); let fd = ensure_open(s); if fd >= 0 { lseek(fd, 0, SEEK_SET); } }
}

// # C: void endutent(void)
#[no_mangle]
pub unsafe extern "C" fn endutent() {
    // SAFETY: close and clear the cached database fd in the global utmp State.
    unsafe { let s = db(); if (*s).fd >= 0 { close((*s).fd); (*s).fd = -1; } }
}

// # C: struct utmp *getutent(void)
#[no_mangle]
pub unsafe extern "C" fn getutent() -> *mut utmp {
    // SAFETY: read one fixed-size record from the database fd into the global
    // return buffer; a short/zero read means EOF, returning NULL like glibc.
    unsafe {
        let s = db();
        let fd = ensure_open(s);
        if fd < 0 { return core::ptr::null_mut(); }
        let buf = core::ptr::addr_of_mut!((*s).ret) as *mut u8;
        let n = read(fd, buf, REC);
        if n == REC as isize { core::ptr::addr_of_mut!((*s).ret) } else { core::ptr::null_mut() }
    }
}

#[inline] fn id_match(a: &[u8; 4], b: &[u8; 4]) -> bool { a == b }

// # C: struct utmp *getutid(const struct utmp *id)
#[no_mangle]
pub unsafe extern "C" fn getutid(id: *const utmp) -> *mut utmp {
    // SAFETY: id is a caller-provided utmp; scan forward from the current
    // position matching ut_type per glibc rules (RUN_LVL/BOOT_TIME/NEW_TIME/
    // OLD_TIME match by type; *_PROCESS types match by ut_id).
    unsafe {
        if id.is_null() { return core::ptr::null_mut(); }
        let t = (*id).ut_type;
        // by_type: time-class records match on ut_type; by_id: process-class
        // records match on ut_id; others never match (glibc getutid rules).
        let by_type = matches!(t, RUN_LVL | BOOT_TIME | NEW_TIME | OLD_TIME);
        let by_id = matches!(t, INIT_PROCESS | LOGIN_PROCESS | USER_PROCESS | DEAD_PROCESS);
        loop {
            let e = getutent();
            if e.is_null() { return core::ptr::null_mut(); }
            if by_type && (*e).ut_type == t { return e; }
            if by_id && id_match(&(*e).ut_id, &(*id).ut_id) { return e; }
        }
    }
}

#[inline] fn line_eq(a: &[u8; UT_LINESIZE], b: &[u8; UT_LINESIZE]) -> bool { a == b }

// # C: struct utmp *getutline(const struct utmp *line)
#[no_mangle]
pub unsafe extern "C" fn getutline(line: *const utmp) -> *mut utmp {
    // SAFETY: line is caller storage; scan forward for a USER/LOGIN_PROCESS
    // record whose ut_line matches, per glibc getutline semantics.
    unsafe {
        if line.is_null() { return core::ptr::null_mut(); }
        loop {
            let e = getutent();
            if e.is_null() { return core::ptr::null_mut(); }
            if ((*e).ut_type == USER_PROCESS || (*e).ut_type == LOGIN_PROCESS)
                && line_eq(&(*e).ut_line, &(*line).ut_line) { return e; }
        }
    }
}

// # C: struct utmp *pututline(const struct utmp *ut)
#[no_mangle]
pub unsafe extern "C" fn pututline(ut: *const utmp) -> *mut utmp {
    // SAFETY: ut is caller storage; locate a matching record via getutid (which
    // rewinds an entry on hit) and overwrite it, else append at EOF. The shared
    // database fd backs both the seek and the write.
    unsafe {
        if ut.is_null() { return core::ptr::null_mut(); }
        let s = db();
        let fd = ensure_open(s);
        if fd < 0 { return core::ptr::null_mut(); }
        // Try to find an existing slot for this id; getutid leaves the fd just
        // past the matched record, so rewind one record before writing.
        let found = getutid(ut);
        let pos = if !found.is_null() {
            let cur = lseek(fd, 0, SEEK_CUR);
            if cur >= REC as i64 { cur - REC as i64 } else { 0 }
        } else {
            lseek(fd, 0, SEEK_END)
        };
        if lseek(fd, pos, SEEK_SET) < 0 { return core::ptr::null_mut(); }
        let src = ut as *const u8;
        if write(fd, src, REC) != REC as isize { return core::ptr::null_mut(); }
        // Mirror into the return buffer and hand it back.
        core::ptr::copy_nonoverlapping(src, core::ptr::addr_of_mut!((*s).ret) as *mut u8, REC);
        core::ptr::addr_of_mut!((*s).ret)
    }
}

// # C: int utmpname(const char *file)
#[no_mangle]
pub unsafe extern "C" fn utmpname(file: *const u8) -> i32 {
    // SAFETY: file is a NUL-terminated path; copy it (bounded by PATH_MAX) into
    // the global name buffer and close any open fd so the next op reopens it.
    unsafe {
        if file.is_null() { return -1; }
        let s = db();
        let mut i = 0;
        while i < PATH_MAX - 1 {
            let c = *file.add(i);
            (*s).name[i] = c;
            if c == 0 { break; }
            i += 1;
        }
        (*s).name[if i < PATH_MAX { i } else { PATH_MAX - 1 }] = 0;
        if (*s).fd >= 0 { close((*s).fd); (*s).fd = -1; }
        0
    }
}

// utmpx aliases (utmpx layout == utmp).

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn layout() {
        assert_eq!(REC, 384);
        assert_eq!(core::mem::offset_of!(utmp, ut_pid), 4);
        assert_eq!(core::mem::offset_of!(utmp, ut_line), 8);
        assert_eq!(core::mem::offset_of!(utmp, ut_id), 40);
        assert_eq!(core::mem::offset_of!(utmp, ut_user), 44);
        assert_eq!(core::mem::offset_of!(utmp, ut_host), 76);
        assert_eq!(core::mem::offset_of!(utmp, ut_exit), 332);
        assert_eq!(core::mem::offset_of!(utmp, ut_session), 336);
        assert_eq!(core::mem::offset_of!(utmp, ut_tv), 340);
        assert_eq!(core::mem::offset_of!(utmp, ut_addr_v6), 348);
        assert_eq!(core::mem::offset_of!(utmp, __glibc_reserved), 364);
    }
}
