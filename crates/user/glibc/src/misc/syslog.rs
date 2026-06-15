// <syslog.h> — system logging (openlog/syslog/vsyslog/closelog/setlogmask).
// LOG_* facility/level/option constants match host <sys/syslog.h>. A message
// is formatted "<PRI>TIMESTAMP IDENT[PID]: TEXT" and written to /dev/log
// (AF_UNIX datagram); if that fails it falls back to the console (stderr).
// `%m` in the user format expands to strerror(errno), per the syslog spec.

#![allow(non_upper_case_globals)]

// ---- priority levels (severities) ----
pub const LOG_EMERG: i32 = 0;
pub const LOG_ALERT: i32 = 1;
pub const LOG_CRIT: i32 = 2;
pub const LOG_ERR: i32 = 3;
pub const LOG_WARNING: i32 = 4;
pub const LOG_NOTICE: i32 = 5;
pub const LOG_INFO: i32 = 6;
pub const LOG_DEBUG: i32 = 7;
pub const LOG_PRIMASK: i32 = 0x07;

// ---- facilities (already shifted left by 3) ----
pub const LOG_KERN: i32 = 0 << 3;
pub const LOG_USER: i32 = 1 << 3;
pub const LOG_MAIL: i32 = 2 << 3;
pub const LOG_DAEMON: i32 = 3 << 3;
pub const LOG_AUTH: i32 = 4 << 3;
pub const LOG_SYSLOG: i32 = 5 << 3;
pub const LOG_LPR: i32 = 6 << 3;
pub const LOG_NEWS: i32 = 7 << 3;
pub const LOG_UUCP: i32 = 8 << 3;
pub const LOG_CRON: i32 = 9 << 3;
pub const LOG_AUTHPRIV: i32 = 10 << 3;
pub const LOG_FTP: i32 = 11 << 3;
pub const LOG_LOCAL0: i32 = 16 << 3;
pub const LOG_LOCAL1: i32 = 17 << 3;
pub const LOG_LOCAL2: i32 = 18 << 3;
pub const LOG_LOCAL3: i32 = 19 << 3;
pub const LOG_LOCAL4: i32 = 20 << 3;
pub const LOG_LOCAL5: i32 = 21 << 3;
pub const LOG_LOCAL6: i32 = 22 << 3;
pub const LOG_LOCAL7: i32 = 23 << 3;
pub const LOG_NFACILITIES: i32 = 24;
pub const LOG_FACMASK: i32 = 0x03f8;

// ---- openlog options ----
pub const LOG_PID: i32 = 0x01;
pub const LOG_CONS: i32 = 0x02;
pub const LOG_ODELAY: i32 = 0x04;
pub const LOG_NDELAY: i32 = 0x08;
pub const LOG_NOWAIT: i32 = 0x10;
pub const LOG_PERROR: i32 = 0x20;

/// # C: int LOG_MASK(int pri) — single-priority bit.
#[inline]
pub const fn log_mask(pri: i32) -> i32 { 1 << pri }
/// # C: int LOG_UPTO(int pri) — all priorities through pri.
#[inline]
pub const fn log_upto(pri: i32) -> i32 { (1 << (pri + 1)) - 1 }
/// # C: int LOG_PRI(int p) — priority part of a packed priority.
#[inline]
pub const fn log_pri(p: i32) -> i32 { p & LOG_PRIMASK }
/// # C: int LOG_FAC(int p) — facility number from a packed priority.
#[inline]
pub const fn log_fac(p: i32) -> i32 { (p & LOG_FACMASK) >> 3 }
/// # C: int LOG_MAKEPRI(int fac, int pri) — pack facility + priority.
#[inline]
pub const fn log_makepri(fac: i32, pri: i32) -> i32 { fac | pri }

#[cfg(feature = "freestanding")]
pub use imp::{closelog, openlog, setlogmask, syslog, vsyslog};

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::misc::sink::{vformat_into, FdSink};
    use crate::string::strerror::msg as strerror_msg;
    use core::cell::UnsafeCell;
    use core::ffi::VaList;

    const DEFAULT_FAC: i32 = LOG_USER;
    const STDERR_FD: i32 = 2;

    struct State { ident: *const u8, option: i32, facility: i32, mask: i32, fd: i32 }
    #[repr(transparent)]
    struct StateCell(UnsafeCell<State>);
    // SAFETY: syslog config is process-global, mutated only by openlog/
    // closelog/setlogmask which glibc also leaves unsynchronised; oxide's
    // single-thread startup matches that contract.
    unsafe impl Sync for StateCell {}
    static ST: StateCell = StateCell(UnsafeCell::new(State {
        ident: core::ptr::null(), option: 0, facility: DEFAULT_FAC, mask: 0xff, fd: -1,
    }));

    fn st() -> *mut State { ST.0.get() }

    // # C: void openlog(const char *ident, int option, int facility)
    #[no_mangle]
    pub unsafe extern "C" fn openlog(ident: *const u8, option: i32, facility: i32) {
        // SAFETY: stores caller-owned ident pointer + scalar option/facility;
        // LOG_NDELAY opens /dev/log eagerly (best effort).
        unsafe {
            let s = &mut *st();
            s.ident = ident;
            s.option = option;
            if facility != 0 { s.facility = facility & LOG_FACMASK; }
            if option & LOG_NDELAY != 0 && s.fd < 0 { s.fd = open_dev_log(); }
        }
    }

    // # C: void closelog(void)
    #[no_mangle]
    pub unsafe extern "C" fn closelog() {
        // SAFETY: closes the /dev/log fd if open and resets config to default.
        unsafe {
            let s = &mut *st();
            if s.fd >= 0 { crate::posix::io::close(s.fd); s.fd = -1; }
            s.ident = core::ptr::null();
            s.option = 0;
            s.facility = DEFAULT_FAC;
        }
    }

    // # C: int setlogmask(int mask) — set priority mask, return the old one.
    // mask == 0 queries without changing (glibc semantics).
    #[no_mangle]
    pub unsafe extern "C" fn setlogmask(mask: i32) -> i32 {
        // SAFETY: swaps the process-global mask; 0 leaves it unchanged.
        unsafe {
            let s = &mut *st();
            let old = s.mask;
            if mask != 0 { s.mask = mask; }
            old
        }
    }

    // # C: void syslog(int priority, const char *fmt, ...)
    #[no_mangle]
    pub unsafe extern "C" fn syslog(priority: i32, fmt: *const u8, mut ap: ...) {
        // SAFETY: ap supplies the varargs named by fmt; forwards to do_log.
        unsafe { do_log(priority, fmt, &mut ap); }
    }

    // # C: void vsyslog(int priority, const char *fmt, va_list ap)
    #[no_mangle]
    pub unsafe extern "C" fn vsyslog(priority: i32, fmt: *const u8, mut ap: VaList) {
        // SAFETY: ap holds the matching varargs; forwards to do_log.
        unsafe { do_log(priority, fmt, &mut ap); }
    }

    // shared formatter for syslog/vsyslog over a va_list.
    unsafe fn do_log(priority: i32, fmt: *const u8, ap: &mut VaList) {
        // SAFETY: state is process-global; fmt NUL-terminated; ap matches fmt.
        unsafe {
            let s = &mut *st();
            // drop messages whose level is masked out.
            if super::log_mask(super::log_pri(priority)) & s.mask == 0 { return; }
            // capture errno for %m before user formatting can clobber it.
            let e = *crate::internal::errno::__errno_location();

            // packed priority: caller facility, else the openlog default.
            let pri = if priority & LOG_FACMASK != 0 { priority } else { (priority & LOG_PRIMASK) | s.facility };

            let mut sink = build_sink(s);
            // "<PRI>" header.
            sink.put(b'<');
            put_dec(&mut sink, pri as u32);
            sink.put(b'>');
            // ident + optional [pid] + ": "
            if !s.ident.is_null() { sink.put_cstr(s.ident); }
            if s.option & LOG_PID != 0 {
                sink.put(b'[');
                // SAFETY: getpid(2) takes no args and cannot fail.
                let pid = crate::arch::syscall::sys0(crate::internal::nr::GETPID) as u32;
                put_dec(&mut sink, pid);
                sink.put(b']');
            }
            if !s.ident.is_null() { sink.put(b':'); sink.put(b' '); }
            // user message with %m → strerror(errno) expansion.
            emit_fmt(&mut sink, fmt, ap, e);
            sink.flush();
        }
    }

    // pick the destination fd: /dev/log if reachable, else stderr/console.
    unsafe fn build_sink(s: &mut State) -> FdSink {
        // SAFETY: opens /dev/log lazily; on failure uses stderr (LOG_CONS path).
        unsafe {
            if s.fd < 0 { s.fd = open_dev_log(); }
            let fd = if s.fd >= 0 { s.fd } else { STDERR_FD };
            FdSink::new(fd)
        }
    }

    #[repr(C)]
    struct SockaddrUn { sun_family: u16, sun_path: [u8; 108] }

    // connect an AF_UNIX datagram socket to /dev/log. Returns -1 on failure.
    unsafe fn open_dev_log() -> i32 {
        use crate::arch::syscall::{sys3, sys1};
        use crate::internal::{errno::ret, nr};
        use crate::net::socket::{AF_UNIX, SOCK_DGRAM};
        // SAFETY: socket(2) then connect(2) to the "/dev/log" unix path; the
        // sockaddr_un is stack-local and the path is a fixed NUL-terminated
        // literal that fits sun_path; close(2) on connect failure.
        unsafe {
            let fd = match ret(sys3(nr::SOCKET, AF_UNIX as usize, SOCK_DGRAM as usize, 0)) {
                Ok(v) => v as i32,
                Err(_) => return -1,
            };
            let mut addr = SockaddrUn { sun_family: AF_UNIX, sun_path: [0; 108] };
            let path = b"/dev/log";
            addr.sun_path[..path.len()].copy_from_slice(path);
            let len = 2 + path.len() + 1; // family + path + NUL
            match ret(sys3(nr::CONNECT, fd as usize, &addr as *const _ as usize, len)) {
                Ok(_) => fd,
                Err(_) => { let _ = sys1(nr::CLOSE, fd as usize); -1 }
            }
        }
    }

    // decimal u32 into the sink.
    fn put_dec(s: &mut FdSink, mut n: u32) {
        let mut tmp = [0u8; 10];
        let mut i = tmp.len();
        loop { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; if n == 0 { break; } }
        for &b in &tmp[i..] { s.put(b); }
    }

    // format fmt into sink, expanding "%m" to strerror(e). Other conversions
    // go through the printf engine on the run between %m's.
    unsafe fn emit_fmt(sink: &mut FdSink, fmt: *const u8, ap: &mut VaList, e: i32) {
        if fmt.is_null() { return; }
        // SAFETY: fmt NUL-terminated; pre-expand %m, format the rest via
        // the printf engine. Run-splitting keeps each piece NUL-bounded.
        unsafe {
            let mut buf = alloc::vec::Vec::<u8>::new();
            let mut p = fmt;
            while *p != 0 {
                if *p == b'%' && *p.add(1) == b'm' {
                    for &b in strerror_msg(e) { buf.push(b); }
                    p = p.add(2);
                } else {
                    buf.push(*p);
                    // keep '%' pairs intact so the engine sees valid specs.
                    if *p == b'%' && *p.add(1) != 0 { buf.push(*p.add(1)); p = p.add(2); }
                    else { p = p.add(1); }
                }
            }
            buf.push(0);
            vformat_into(sink, buf.as_ptr(), ap);
        }
    }
}
