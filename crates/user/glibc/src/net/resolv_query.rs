// Resolver query builders (docs/59 §9.1): pure DNS packet construction for
// res_mkquery/res_nmkquery. Network send/search APIs remain separate.
#![cfg(feature = "freestanding")]

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::syscall::{sys1, sys3, sys4, sys6};
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::net::netdb::{NO_RECOVERY, TRY_AGAIN};
use crate::net::socket::{sockaddr_in, AF_INET, SOCK_DGRAM};

const QUERY: i32 = 0;
const HEADER_LEN: usize = 12;
const EMSGSIZE: i32 = 90;
const EINVAL: i32 = 22;
const AT_FDCWD: i32 = -100;
const POLLIN: i16 = 1;
const DNS_PORT: u16 = 53;
const RES_RECURSE: u64 = 0x0000_0040;
const RES_TRUSTAD: u64 = 0x0400_0000;
static QHOOK: AtomicUsize = AtomicUsize::new(0);
static RHOOK: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct PollFd { fd: i32, events: i16, revents: i16 }

#[repr(C)]
struct Timespec { tv_sec: i64, tv_nsec: i64 }

extern "C" {
    fn __h_errno_location() -> *mut i32;
}

unsafe fn set_herrno(v: i32) {
    // SAFETY: __h_errno_location returns the process/thread h_errno slot.
    unsafe { *__h_errno_location() = v; }
}

unsafe fn put16(dst: *mut u8, v: u16) {
    // SAFETY: dst points to two writable bytes.
    unsafe {
        *dst = (v >> 8) as u8;
        *dst.add(1) = v as u8;
    }
}

unsafe fn build(op: i32, dname: *const c_char, class: i32, ty: i32, newrr: *const u8, buf: *mut u8, buflen: i32, flags: u16) -> i32 {
    // SAFETY: dname is a presentation DNS name; buf is writable for buflen
    // bytes. newrr/update queries are not supported by this focused builder.
    unsafe {
        if op != QUERY || !newrr.is_null() || buflen < HEADER_LEN as i32 || dname.is_null() || buf.is_null() {
            crate::internal::errno::set(EMSGSIZE);
            return -1;
        }
        let cap = buflen as usize;
        core::ptr::write_bytes(buf, 0, HEADER_LEN);
        put16(buf.add(2), flags);
        put16(buf.add(4), 1);
        let q = buf.add(HEADER_LEN);
        let n = crate::net::nameser::ns_name_compress(dname, q, cap - HEADER_LEN, core::ptr::null_mut(), core::ptr::null_mut());
        if n < 0 || HEADER_LEN + n as usize + 4 > cap {
            crate::internal::errno::set(EMSGSIZE);
            return -1;
        }
        let p = q.add(n as usize);
        put16(p, ty as u16);
        put16(p.add(2), class as u16);
        (HEADER_LEN + n as usize + 4) as i32
    }
}

unsafe fn state_options(statp: *mut c_void) -> u64 {
    // SAFETY: glibc's res_state starts `int retrans; int retry; unsigned long options;`.
    unsafe { *((statp as *const u8).add(8) as *const u64) }
}

fn query_flags(options: u64) -> u16 {
    let mut flags = 0u16;
    if options & RES_RECURSE != 0 { flags |= 0x0100; }
    if options & RES_TRUSTAD != 0 { flags |= 0x0020; }
    flags
}

fn parse_ipv4(s: &[u8]) -> Option<u32> {
    let mut parts = [0u8; 4];
    let mut idx = 0usize;
    let mut val = 0u32;
    let mut saw = false;
    for &b in s {
        if b == b'.' {
            if !saw || idx >= 3 || val > 255 { return None; }
            parts[idx] = val as u8;
            idx += 1;
            val = 0;
            saw = false;
        } else if b.is_ascii_digit() {
            val = val.saturating_mul(10).saturating_add((b - b'0') as u32);
            saw = true;
        } else {
            break;
        }
    }
    if !saw || idx != 3 || val > 255 { return None; }
    parts[3] = val as u8;
    Some(u32::from_be_bytes(parts).to_be())
}

fn first_nameserver() -> u32 {
    let mut buf = [0u8; 2048];
    let path = b"/etc/resolv.conf\0";
    // SAFETY: opens a fixed NUL-terminated /etc/resolv.conf path read-only.
    let fd = ret_isize(unsafe { sys4(nr::OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, 0, 0) }) as i32;
    if fd < 0 {
        return u32::from_be_bytes([127, 0, 0, 1]).to_be();
    }
    // SAFETY: reads into the fixed stack buffer, then closes the scalar fd.
    let n = ret_isize(unsafe { sys3(nr::READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) });
    // SAFETY: close(2) takes only the scalar fd returned by openat.
    unsafe { sys1(nr::CLOSE, fd as usize); }
    if n <= 0 {
        return u32::from_be_bytes([127, 0, 0, 1]).to_be();
    }
    for line in buf[..n as usize].split(|&b| b == b'\n') {
        let mut p = line;
        while p.first().is_some_and(|c| c.is_ascii_whitespace()) { p = &p[1..]; }
        if !p.starts_with(b"nameserver") { continue; }
        p = &p[b"nameserver".len()..];
        while p.first().is_some_and(|c| c.is_ascii_whitespace()) { p = &p[1..]; }
        if let Some(addr) = parse_ipv4(p) { return addr; }
    }
    u32::from_be_bytes([127, 0, 0, 1]).to_be()
}

unsafe fn udp_send(query: *const u8, querylen: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: query/answer are caller buffers. Kernel validates socket buffers;
    // this function bounds every Rust slice/pointer by the supplied lengths.
    unsafe {
        if query.is_null() || answer.is_null() || querylen <= 0 || anslen <= 0 {
            crate::internal::errno::set(EINVAL);
            set_herrno(NO_RECOVERY);
            return -1;
        }
        let fd = ret_isize(sys3(nr::SOCKET, AF_INET as usize, SOCK_DGRAM as usize, 0)) as i32;
        if fd < 0 {
            set_herrno(TRY_AGAIN);
            return -1;
        }
        let addr = sockaddr_in {
            sin_family: AF_INET,
            sin_port: DNS_PORT.to_be(),
            sin_addr: first_nameserver(),
            sin_zero: [0; 8],
        };
        let sr = ret_isize(sys6(
            nr::SENDTO,
            fd as usize,
            query as usize,
            querylen as usize,
            0,
            &addr as *const sockaddr_in as usize,
            core::mem::size_of::<sockaddr_in>(),
        ));
        if sr < 0 {
            sys1(nr::CLOSE, fd as usize);
            set_herrno(TRY_AGAIN);
            return -1;
        }
        let mut pfd = PollFd { fd, events: POLLIN, revents: 0 };
        let ts = Timespec { tv_sec: 2, tv_nsec: 0 };
        let pr = ret_isize(sys6(
            nr::PPOLL,
            &mut pfd as *mut PollFd as usize,
            1,
            &ts as *const Timespec as usize,
            0,
            0,
            0,
        ));
        if pr <= 0 {
            sys1(nr::CLOSE, fd as usize);
            set_herrno(TRY_AGAIN);
            return -1;
        }
        let rr = ret_isize(sys6(
            nr::RECVFROM,
            fd as usize,
            answer as usize,
            anslen as usize,
            0,
            0,
            0,
        ));
        sys1(nr::CLOSE, fd as usize);
        if rr < 0 {
            set_herrno(TRY_AGAIN);
            -1
        } else {
            rr as i32
        }
    }
}

unsafe fn query_common(statp: *mut c_void, name: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: name is NUL-terminated; answer is writable for anslen bytes.
    unsafe {
        let mut qbuf = [0u8; 1024];
        let qlen = res_nmkquery(statp, QUERY, name, class, ty, core::ptr::null(), 0, core::ptr::null(), qbuf.as_mut_ptr(), qbuf.len() as i32);
        if qlen < 0 {
            set_herrno(NO_RECOVERY);
            return -1;
        }
        udp_send(qbuf.as_ptr(), qlen, answer, anslen)
    }
}

unsafe fn query_domain_common(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: name/domain are null or NUL-terminated C strings; combined name
    // is built in a fixed buffer and then passed to query_common.
    unsafe {
        if name.is_null() || domain.is_null() || *domain == 0 {
            return query_common(statp, name, class, ty, answer, anslen);
        }
        let mut out = [0u8; 256];
        let mut n = 0usize;
        let mut p = name as *const u8;
        while *p != 0 {
            if n + 1 >= out.len() { set_herrno(NO_RECOVERY); return -1; }
            out[n] = *p;
            n += 1;
            p = p.add(1);
        }
        if n > 0 && out[n - 1] != b'.' {
            if n + 1 >= out.len() { set_herrno(NO_RECOVERY); return -1; }
            out[n] = b'.';
            n += 1;
        }
        p = domain as *const u8;
        while *p != 0 {
            if n + 1 >= out.len() { set_herrno(NO_RECOVERY); return -1; }
            out[n] = *p;
            n += 1;
            p = p.add(1);
        }
        out[n] = 0;
        query_common(statp, out.as_ptr() as *const c_char, class, ty, answer, anslen)
    }
}

// # C: int res_mkquery(int op, const char *dname, int class, int type,
//                      const unsigned char *data, int datalen,
//                      const unsigned char *newrr,
//                      unsigned char *buf, int buflen)
#[no_mangle]
pub unsafe extern "C" fn res_mkquery(op: i32, dname: *const c_char, class: i32, ty: i32, _data: *const u8, _datalen: i32, newrr: *const u8, buf: *mut u8, buflen: i32) -> i32 {
    // SAFETY: forwards raw C pointers to the checked packet builder.
    unsafe { build(op, dname, class, ty, newrr, buf, buflen, query_flags(RES_RECURSE | RES_TRUSTAD)) }
}

// # C: int res_nmkquery(res_state statp, int op, const char *dname, int class,
//                       int type, const unsigned char *data, int datalen,
//                       const unsigned char *newrr, unsigned char *buf, int buflen)
#[no_mangle]
pub unsafe extern "C" fn res_nmkquery(_statp: *mut c_void, op: i32, dname: *const c_char, class: i32, ty: i32, _data: *const u8, _datalen: i32, newrr: *const u8, buf: *mut u8, buflen: i32) -> i32 {
    // SAFETY: statp is accepted for ABI compatibility; only the leading
    // `options` field is used to match glibc's QUERY header flags.
    let flags = if _statp.is_null() {
        0
    } else {
        // SAFETY: non-null statp points to a resolver state whose prefix
        // contains the glibc-compatible options word.
        unsafe { query_flags(state_options(_statp)) }
    };
    // SAFETY: forwards raw C pointers to the checked packet builder.
    unsafe { build(op, dname, class, ty, newrr, buf, buflen, flags) }
}

// # C: void res_send_setqhook(void *hook)
#[no_mangle]
pub extern "C" fn res_send_setqhook(hook: *mut c_void) {
    QHOOK.store(hook as usize, Ordering::Relaxed);
}

// # C: void res_send_setrhook(void *hook)
#[no_mangle]
pub extern "C" fn res_send_setrhook(hook: *mut c_void) {
    RHOOK.store(hook as usize, Ordering::Relaxed);
}

// # C: int res_nsend(res_state statp, const unsigned char *msg, int msglen,
//                    unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_nsend(_statp: *mut c_void, msg: *const u8, msglen: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: forwards caller buffers to the bounded UDP DNS sender.
    unsafe { udp_send(msg, msglen, answer, anslen) }
}

// # C: int res_send(const unsigned char *msg, int msglen, unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_send(msg: *const u8, msglen: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: resolver state defaults are not required for sending a complete packet.
    unsafe { res_nsend(core::ptr::null_mut(), msg, msglen, answer, anslen) }
}

// # C: int res_nquery(res_state statp, const char *dname, int class, int type,
//                     unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_nquery(statp: *mut c_void, dname: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: forwards the checked C-string/query buffers to query_common.
    unsafe { query_common(statp, dname, class, ty, answer, anslen) }
}

// # C: int res_query(const char *dname, int class, int type, unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_query(dname: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: default-state wrapper for res_nquery.
    unsafe { res_nquery(core::ptr::null_mut(), dname, class, ty, answer, anslen) }
}

// # C: int res_nquerydomain(res_state statp, const char *name, const char *domain,
//                           int class, int type, unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_nquerydomain(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: combines name/domain into a bounded stack C string.
    unsafe { query_domain_common(statp, name, domain, class, ty, answer, anslen) }
}

// # C: int res_querydomain(const char *name, const char *domain, int class,
//                          int type, unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_querydomain(name: *const c_char, domain: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: default-state wrapper for res_nquerydomain.
    unsafe { res_nquerydomain(core::ptr::null_mut(), name, domain, class, ty, answer, anslen) }
}

// # C: int res_nsearch(res_state statp, const char *dname, int class, int type,
//                      unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_nsearch(statp: *mut c_void, dname: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: minimal search path: query the supplied name exactly.
    unsafe { res_nquery(statp, dname, class, ty, answer, anslen) }
}

// # C: int res_search(const char *dname, int class, int type, unsigned char *answer, int anslen)
#[no_mangle]
pub unsafe extern "C" fn res_search(dname: *const c_char, class: i32, ty: i32, answer: *mut u8, anslen: i32) -> i32 {
    // SAFETY: default-state wrapper for res_nsearch.
    unsafe { res_nsearch(core::ptr::null_mut(), dname, class, ty, answer, anslen) }
}
