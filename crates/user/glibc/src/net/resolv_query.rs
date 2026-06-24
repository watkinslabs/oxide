// Resolver query builders (docs/59 §9.1): pure DNS packet construction for
// res_mkquery/res_nmkquery. Network send/search APIs remain separate.
#![cfg(feature = "freestanding")]

use core::ffi::{c_char, c_void};

const QUERY: i32 = 0;
const HEADER_LEN: usize = 12;
const EMSGSIZE: i32 = 90;
const RES_RECURSE: u64 = 0x0000_0040;
const RES_TRUSTAD: u64 = 0x0400_0000;

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
