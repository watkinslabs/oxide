// RFC3542 IPv6 Routing Header (Type 0) builder/parser (docs/59§6 G13):
// inet6_rth_space/init/add/segments/getaddr/reverse. struct ip6_rthdr0 is
// { u8 nxt; u8 len; u8 type; u8 segleft; u32 reserved; in6_addr[segments] },
// len counted in 8-octet units (= 2*segments), addresses at offset 8. C ABI.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

const RTHDR_TYPE_0: i32 = 0;
const HDR: usize = 8;        // fixed header bytes before the address vector
const ADDR: usize = 16;      // sizeof(struct in6_addr)

#[inline] unsafe fn seglen(bp: *const u8) -> usize {
    // SAFETY: bp points at a valid ip6_rthdr0; ip6r0_len (byte 1) is 2*segments.
    unsafe { (*bp.add(1) as usize) / 2 }
}

// # C: socklen_t inet6_rth_space(int type, int segments)
#[no_mangle]
pub extern "C" fn inet6_rth_space(type_: i32, segments: i32) -> u32 {
    // # C: bytes needed for a Type-0 routing header with `segments` hops.
    if type_ != RTHDR_TYPE_0 || segments < 0 || segments > 127 { return 0; }
    (HDR + ADDR * segments as usize) as u32
}

// # C: void *inet6_rth_init(void *bp, socklen_t bp_len, int type, int segments)
#[no_mangle]
pub unsafe extern "C" fn inet6_rth_init(bp: *mut c_void, bp_len: u32, type_: i32, segments: i32) -> *mut c_void {
    // SAFETY: bp is writable for bp_len bytes; initialise the fixed header with
    // segleft=0 and len=2*segments, returning bp (NULL if it cannot hold it).
    unsafe {
        if type_ != RTHDR_TYPE_0 || segments < 0 || segments > 127 { return core::ptr::null_mut(); }
        let need = HDR + ADDR * segments as usize;
        if (bp_len as usize) < need || bp.is_null() { return core::ptr::null_mut(); }
        let p = bp as *mut u8;
        *p = 0;                       // ip6r0_nxt
        *p.add(1) = (2 * segments) as u8; // ip6r0_len
        *p.add(2) = 0;                // ip6r0_type
        *p.add(3) = 0;                // ip6r0_segleft
        for i in 4..8 { *p.add(i) = 0; } // reserved
        bp
    }
}

// # C: int inet6_rth_add(void *bp, const struct in6_addr *addr)
#[no_mangle]
pub unsafe extern "C" fn inet6_rth_add(bp: *mut c_void, addr: *const c_void) -> i32 {
    // SAFETY: bp is an initialised Type-0 header; addr points at 16 bytes.
    // Appends at slot segleft and increments it; -1 when full or wrong type.
    unsafe {
        let p = bp as *mut u8;
        if *p.add(2) != 0 { return -1; }
        let segleft = *p.add(3) as usize;
        if segleft + 1 > seglen(p) { return -1; }
        core::ptr::copy_nonoverlapping(addr as *const u8, p.add(HDR + ADDR * segleft), ADDR);
        *p.add(3) = (segleft + 1) as u8;
        0
    }
}

// # C: int inet6_rth_segments(const void *bp)
#[no_mangle]
pub unsafe extern "C" fn inet6_rth_segments(bp: *const c_void) -> i32 {
    // SAFETY: bp is a Type-0 header; segments = ip6r0_len / 2.
    unsafe {
        let p = bp as *const u8;
        if *p.add(2) != 0 { return -1; }
        seglen(p) as i32
    }
}

// # C: struct in6_addr *inet6_rth_getaddr(const void *bp, int index)
#[no_mangle]
pub unsafe extern "C" fn inet6_rth_getaddr(bp: *const c_void, index: i32) -> *mut c_void {
    // SAFETY: bp is a Type-0 header; returns &address[index] for index<segleft,
    // else NULL.
    unsafe {
        let p = bp as *const u8;
        if *p.add(2) != 0 || index < 0 || index >= *p.add(3) as i32 { return core::ptr::null_mut(); }
        p.add(HDR + ADDR * index as usize) as *mut c_void
    }
}

// # C: int inet6_rth_reverse(const void *in, void *out)
#[no_mangle]
pub unsafe extern "C" fn inet6_rth_reverse(input: *const c_void, output: *mut c_void) -> i32 {
    // SAFETY: in/out are Type-0 headers of the same segment count (may alias).
    // Reverses the address vector and sets segleft = segments.
    unsafe {
        let ip = input as *const u8;
        if *ip.add(2) != 0 { return -1; }
        let segs = seglen(ip);
        // stage source addresses to avoid aliasing when in == out
        let mut tmp = [0u8; 128 * ADDR];
        for i in 0..segs { core::ptr::copy_nonoverlapping(ip.add(HDR + ADDR * i), tmp.as_mut_ptr().add(ADDR * i), ADDR); }
        let op = output as *mut u8;
        *op = *ip;            // nxt
        *op.add(1) = *ip.add(1); // len
        *op.add(2) = 0;       // type
        *op.add(3) = segs as u8; // segleft = segments
        for i in 4..8 { *op.add(i) = 0; }
        for i in 0..segs { core::ptr::copy_nonoverlapping(tmp.as_ptr().add(ADDR * (segs - 1 - i)), op.add(HDR + ADDR * i), ADDR); }
        0
    }
}
