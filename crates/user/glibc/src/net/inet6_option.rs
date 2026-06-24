// RFC2292 obsolete IPv6 option builder/parser (docs/59§6 G13). glibc wraps a
// full extension header in cmsghdr data: byte 0 is caller-owned next-header,
// byte 1 is hdr-ext-len, options start at CMSG_DATA+2. The API has no buffer
// length argument; it only advances cmsg_len like glibc.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

const IPPROTO_IPV6: i32 = 41;
const IPV6_HOPOPTS: i32 = 54;
const IPV6_DSTOPTS: i32 = 59;
const CMSGHDR_LEN: usize = 16;
const PAD1: u8 = 0;
const PADN: u8 = 1;

#[repr(C)]
pub struct Cmsghdr {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}

fn align8(n: usize) -> usize { (n + 7) & !7 }
fn cmsg_data(c: *mut Cmsghdr) -> *mut u8 { (c as *mut u8).wrapping_add(CMSGHDR_LEN) }
fn ext_len(c: *const Cmsghdr) -> usize {
    // SAFETY: caller supplies a cmsghdr pointer from the RFC2292 API surface.
    let len = unsafe { (*c).cmsg_len };
    len.saturating_sub(CMSGHDR_LEN)
}

unsafe fn set_len(c: *mut Cmsghdr, ext: usize) {
    // SAFETY: c points to a writable cmsghdr; data byte 1 is the IPv6 hdr-ext-len.
    unsafe {
        (*c).cmsg_len = CMSGHDR_LEN + ext;
        *cmsg_data(c).add(1) = (ext / 8).saturating_sub(1) as u8;
    }
}

unsafe fn write_pad(base: *mut u8, at: usize, pad: usize) {
    // SAFETY: caller reserved base[at..at+pad] inside the cmsghdr payload.
    unsafe {
        if pad == 0 { return; }
        if pad == 1 { *base.add(at) = PAD1; return; }
        *base.add(at) = PADN;
        *base.add(at + 1) = (pad - 2) as u8;
        for i in 2..pad { *base.add(at + i) = 0; }
    }
}

fn padding_for(cur: usize, multx: i32, plusy: i32) -> Option<usize> {
    if multx <= 0 || plusy < 0 { return None; }
    let m = multx as usize;
    let want = plusy as usize % m;
    let pad = (want + m - (cur % m)) % m;
    Some(if pad == 0 { m.max(plusy as usize) } else { pad })
}

unsafe fn reserve(c: *mut Cmsghdr, opt_len: usize, multx: i32, plusy: i32) -> Option<*mut u8> {
    let cur = ext_len(c).max(2);
    let pad = padding_for(cur, multx, plusy)?;
    let start = cur.checked_add(pad)?;
    let end = start.checked_add(opt_len)?;
    let final_len = align8(end);
    let base = cmsg_data(c);
    // SAFETY: old RFC2292 API has no capacity parameter; caller allocated enough
    // bytes via inet6_option_space. Writes mirror glibc's cmsg_len-only contract.
    unsafe {
        write_pad(base, cur, pad);
        write_pad(base, end, final_len - end);
        set_len(c, final_len);
        Some(base.add(start))
    }
}

// # C: int inet6_option_space(int nbytes)
#[no_mangle]
pub extern "C" fn inet6_option_space(nbytes: i32) -> i32 {
    if nbytes < 0 { return 0; }
    (CMSGHDR_LEN + align8(nbytes as usize + 2)) as i32
}

// # C: int inet6_option_init(void *bp, struct cmsghdr **cmsgp, int type)
#[no_mangle]
pub unsafe extern "C" fn inet6_option_init(bp: *mut c_void, cmsgp: *mut *mut Cmsghdr, type_: i32) -> i32 {
    // SAFETY: bp points to caller storage for a cmsghdr; cmsgp is writable.
    unsafe {
        if bp.is_null() || cmsgp.is_null() { return -1; }
        if type_ != IPV6_HOPOPTS && type_ != IPV6_DSTOPTS { return -1; }
        let c = bp as *mut Cmsghdr;
        (*c).cmsg_len = CMSGHDR_LEN;
        (*c).cmsg_level = IPPROTO_IPV6;
        (*c).cmsg_type = type_;
        *cmsgp = c;
        0
    }
}

// # C: int inet6_option_append(struct cmsghdr *cmsg, const uint8_t *typep, int multx, int plusy)
#[no_mangle]
pub unsafe extern "C" fn inet6_option_append(cmsg: *mut Cmsghdr, typep: *const u8, multx: i32, plusy: i32) -> i32 {
    // SAFETY: typep points at an RFC2292 option {type,len,data...}; cmsg writable.
    unsafe {
        if cmsg.is_null() || typep.is_null() { return -1; }
        let opt_len = (*typep.add(1) as usize).saturating_add(2);
        let dst = match reserve(cmsg, opt_len, multx, plusy) { Some(p) => p, None => return -1 };
        core::ptr::copy_nonoverlapping(typep, dst, opt_len);
        0
    }
}

// # C: uint8_t *inet6_option_alloc(struct cmsghdr *cmsg, int datalen, int multx, int plusy)
#[no_mangle]
pub unsafe extern "C" fn inet6_option_alloc(cmsg: *mut Cmsghdr, datalen: i32, multx: i32, plusy: i32) -> *mut u8 {
    if cmsg.is_null() || datalen < 0 { return core::ptr::null_mut(); }
    // SAFETY: cmsg is caller-owned; reserve returns the option start where the
    // caller writes {type,len,data...}.
    unsafe { reserve(cmsg, datalen as usize + 2, multx, plusy).unwrap_or(core::ptr::null_mut()) }
}

unsafe fn next_from(cmsg: *const Cmsghdr, tptrp: *mut *mut u8) -> Option<*mut u8> {
    // SAFETY: cmsg/tptrp are valid; caller scans within cmsg_len.
    unsafe {
        let base = cmsg_data(cmsg as *mut Cmsghdr);
        let bound = ext_len(cmsg);
        let cur = *tptrp;
        let off = if cur.is_null() {
            2
        } else if *cur == PAD1 {
            cur.offset_from(base) as usize + 1
        } else {
            cur.offset_from(base) as usize + (*cur.add(1) as usize) + 2
        };
        if off >= bound { return None; }
        let t = *base.add(off);
        if t == PAD1 {
            *tptrp = base.add(off);
            return Some(base.add(off));
        }
        if off + 1 >= bound { return None; }
        *tptrp = base.add(off);
        Some(base.add(off))
    }
}

// # C: int inet6_option_next(const struct cmsghdr *cmsg, uint8_t **tptrp)
#[no_mangle]
pub unsafe extern "C" fn inet6_option_next(cmsg: *const Cmsghdr, tptrp: *mut *mut u8) -> i32 {
    if cmsg.is_null() || tptrp.is_null() { return -1; }
    // SAFETY: next_from validates bounds against cmsg_len.
    unsafe { if next_from(cmsg, tptrp).is_some() { 0 } else { -1 } }
}

// # C: int inet6_option_find(const struct cmsghdr *cmsg, uint8_t **tptrp, int type)
#[no_mangle]
pub unsafe extern "C" fn inet6_option_find(cmsg: *const Cmsghdr, tptrp: *mut *mut u8, type_: i32) -> i32 {
    if cmsg.is_null() || tptrp.is_null() { return -1; }
    // SAFETY: next_from walks within cmsg_len; found pointer is returned as glibc does.
    unsafe {
        while let Some(p) = next_from(cmsg, tptrp) {
            if *p == type_ as u8 { return 0; }
        }
        *tptrp = core::ptr::null_mut();
        -1
    }
}
