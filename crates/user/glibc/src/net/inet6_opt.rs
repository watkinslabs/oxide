// RFC3542 IPv6 Hop-by-Hop / Destination options builder + parser (docs/59§6
// G13): inet6_opt_init/append/finish/set_val + _next/_find/_get_val. The option
// area is a TLV stream after a 2-byte header (ext[0]=next-hdr left to the caller,
// ext[1]=hdr-ext-len in 8-octet units − 1). Pad1 = 0x00; PadN = {1, padlen−2,
// zeros}. Option data is aligned to `align` by padding before each option, and
// the whole header is padded to a multiple of 8 by finish. C ABI; null extbuf =
// length-computation pass.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

const PAD1: u8 = 0;
const PADN: u8 = 1;

// Write `pad` bytes of Pad1/PadN option padding at ext[at..at+pad].
unsafe fn write_pad(ext: *mut u8, at: usize, pad: usize) {
    // SAFETY: ext[at..at+pad] is within the validated extension buffer.
    unsafe {
        if pad == 0 { return; }
        if pad == 1 { *ext.add(at) = PAD1; return; }
        *ext.add(at) = PADN;
        *ext.add(at + 1) = (pad - 2) as u8;
        for i in 2..pad { *ext.add(at + i) = 0; }
    }
}

// # C: int inet6_opt_init(void *extbuf, socklen_t extlen)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_init(extbuf: *mut c_void, extlen: u32) -> i32 {
    // SAFETY: extbuf null (length pass) or writable for extlen bytes (a multiple
    // of 8). Sets ext[1] = extlen/8 − 1, leaving ext[0] for the caller.
    unsafe {
        if !extbuf.is_null() {
            if extlen == 0 || extlen % 8 != 0 { return -1; }
            *(extbuf as *mut u8).add(1) = (extlen / 8 - 1) as u8;
        }
        2
    }
}

// # C: int inet6_opt_append(void *extbuf, socklen_t extlen, int offset, uint8_t type, socklen_t len, uint8_t align, void **databufp)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_append(extbuf: *mut c_void, extlen: u32, offset: i32, type_: u8, len: u32, align: u8, databufp: *mut *mut c_void) -> i32 {
    // SAFETY: extbuf null (length pass) or writable; pads so the option data
    // lands on an `align` boundary, then writes {type, len} and hands back the
    // data pointer. Returns the new offset, −1 on bad align or overflow.
    unsafe {
        if align != 1 && align != 2 && align != 4 && align != 8 { return -1; }
        if align as u32 > len { return -1; }
        let pad = (align as u32 - ((offset as u32 + 2) % align as u32)) % align as u32;
        let newoff = offset + pad as i32 + 2 + len as i32;
        if !extbuf.is_null() {
            if newoff as u32 > extlen { return -1; }
            let ext = extbuf as *mut u8;
            write_pad(ext, offset as usize, pad as usize);
            let p = offset as usize + pad as usize;
            *ext.add(p) = type_;
            *ext.add(p + 1) = len as u8;
            if !databufp.is_null() { *databufp = ext.add(p + 2) as *mut c_void; }
        }
        newoff
    }
}

// # C: int inet6_opt_finish(void *extbuf, socklen_t extlen, int offset)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_finish(extbuf: *mut c_void, extlen: u32, offset: i32) -> i32 {
    // SAFETY: extbuf null (length pass) or writable; pads the option area out to
    // a multiple of 8 and records the final hdr-ext-len in ext[1].
    unsafe {
        let pad = (8 - (offset as u32 % 8)) % 8;
        let total = offset + pad as i32;
        if !extbuf.is_null() {
            if total as u32 > extlen { return -1; }
            let ext = extbuf as *mut u8;
            write_pad(ext, offset as usize, pad as usize);
            *ext.add(1) = (total / 8 - 1) as u8;
        }
        total
    }
}

// # C: int inet6_opt_set_val(void *databuf, int offset, void *val, socklen_t vallen)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_set_val(databuf: *mut c_void, offset: i32, val: *const c_void, vallen: u32) -> i32 {
    // SAFETY: databuf+offset writable for vallen bytes; val readable for vallen.
    unsafe {
        core::ptr::copy_nonoverlapping(val as *const u8, (databuf as *mut u8).add(offset as usize), vallen as usize);
        offset + vallen as i32
    }
}

// # C: int inet6_opt_get_val(void *databuf, int offset, void *val, socklen_t vallen)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_get_val(databuf: *mut c_void, offset: i32, val: *mut c_void, vallen: u32) -> i32 {
    // SAFETY: databuf+offset readable for vallen bytes; val writable for vallen.
    unsafe {
        core::ptr::copy_nonoverlapping((databuf as *const u8).add(offset as usize), val as *mut u8, vallen as usize);
        offset + vallen as i32
    }
}

// # C: int inet6_opt_next(void *extbuf, socklen_t extlen, int offset, uint8_t *typep, socklen_t *lenp, void **databufp)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_next(extbuf: *mut c_void, extlen: u32, offset: i32, typep: *mut u8, lenp: *mut u32, databufp: *mut *mut c_void) -> i32 {
    // SAFETY: extbuf readable for extlen bytes; out-params writable. Skips
    // Pad1/PadN, returns the resume offset (offset==0 ⇒ start past the 2-byte
    // header), or −1 at the end.
    unsafe {
        let ext = extbuf as *mut u8;
        let mut o = if offset == 0 { 2 } else { offset as usize };
        let bound = extlen as usize;
        while o < bound {
            let t = *ext.add(o);
            if t == PAD1 { o += 1; continue; }
            if o + 1 >= bound { break; }
            let olen = *ext.add(o + 1) as usize;
            if t == PADN { o += 2 + olen; continue; }
            *typep = t; *lenp = olen as u32; *databufp = ext.add(o + 2) as *mut c_void;
            return (o + 2 + olen) as i32;
        }
        -1
    }
}

// # C: int inet6_opt_find(void *extbuf, socklen_t extlen, int offset, uint8_t type, socklen_t *lenp, void **databufp)
#[no_mangle]
pub unsafe extern "C" fn inet6_opt_find(extbuf: *mut c_void, extlen: u32, offset: i32, type_: u8, lenp: *mut u32, databufp: *mut *mut c_void) -> i32 {
    // SAFETY: extbuf readable for extlen bytes; out-params writable. Scans for an
    // option of `type`, skipping all others by their length; −1 if not found.
    unsafe {
        let ext = extbuf as *mut u8;
        let mut o = if offset == 0 { 2 } else { offset as usize };
        let bound = extlen as usize;
        while o < bound {
            let t = *ext.add(o);
            if t == PAD1 { o += 1; continue; }
            if o + 1 >= bound { break; }
            let olen = *ext.add(o + 1) as usize;
            if t == type_ { *lenp = olen as u32; *databufp = ext.add(o + 2) as *mut c_void; return (o + 2 + olen) as i32; }
            o += 2 + olen;
        }
        -1
    }
}
