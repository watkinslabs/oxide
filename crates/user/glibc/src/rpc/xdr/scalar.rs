use super::*;
pub unsafe extern "C" fn xdr_long(x: *mut XDR, lp: *mut i64) -> i32 {
    // SAFETY: 4-byte wire long; ENCODE writes, DECODE reads, FREE is a no-op.
    unsafe { match (*x).x_op { ENCODE => putlong(x, lp), DECODE => getlong(x, lp), _ => TRUE } }
}
// # C: bool_t xdr_u_long(XDR*, unsigned long*)
#[no_mangle]
pub unsafe extern "C" fn xdr_u_long(x: *mut XDR, ulp: *mut u64) -> i32 {
    // SAFETY: as xdr_long over an unsigned long.
    unsafe {
        match (*x).x_op {
            ENCODE => { let l = *ulp as i64; putlong(x, &l) }
            DECODE => { let mut l = 0i64; if getlong(x, &mut l) == 0 { return FALSE; } *ulp = l as u64; TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_int(XDR*, int*)
#[no_mangle]
pub unsafe extern "C" fn xdr_int(x: *mut XDR, ip: *mut i32) -> i32 {
    // SAFETY: int rides the 4-byte wire long.
    unsafe {
        match (*x).x_op {
            ENCODE => { let l = *ip as i64; putlong(x, &l) }
            DECODE => { let mut l = 0i64; if getlong(x, &mut l) == 0 { return FALSE; } *ip = l as i32; TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_u_int(XDR*, unsigned*)
#[no_mangle]
pub unsafe extern "C" fn xdr_u_int(x: *mut XDR, up: *mut u32) -> i32 {
    // SAFETY: unsigned int over the 4-byte wire long.
    unsafe {
        match (*x).x_op {
            ENCODE => { let l = *up as i64; putlong(x, &l) }
            DECODE => { let mut l = 0i64; if getlong(x, &mut l) == 0 { return FALSE; } *up = l as u32; TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_short(XDR*, short*)
#[no_mangle]
pub unsafe extern "C" fn xdr_short(x: *mut XDR, sp: *mut i16) -> i32 {
    // SAFETY: short padded to the 4-byte wire long.
    unsafe {
        let mut l = *sp as i64;
        match (*x).x_op { ENCODE => putlong(x, &l), DECODE => { if getlong(x, &mut l) == 0 { return FALSE; } *sp = l as i16; TRUE } _ => TRUE }
    }
}
// # C: bool_t xdr_u_short(XDR*, unsigned short*)
#[no_mangle]
pub unsafe extern "C" fn xdr_u_short(x: *mut XDR, usp: *mut u16) -> i32 {
    // SAFETY: unsigned short padded to the 4-byte wire long.
    unsafe {
        let mut l = *usp as i64;
        match (*x).x_op { ENCODE => putlong(x, &l), DECODE => { if getlong(x, &mut l) == 0 { return FALSE; } *usp = l as u16; TRUE } _ => TRUE }
    }
}
// # C: bool_t xdr_char(XDR*, char*)
#[no_mangle]
pub unsafe extern "C" fn xdr_char(x: *mut XDR, cp: *mut u8) -> i32 {
    // SAFETY: char rides an int on the wire.
    unsafe { let mut i = *cp as i32; if xdr_int(x, &mut i) == 0 { return FALSE; } *cp = i as u8; TRUE }
}
// # C: bool_t xdr_u_char(XDR*, unsigned char*)
#[no_mangle]
pub unsafe extern "C" fn xdr_u_char(x: *mut XDR, cp: *mut u8) -> i32 {
    // SAFETY: x live, cp writable; rides an unsigned int on the wire.
    unsafe { let mut i = *cp as u32; if xdr_u_int(x, &mut i) == 0 { return FALSE; } *cp = i as u8; TRUE }
}
// # C: bool_t xdr_bool(XDR*, bool_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_bool(x: *mut XDR, bp: *mut i32) -> i32 {
    // SAFETY: bool encoded as a 0/1 wire long.
    unsafe {
        match (*x).x_op {
            ENCODE => { let l = if *bp != 0 { 1i64 } else { 0 }; putlong(x, &l) }
            DECODE => { let mut l = 0i64; if getlong(x, &mut l) == 0 { return FALSE; } *bp = (l != 0) as i32; TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_enum(XDR*, enum_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_enum(x: *mut XDR, ep: *mut i32) -> i32 {
    // SAFETY: x live, ep writable; enum rides a 4-byte wire int.
    unsafe { xdr_int(x, ep) }
}
// # C: bool_t xdr_void(void)
#[no_mangle]
pub extern "C" fn xdr_void() -> i32 { TRUE }

// fixed-width
// # C: bool_t xdr_int32_t(XDR*, int32_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_int32_t(x: *mut XDR, ip: *mut i32) -> i32 {
    // SAFETY: 4-byte wire int via the int32 ops.
    unsafe { match (*x).x_op { ENCODE => ((*(*x).x_ops).putint32)(x, ip), DECODE => ((*(*x).x_ops).getint32)(x, ip), _ => TRUE } }
}
// # C: bool_t xdr_uint32_t(XDR*, uint32_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_uint32_t(x: *mut XDR, up: *mut u32) -> i32 {
    // SAFETY: x live, up writable; same wire bits as a signed int32.
    unsafe { xdr_int32_t(x, up as *mut i32) }
}
// # C: bool_t xdr_int8_t(XDR*, int8_t*) / uint8_t / int16_t / uint16_t
#[no_mangle]
pub unsafe extern "C" fn xdr_int8_t(x: *mut XDR, ip: *mut i8) -> i32 {
    // SAFETY: x live, ip writable; 8-bit value rides a wire int.
    unsafe { let mut i = *ip as i32; if xdr_int(x, &mut i) == 0 { return FALSE; } *ip = i as i8; TRUE }
}
#[no_mangle]
pub unsafe extern "C" fn xdr_uint8_t(x: *mut XDR, up: *mut u8) -> i32 {
    // SAFETY: 8-bit unsigned via a wire u_int.
    unsafe { let mut i = *up as u32; if xdr_u_int(x, &mut i) == 0 { return FALSE; } *up = i as u8; TRUE }
}
#[no_mangle]
pub unsafe extern "C" fn xdr_int16_t(x: *mut XDR, sp: *mut i16) -> i32 {
    // SAFETY: x live, sp writable; 16-bit value via xdr_short.
    unsafe { xdr_short(x, sp) }
}
#[no_mangle]
pub unsafe extern "C" fn xdr_uint16_t(x: *mut XDR, usp: *mut u16) -> i32 {
    // SAFETY: 16-bit unsigned via xdr_u_short.
    unsafe { xdr_u_short(x, usp) }
}

// 64-bit (hyper) — two wire longs, hi then lo.
// # C: bool_t xdr_hyper(XDR*, quad_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_hyper(x: *mut XDR, llp: *mut i64) -> i32 {
    // SAFETY: 8 bytes big-endian as two 4-byte wire longs (hi, lo).
    unsafe {
        match (*x).x_op {
            ENCODE => { let hi = (*llp >> 32) & 0xffff_ffff; let lo = *llp & 0xffff_ffff; if putlong(x, &hi) == 0 { return FALSE; } putlong(x, &lo) }
            DECODE => { let mut hi = 0i64; let mut lo = 0i64; if getlong(x, &mut hi) == 0 || getlong(x, &mut lo) == 0 { return FALSE; } *llp = (hi << 32) | (lo & 0xffff_ffff); TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_u_hyper(XDR*, u_quad_t*)
#[no_mangle]
pub unsafe extern "C" fn xdr_u_hyper(x: *mut XDR, ullp: *mut u64) -> i32 {
    // SAFETY: x live, ullp writable; unsigned 8-byte big-endian hyper.
    unsafe {
        match (*x).x_op {
            ENCODE => { let hi = ((*ullp >> 32) & 0xffff_ffff) as i64; let lo = (*ullp & 0xffff_ffff) as i64; if putlong(x, &hi) == 0 { return FALSE; } putlong(x, &lo) }
            DECODE => { let mut hi = 0i64; let mut lo = 0i64; if getlong(x, &mut hi) == 0 || getlong(x, &mut lo) == 0 { return FALSE; } *ullp = (((hi as u64) & 0xffff_ffff) << 32) | ((lo as u64) & 0xffff_ffff); TRUE }
            _ => TRUE,
        }
    }
}
// aliases of hyper (8-byte big-endian); same contract as xdr_hyper/xdr_u_hyper.
// # C: bool_t xdr_int64_t / xdr_longlong_t / xdr_quad_t (XDR*, *)
#[no_mangle] pub unsafe extern "C" fn xdr_int64_t(x: *mut XDR, p: *mut i64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable i64; == xdr_hyper.
    unsafe { xdr_hyper(x, p) }
}
#[no_mangle] pub unsafe extern "C" fn xdr_longlong_t(x: *mut XDR, p: *mut i64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable i64; == xdr_hyper.
    unsafe { xdr_hyper(x, p) }
}
#[no_mangle] pub unsafe extern "C" fn xdr_quad_t(x: *mut XDR, p: *mut i64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable i64; == xdr_hyper.
    unsafe { xdr_hyper(x, p) }
}
// # C: bool_t xdr_uint64_t / xdr_u_longlong_t / xdr_u_quad_t (XDR*, *)
#[no_mangle] pub unsafe extern "C" fn xdr_uint64_t(x: *mut XDR, p: *mut u64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable u64; == xdr_u_hyper.
    unsafe { xdr_u_hyper(x, p) }
}
#[no_mangle] pub unsafe extern "C" fn xdr_u_longlong_t(x: *mut XDR, p: *mut u64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable u64; == xdr_u_hyper.
    unsafe { xdr_u_hyper(x, p) }
}
#[no_mangle] pub unsafe extern "C" fn xdr_u_quad_t(x: *mut XDR, p: *mut u64) -> i32 {
    // SAFETY: x is a live XDR stream; p a writable/readable u64; == xdr_u_hyper.
    unsafe { xdr_u_hyper(x, p) }
}

// # C: bool_t xdr_float(XDR*, float*)
#[no_mangle]
pub unsafe extern "C" fn xdr_float(x: *mut XDR, fp: *mut f32) -> i32 {
    // SAFETY: x live, fp writable; IEEE-754 bits ride a wire int32.
    unsafe { let mut bits = (*fp).to_bits() as i32; if xdr_int32_t(x, &mut bits) == 0 { return FALSE; } *fp = f32::from_bits(bits as u32); TRUE }
}
// # C: bool_t xdr_double(XDR*, double*)
#[no_mangle]
pub unsafe extern "C" fn xdr_double(x: *mut XDR, dp: *mut f64) -> i32 {
    // SAFETY: IEEE double as two wire longs (hi, lo), big-endian.
    unsafe { let mut bits = (*dp).to_bits() as i64; if xdr_hyper(x, &mut bits) == 0 { return FALSE; } *dp = f64::from_bits(bits as u64); TRUE }
}

// --- aggregate primitives ---------------------------------------------------
