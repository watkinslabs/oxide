// XDR — External Data Representation (docs/59§6 §9.1, RFC 4506). The Sun RPC
// serialization layer: a memory stream (xdrmem) + the scalar/aggregate filter
// primitives. Wire format is big-endian, 4-byte aligned. struct XDR is 48 bytes
// (x_op + vtable + 3 ptrs + x_handy); the vtable is 10 fn pointers. ENCODE=0,
// DECODE=1, FREE=2; bool_t TRUE=1/FALSE=0.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

const ENCODE: i32 = 0;
const DECODE: i32 = 1;
const FREE: i32 = 2;
const TRUE: i32 = 1;
const FALSE: i32 = 0;

#[repr(C)]
pub struct XdrOps {
    getlong: unsafe extern "C" fn(*mut XDR, *mut i64) -> i32,
    putlong: unsafe extern "C" fn(*mut XDR, *const i64) -> i32,
    getbytes: unsafe extern "C" fn(*mut XDR, *mut u8, u32) -> i32,
    putbytes: unsafe extern "C" fn(*mut XDR, *const u8, u32) -> i32,
    getpostn: unsafe extern "C" fn(*const XDR) -> u32,
    setpostn: unsafe extern "C" fn(*mut XDR, u32) -> i32,
    inline_: unsafe extern "C" fn(*mut XDR, u32) -> *mut i32,
    destroy: unsafe extern "C" fn(*mut XDR),
    getint32: unsafe extern "C" fn(*mut XDR, *mut i32) -> i32,
    putint32: unsafe extern "C" fn(*mut XDR, *const i32) -> i32,
}
#[repr(C)]
pub struct XDR {
    x_op: i32,
    _pad: i32,
    x_ops: *const XdrOps,
    x_public: *mut c_void,
    x_private: *mut u8, // current position
    x_base: *mut u8,    // buffer start
    x_handy: u32,       // bytes remaining
    _pad2: u32,
}
const _: () = assert!(core::mem::size_of::<XDR>() == 48);

// --- xdrmem stream ops ------------------------------------------------------
unsafe extern "C" fn mem_getlong(x: *mut XDR, lp: *mut i64) -> i32 {
    // SAFETY: x is a live xdrmem stream; read 4 big-endian bytes (sign-extended).
    unsafe {
        let x = &mut *x;
        if x.x_handy < 4 { return FALSE; }
        let p = x.x_private;
        *lp = i32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) as i64;
        x.x_private = x.x_private.add(4); x.x_handy -= 4; TRUE
    }
}
unsafe extern "C" fn mem_putlong(x: *mut XDR, lp: *const i64) -> i32 {
    // SAFETY: write the low 32 bits of *lp big-endian into the stream.
    unsafe {
        let x = &mut *x;
        if x.x_handy < 4 { return FALSE; }
        let b = (*lp as i32).to_be_bytes();
        core::ptr::copy_nonoverlapping(b.as_ptr(), x.x_private, 4);
        x.x_private = x.x_private.add(4); x.x_handy -= 4; TRUE
    }
}
unsafe extern "C" fn mem_getbytes(x: *mut XDR, addr: *mut u8, len: u32) -> i32 {
    // SAFETY: copy len bytes out of the stream if available.
    unsafe {
        let x = &mut *x;
        if x.x_handy < len { return FALSE; }
        core::ptr::copy_nonoverlapping(x.x_private, addr, len as usize);
        x.x_private = x.x_private.add(len as usize); x.x_handy -= len; TRUE
    }
}
unsafe extern "C" fn mem_putbytes(x: *mut XDR, addr: *const u8, len: u32) -> i32 {
    // SAFETY: copy len bytes into the stream if room remains.
    unsafe {
        let x = &mut *x;
        if x.x_handy < len { return FALSE; }
        core::ptr::copy_nonoverlapping(addr, x.x_private, len as usize);
        x.x_private = x.x_private.add(len as usize); x.x_handy -= len; TRUE
    }
}
unsafe extern "C" fn mem_getpostn(x: *const XDR) -> u32 {
    // SAFETY: x is a live stream; position = current pointer minus base.
    unsafe { (*x).x_private as usize as u32 - (*x).x_base as usize as u32 }
}
unsafe extern "C" fn mem_setpostn(x: *mut XDR, pos: u32) -> i32 {
    // SAFETY: move to base+pos if within the stream, adjusting x_handy.
    unsafe {
        let x = &mut *x;
        let newaddr = x.x_base.add(pos as usize);
        let lastaddr = x.x_private.add(x.x_handy as usize);
        if newaddr as usize > lastaddr as usize { return FALSE; }
        x.x_private = newaddr; x.x_handy = (lastaddr as usize - newaddr as usize) as u32; TRUE
    }
}
unsafe extern "C" fn mem_inline(x: *mut XDR, len: u32) -> *mut i32 {
    // SAFETY: hand back a pointer to len bytes in-place if available (fast path).
    unsafe {
        let x = &mut *x;
        if x.x_handy < len { return core::ptr::null_mut(); }
        let p = x.x_private; x.x_private = x.x_private.add(len as usize); x.x_handy -= len; p as *mut i32
    }
}
unsafe extern "C" fn mem_destroy(_x: *mut XDR) {}
unsafe extern "C" fn mem_getint32(x: *mut XDR, ip: *mut i32) -> i32 {
    // SAFETY: read a 4-byte big-endian int32.
    unsafe {
        let x = &mut *x;
        if x.x_handy < 4 { return FALSE; }
        let p = x.x_private;
        *ip = i32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
        x.x_private = x.x_private.add(4); x.x_handy -= 4; TRUE
    }
}
unsafe extern "C" fn mem_putint32(x: *mut XDR, ip: *const i32) -> i32 {
    // SAFETY: write a 4-byte big-endian int32.
    unsafe {
        let x = &mut *x;
        if x.x_handy < 4 { return FALSE; }
        let b = (*ip).to_be_bytes();
        core::ptr::copy_nonoverlapping(b.as_ptr(), x.x_private, 4);
        x.x_private = x.x_private.add(4); x.x_handy -= 4; TRUE
    }
}
static XDRMEM_OPS: XdrOps = XdrOps {
    getlong: mem_getlong, putlong: mem_putlong, getbytes: mem_getbytes, putbytes: mem_putbytes,
    getpostn: mem_getpostn, setpostn: mem_setpostn, inline_: mem_inline, destroy: mem_destroy,
    getint32: mem_getint32, putint32: mem_putint32,
};

// # C: void xdrmem_create(XDR*, char *addr, unsigned size, enum xdr_op op)
#[no_mangle]
pub unsafe extern "C" fn xdrmem_create(xdrs: *mut XDR, addr: *mut u8, size: u32, op: i32) {
    // SAFETY: initialize a memory XDR stream over addr[0..size].
    unsafe {
        let x = &mut *xdrs;
        x.x_op = op; x.x_ops = &XDRMEM_OPS; x.x_public = core::ptr::null_mut();
        x.x_private = addr; x.x_base = addr; x.x_handy = size;
    }
}

// vtable-call helpers
unsafe fn getlong(x: *mut XDR, lp: *mut i64) -> i32 { unsafe { ((*(*x).x_ops).getlong)(x, lp) } }
unsafe fn putlong(x: *mut XDR, lp: *const i64) -> i32 { unsafe { ((*(*x).x_ops).putlong)(x, lp) } }
unsafe fn getbytes(x: *mut XDR, a: *mut u8, n: u32) -> i32 { unsafe { ((*(*x).x_ops).getbytes)(x, a, n) } }
unsafe fn putbytes(x: *mut XDR, a: *const u8, n: u32) -> i32 { unsafe { ((*(*x).x_ops).putbytes)(x, a, n) } }

// --- scalar primitives ------------------------------------------------------
// # C: bool_t xdr_long(XDR*, long*)
#[no_mangle]
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
// # C: bool_t xdr_opaque(XDR*, caddr_t, unsigned cnt) — fixed-length, 4-byte pad.
#[no_mangle]
pub unsafe extern "C" fn xdr_opaque(x: *mut XDR, cp: *mut u8, cnt: u32) -> i32 {
    // SAFETY: cnt bytes + (4 - cnt%4)%4 zero padding bytes.
    unsafe {
        if cnt == 0 { return TRUE; }
        let rnd = (4 - (cnt & 3)) & 3;
        let zeros = [0u8; 4];
        match (*x).x_op {
            ENCODE => { if putbytes(x, cp, cnt) == 0 { return FALSE; } if rnd > 0 { return putbytes(x, zeros.as_ptr(), rnd); } TRUE }
            DECODE => { if getbytes(x, cp, cnt) == 0 { return FALSE; } if rnd > 0 { let mut crud = [0u8; 4]; return getbytes(x, crud.as_mut_ptr(), rnd); } TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_bytes(XDR*, char**, unsigned*, unsigned maxsize)
#[no_mangle]
pub unsafe extern "C" fn xdr_bytes(x: *mut XDR, cpp: *mut *mut u8, sizep: *mut u32, maxsize: u32) -> i32 {
    // SAFETY: length-prefixed counted bytes; DECODE mallocs *cpp if null, FREE frees it.
    unsafe {
        if xdr_u_int(x, sizep) == 0 { return FALSE; }
        let n = *sizep;
        if n > maxsize { return FALSE; }
        match (*x).x_op {
            DECODE => {
                if n == 0 { return TRUE; }
                if (*cpp).is_null() { *cpp = crate::malloc::heap::malloc(n as usize); if (*cpp).is_null() { return FALSE; } }
                xdr_opaque(x, *cpp, n)
            }
            ENCODE => { if n == 0 { return TRUE; } xdr_opaque(x, *cpp, n) }
            _ => { if !(*cpp).is_null() { crate::malloc::heap::free(*cpp); *cpp = core::ptr::null_mut(); } TRUE }
        }
    }
}
// # C: bool_t xdr_string(XDR*, char**, unsigned maxsize)
#[no_mangle]
pub unsafe extern "C" fn xdr_string(x: *mut XDR, cpp: *mut *mut u8, maxsize: u32) -> i32 {
    // SAFETY: length-prefixed NUL-terminated string; DECODE allocs size+1.
    unsafe {
        let op = (*x).x_op;
        if op == FREE { if !(*cpp).is_null() { crate::malloc::heap::free(*cpp); *cpp = core::ptr::null_mut(); } return TRUE; }
        let mut size: u32 = if op == ENCODE { crate::string::len::strlen_impl(*cpp) as u32 } else { 0 };
        if xdr_u_int(x, &mut size) == 0 { return FALSE; }
        if size > maxsize { return FALSE; }
        match op {
            ENCODE => xdr_opaque(x, *cpp, size),
            DECODE => {
                if (*cpp).is_null() { *cpp = crate::malloc::heap::malloc(size as usize + 1); if (*cpp).is_null() { return FALSE; } }
                if xdr_opaque(x, *cpp, size) == 0 { return FALSE; }
                *(*cpp).add(size as usize) = 0; TRUE
            }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_wrapstring(XDR*, char**)
#[no_mangle]
pub unsafe extern "C" fn xdr_wrapstring(x: *mut XDR, cpp: *mut *mut u8) -> i32 {
    // SAFETY: xdr_string with the maximum length bound.
    unsafe { xdr_string(x, cpp, u32::MAX) }
}
// # C: bool_t xdr_netobj(XDR*, struct netobj*)  {u_int n_len; char* n_bytes;}
#[repr(C)]
pub struct netobj { pub n_len: u32, _pad: u32, pub n_bytes: *mut u8 }
#[no_mangle]
pub unsafe extern "C" fn xdr_netobj(x: *mut XDR, np: *mut netobj) -> i32 {
    // SAFETY: a counted byte string (max 1024) via xdr_bytes.
    unsafe { xdr_bytes(x, &mut (*np).n_bytes, &mut (*np).n_len, 1024) }
}

// # C: void xdr_free(xdrproc_t proc, char *objp)
#[no_mangle]
pub unsafe extern "C" fn xdr_free(proc: unsafe extern "C" fn(*mut XDR, *mut c_void) -> i32, objp: *mut c_void) {
    // SAFETY: run `proc` with a FREE-op XDR so it releases any owned allocations.
    unsafe {
        let mut x: XDR = core::mem::zeroed();
        x.x_op = FREE;
        proc(&mut x, objp);
    }
}

type XdrProc = unsafe extern "C" fn(*mut XDR, *mut c_void) -> i32;

// # C: bool_t xdr_vector(XDR*, char *basep, unsigned nelem, unsigned elemsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_vector(x: *mut XDR, basep: *mut u8, nelem: u32, elemsize: u32, elproc: XdrProc) -> i32 {
    // SAFETY: basep is an nelem*elemsize array; run elproc on each element.
    unsafe {
        for i in 0..nelem as usize {
            if elproc(x, basep.add(i * elemsize as usize) as *mut c_void) == 0 { return FALSE; }
        }
        TRUE
    }
}
// # C: bool_t xdr_array(XDR*, char**, unsigned*, unsigned maxsize, unsigned elemsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_array(x: *mut XDR, addrp: *mut *mut u8, sizep: *mut u32, maxsize: u32, elemsize: u32, elproc: XdrProc) -> i32 {
    // SAFETY: length-prefixed counted array; DECODE allocs the element block,
    // FREE runs elproc(FREE) on each element then frees the block.
    unsafe {
        if xdr_u_int(x, sizep) == 0 { return FALSE; }
        let n = *sizep;
        if n > maxsize { return FALSE; }
        let op = (*x).x_op;
        if op == DECODE && n != 0 && (*addrp).is_null() {
            *addrp = crate::malloc::heap::malloc(n as usize * elemsize as usize);
            if (*addrp).is_null() { return FALSE; }
            core::ptr::write_bytes(*addrp, 0, n as usize * elemsize as usize);
        }
        let r = if n != 0 { xdr_vector(x, *addrp, n, elemsize, elproc) } else { TRUE };
        if op == FREE && !(*addrp).is_null() { crate::malloc::heap::free(*addrp); *addrp = core::ptr::null_mut(); }
        r
    }
}
// # C: bool_t xdr_reference(XDR*, char**, unsigned size, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_reference(x: *mut XDR, pp: *mut *mut u8, size: u32, proc: XdrProc) -> i32 {
    // SAFETY: a non-optional pointer to one object; DECODE allocs it, FREE frees it.
    unsafe {
        let op = (*x).x_op;
        if op == DECODE && (*pp).is_null() {
            *pp = crate::malloc::heap::malloc(size as usize);
            if (*pp).is_null() { return FALSE; }
            core::ptr::write_bytes(*pp, 0, size as usize);
        }
        if (*pp).is_null() { return TRUE; }
        let r = proc(x, *pp as *mut c_void);
        if op == FREE { crate::malloc::heap::free(*pp); *pp = core::ptr::null_mut(); }
        r
    }
}
// # C: bool_t xdr_pointer(XDR*, char**, unsigned objsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_pointer(x: *mut XDR, objpp: *mut *mut u8, objsize: u32, proc: XdrProc) -> i32 {
    // SAFETY: an optional pointer — a leading bool says whether the object is
    // present, then xdr_reference handles it.
    unsafe {
        let mut more = (!(*objpp).is_null()) as i32;
        if xdr_bool(x, &mut more) == 0 { return FALSE; }
        if more == 0 { *objpp = core::ptr::null_mut(); return TRUE; }
        xdr_reference(x, objpp, objsize, proc)
    }
}

// Sizing stream: counts bytes (in x_handy) instead of touching memory.
unsafe extern "C" fn size_putlong(x: *mut XDR, _: *const i64) -> i32 {
    // SAFETY: x is the live sizing stream; a wire long counts as 4 bytes.
    unsafe { (*x).x_handy += 4; TRUE }
}
unsafe extern "C" fn size_putint32(x: *mut XDR, _: *const i32) -> i32 {
    // SAFETY: x is the live sizing stream; a wire int32 counts as 4 bytes.
    unsafe { (*x).x_handy += 4; TRUE }
}
unsafe extern "C" fn size_putbytes(x: *mut XDR, _: *const u8, n: u32) -> i32 {
    // SAFETY: x is the live sizing stream; n raw bytes add n to the count.
    unsafe { (*x).x_handy += n; TRUE }
}
unsafe extern "C" fn size_getlong(_: *mut XDR, _: *mut i64) -> i32 { FALSE }
unsafe extern "C" fn size_getbytes(_: *mut XDR, _: *mut u8, _: u32) -> i32 { FALSE }
unsafe extern "C" fn size_getpostn(x: *const XDR) -> u32 {
    // SAFETY: x is the live sizing stream; x_handy holds the accumulated count.
    unsafe { (*x).x_handy }
}
unsafe extern "C" fn size_setpostn(_: *mut XDR, _: u32) -> i32 { FALSE }
unsafe extern "C" fn size_inline(_: *mut XDR, _: u32) -> *mut i32 { core::ptr::null_mut() }
unsafe extern "C" fn size_getint32(_: *mut XDR, _: *mut i32) -> i32 { FALSE }
static SIZE_OPS: XdrOps = XdrOps {
    getlong: size_getlong, putlong: size_putlong, getbytes: size_getbytes, putbytes: size_putbytes,
    getpostn: size_getpostn, setpostn: size_setpostn, inline_: size_inline, destroy: mem_destroy,
    getint32: size_getint32, putint32: size_putint32,
};
// # C: unsigned long xdr_sizeof(xdrproc_t func, void *data)
#[no_mangle]
pub unsafe extern "C" fn xdr_sizeof(func: XdrProc, data: *mut c_void) -> u64 {
    // SAFETY: run func against a counting stream (ENCODE op) and read the byte
    // total accumulated in x_handy.
    unsafe {
        let mut x: XDR = core::mem::zeroed();
        x.x_ops = &SIZE_OPS; x.x_op = ENCODE; x.x_handy = 0;
        func(&mut x, data);
        x.x_handy as u64
    }
}

// # C: unsigned int xdr_getpos(const XDR*) / bool_t xdr_setpos(XDR*, unsigned)
#[no_mangle]
pub unsafe extern "C" fn xdr_getpos(x: *const XDR) -> u32 {
    // SAFETY: dispatch to the stream's getpostn op.
    unsafe { ((*(*x).x_ops).getpostn)(x) }
}
#[no_mangle]
pub unsafe extern "C" fn xdr_setpos(x: *mut XDR, pos: u32) -> i32 {
    // SAFETY: dispatch to the stream's setpostn op.
    unsafe { ((*(*x).x_ops).setpostn)(x, pos) }
}
