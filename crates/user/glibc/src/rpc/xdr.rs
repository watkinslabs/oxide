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


// Module manifest: scalar owns primitive filters; aggregate owns counted data; size owns positioning/sizing; compat owns SunRPC filters/stubs.
mod scalar;
mod aggregate;
mod size;
mod compat;
pub use aggregate::*;
pub use compat::*;
pub use scalar::*;
pub use size::*;
