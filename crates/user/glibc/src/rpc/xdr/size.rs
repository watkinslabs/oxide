use super::*;
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

// --- SunRPC compatibility filters ------------------------------------------
// These structs mirror the historical tirpc/glibc LP64 layouts closely enough
// for the compat-only XDR entry points below. The record/stdio stream backends
