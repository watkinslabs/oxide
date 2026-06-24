//! Obsolete libm compatibility entry points.
#![cfg(feature = "freestanding")]

use core::ffi::c_char;

#[repr(C)]
pub struct exception {
    pub type_: i32,
    pub name: *mut c_char,
    pub arg1: f64,
    pub arg2: f64,
    pub retval: f64,
    pub err: i32,
}

// # C: int matherr(struct exception *exc)
#[no_mangle]
pub unsafe extern "C" fn matherr(_exc: *mut exception) -> i32 {
    0
}
