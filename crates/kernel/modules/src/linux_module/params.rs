use core::ffi::c_char;

use super::{param_arg, parse_bool, parse_i64, parse_u64, write_bytes, write_i64, write_u64, KernelParam, LINUX_EINVAL};

pub(super) unsafe extern "C" fn param_set_bool(val: *const c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<bool>(kp) else { return -LINUX_EINVAL; };
    let Some(v) = parse_bool(val) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    unsafe { *arg = v; }
    0
}

pub(super) unsafe extern "C" fn param_get_bool(buf: *mut c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<bool>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    let v = unsafe { *arg };
    write_bytes(buf, if v { b"Y\n" } else { b"N\n" })
}

pub(super) unsafe extern "C" fn param_set_int(val: *const c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<i32>(kp) else { return -LINUX_EINVAL; };
    let Some(v) = parse_i64(val) else { return -LINUX_EINVAL; };
    if v < i32::MIN as i64 || v > i32::MAX as i64 { return -LINUX_EINVAL; }
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    unsafe { *arg = v as i32; }
    0
}

pub(super) unsafe extern "C" fn param_get_int(buf: *mut c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<i32>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    let v = unsafe { *arg };
    write_i64(buf, v as i64)
}

pub(super) unsafe extern "C" fn param_set_uint(val: *const c_char, kp: *const KernelParam) -> i32 {
    let Some(v) = parse_uint(val) else { return -LINUX_EINVAL; };
    let Some(arg) = param_arg::<u32>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    unsafe { *arg = v; }
    0
}

pub(super) unsafe extern "C" fn param_set_uint_minmax(val: *const c_char, kp: *const KernelParam, min: u32, max: u32) -> i32 {
    let Some(v) = parse_uint(val) else { return -LINUX_EINVAL; };
    if v < min || v > max { return -LINUX_EINVAL; }
    let Some(arg) = param_arg::<u32>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: range validation succeeded before this single typed backing-store mutation.
    unsafe { *arg = v; }
    0
}

pub(super) unsafe extern "C" fn param_get_uint(buf: *mut c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<u32>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    let v = unsafe { *arg };
    write_u64(buf, v as u64)
}

pub(super) unsafe extern "C" fn param_set_ulong(val: *const c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<usize>(kp) else { return -LINUX_EINVAL; };
    let Some(v) = parse_u64(val) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    unsafe { *arg = v as usize; }
    0
}

pub(super) unsafe extern "C" fn param_get_ulong(buf: *mut c_char, kp: *const KernelParam) -> i32 {
    let Some(arg) = param_arg::<usize>(kp) else { return -LINUX_EINVAL; };
    // SAFETY: param_arg checked kp and returned the typed backing storage.
    let v = unsafe { *arg };
    write_u64(buf, v as u64)
}

fn parse_uint(val: *const c_char) -> Option<u32> {
    let v = parse_u64(val)?;
    (v <= u32::MAX as u64).then_some(v as u32)
}
