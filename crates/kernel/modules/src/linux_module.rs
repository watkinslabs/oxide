// Linux module owner/refcount and parameter compatibility exports.
// Module manifest: params owns scalar module parameter parsing and rendering.

mod params;

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

const MODULE_STATE_LIVE: usize = 0;
const MODULE_STATE_COMING: usize = 1;
const MODULE_STATE_GOING: usize = 2;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const PARAM_SCAN_LIMIT: usize = 4096;

#[repr(C)]
pub(crate) struct LinuxModule {
    name:   *const c_char,
    state:  usize,
    refcnt: u32,
}

#[repr(C)]
pub(super) struct KernelParamOps {
    flags: u32,
    set:   Option<unsafe extern "C" fn(*const c_char, *const KernelParam) -> i32>,
    get:   Option<unsafe extern "C" fn(*mut c_char, *const KernelParam) -> i32>,
    free:  Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub(super) struct KernelParam {
    name:  *const c_char,
    mod_:  *mut LinuxModule,
    ops:   *const KernelParamOps,
    perm:  u16,
    level: i8,
    flags: u8,
    arg:   *mut c_void,
}

#[repr(C)]
struct KParamArray {
    max:      u32,
    elemsize: u32,
    num:      *mut u32,
    ops:      *const KernelParamOps,
    elem:     *mut c_void,
}

#[unsafe(no_mangle)]
static param_ops_byte: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_set_byte),
    get:   Some(param_get_byte),
    free:  None,
};

#[unsafe(no_mangle)]
static param_ops_bool: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_set_bool),
    get:   Some(param_get_bool),
    free:  None,
};

#[unsafe(no_mangle)]
static param_ops_int: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_set_int),
    get:   Some(param_get_int),
    free:  None,
};

#[unsafe(no_mangle)]
static param_ops_uint: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_set_uint),
    get:   Some(param_get_uint),
    free:  None,
};

#[unsafe(no_mangle)]
static param_ops_ulong: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_set_ulong),
    get:   Some(param_get_ulong),
    free:  None,
};

#[unsafe(no_mangle)]
static param_array_ops: KernelParamOps = KernelParamOps {
    flags: 0,
    set:   Some(param_array_set),
    get:   Some(param_array_get),
    free:  None,
};

/// Register Linux module lifecycle KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("try_module_get", try_module_get as *const () as usize),
        ("module_put",     module_put     as *const () as usize),
        ("param_set_byte",  param_set_byte  as *const () as usize),
        ("param_get_byte",  param_get_byte  as *const () as usize),
        ("param_set_bool",  param_set_bool  as *const () as usize),
        ("param_get_bool",  param_get_bool  as *const () as usize),
        ("param_set_int",   param_set_int   as *const () as usize),
        ("param_get_int",   param_get_int   as *const () as usize),
        ("param_set_uint",  param_set_uint  as *const () as usize),
        ("param_set_uint_minmax", params::param_set_uint_minmax as *const () as usize),
        ("param_get_uint",  param_get_uint  as *const () as usize),
        ("param_set_ulong", param_set_ulong as *const () as usize),
        ("param_get_ulong", param_get_ulong as *const () as usize),
    ] { export(name, addr, false); }
    export("param_ops_byte",  &param_ops_byte  as *const _ as usize, false);
    export("param_ops_bool",  &param_ops_bool  as *const _ as usize, false);
    export("param_ops_int",   &param_ops_int   as *const _ as usize, false);
    export("param_ops_uint",  &param_ops_uint  as *const _ as usize, false);
    export("param_ops_ulong", &param_ops_ulong as *const _ as usize, false);
    export("param_array_ops", &param_array_ops as *const _ as usize, false);
}

pub(crate) unsafe extern "C" fn try_module_get(module: *mut LinuxModule) -> i32 {
    if module.is_null() { return 1; }
    // SAFETY: try_module_get's KPI contract is that the caller already holds a reference keeping
    // this struct module alive; module was checked non-null above and LinuxModule is repr(C) with
    // Linux's field order, so the state word is readable at this offset.
    let state = unsafe { core::ptr::read_volatile(&(*module).state) };
    if state == MODULE_STATE_GOING { return 0; }
    if state != MODULE_STATE_LIVE && state != MODULE_STATE_COMING { return 0; }
    // SAFETY: module points at Linux module storage whose refcnt field is u32-aligned.
    let r = unsafe { refcnt(module) };
    r.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1)).is_ok() as i32
}

pub(crate) unsafe extern "C" fn module_put(module: *mut LinuxModule) {
    if module.is_null() { return; }
    // SAFETY: module points at Linux module storage whose refcnt field is u32-aligned.
    let r = unsafe { refcnt(module) };
    let _ = r.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
}

unsafe fn refcnt(module: *mut LinuxModule) -> &'static AtomicU32 {
    // SAFETY: LinuxModule is repr(C), refcnt is naturally aligned, and caller proves module lifetime.
    unsafe { &*((&mut (*module).refcnt as *mut u32).cast::<AtomicU32>()) }
}

use params::{param_get_byte, param_get_bool, param_get_int, param_get_uint, param_get_ulong, param_set_byte, param_set_bool, param_set_int, param_set_uint, param_set_ulong};

unsafe extern "C" fn param_array_set(val: *const c_char, kp: *const KernelParam) -> i32 {
    if kp.is_null() { return -LINUX_EINVAL; }
    // SAFETY: kernel_param layout matches Linux and caller supplied kp.
    let arr = unsafe { (*kp).arg as *const KParamArray };
    if arr.is_null() { return -LINUX_EINVAL; }
    // SAFETY: kparam_array is module-owned metadata supplied by Linux module code.
    let arr = unsafe { &*arr };
    if arr.elem.is_null() || arr.ops.is_null() || arr.elemsize == 0 { return -LINUX_EINVAL; }
    // SAFETY: arr.ops is checked non-null above.
    let Some(set) = (unsafe { (*arr.ops).set }) else { return -LINUX_EINVAL; };
    let Some(src) = cstr_bytes(val) else { return -LINUX_EINVAL; };
    let mut used = 0u32;
    for part in split_commas(src) {
        if used >= arr.max { return -LINUX_EINVAL; }
        let mut tmp = [0u8; PARAM_SCAN_LIMIT];
        if part.len() + 1 > tmp.len() { return -LINUX_EINVAL; }
        tmp[..part.len()].copy_from_slice(part);
        tmp[part.len()] = 0;
        let elem = (arr.elem as *mut u8).wrapping_add(used as usize * arr.elemsize as usize);
        // SAFETY: kernel_param layout matches Linux and caller supplied kp.
        let (name, mod_) = unsafe { ((*kp).name, (*kp).mod_) };
        let elem_kp = KernelParam { name, mod_, ops: arr.ops, perm: 0, level: 0, flags: 0, arg: elem.cast::<c_void>() };
        // SAFETY: set is arr.ops->set, the element ops the module itself installed; tmp is the
        // stack scratch NUL-terminated on the two lines above, and elem_kp points at element
        // `used` of arr.elem, which the used < arr.max check keeps inside the module's array.
        let rc = unsafe { set(tmp.as_ptr().cast::<c_char>(), &elem_kp) };
        if rc != 0 { return rc; }
        used += 1;
    }
    if !arr.num.is_null() {
        // SAFETY: num is optional Linux-owned output storage.
        unsafe { *arr.num = used; }
    }
    0
}

unsafe extern "C" fn param_array_get(buf: *mut c_char, kp: *const KernelParam) -> i32 {
    if buf.is_null() || kp.is_null() { return -LINUX_EINVAL; }
    // SAFETY: kernel_param layout matches Linux and caller supplied kp.
    let arr = unsafe { (*kp).arg as *const KParamArray };
    if arr.is_null() { return -LINUX_EINVAL; }
    // SAFETY: kparam_array is module-owned metadata supplied by Linux module code.
    let arr = unsafe { &*arr };
    if arr.elem.is_null() || arr.ops.is_null() || arr.elemsize == 0 { return -LINUX_EINVAL; }
    // SAFETY: arr.ops is checked non-null above.
    let Some(get) = (unsafe { (*arr.ops).get }) else { return -LINUX_EINVAL; };
    let count = if arr.num.is_null() { arr.max } else {
        // SAFETY: num is optional Linux-owned count storage.
        unsafe { (*arr.num).min(arr.max) }
    };
    let mut out = 0usize;
    for idx in 0..count {
        if idx != 0 {
            // SAFETY: Linux param get buffer is a page-sized writable output buffer.
            unsafe { *buf.add(out) = b',' as c_char; }
            out += 1;
        }
        let elem = (arr.elem as *mut u8).wrapping_add(idx as usize * arr.elemsize as usize);
        // SAFETY: kernel_param layout matches Linux and caller supplied kp.
        let (name, mod_) = unsafe { ((*kp).name, (*kp).mod_) };
        let elem_kp = KernelParam { name, mod_, ops: arr.ops, perm: 0, level: 0, flags: 0, arg: elem.cast::<c_void>() };
        // SAFETY: output buffer is page-sized and out remains short for KPI smoke/module param values.
        let n = unsafe { get(buf.add(out), &elem_kp) };
        if n < 0 { return n; }
        out += trim_param_newline(buf, out, n as usize);
    }
    // SAFETY: Linux param get buffer is a page-sized writable output buffer.
    unsafe {
        *buf.add(out) = b'\n' as c_char;
        *buf.add(out + 1) = 0;
    }
    (out + 1) as i32
}

pub(super) fn param_arg<T>(kp: *const KernelParam) -> Option<*mut T> {
    if kp.is_null() { return None; }
    // SAFETY: caller supplied a Linux kernel_param pointer and we only read arg.
    let arg = unsafe { (*kp).arg };
    if arg.is_null() { None } else { Some(arg.cast::<T>()) }
}

pub(super) fn parse_bool(s: *const c_char) -> Option<bool> {
    let b = trim_ascii(cstr_bytes(s)?);
    if eq_ignore_case(b, b"y") || eq_ignore_case(b, b"yes") || eq_ignore_case(b, b"1") ||
       eq_ignore_case(b, b"on") || eq_ignore_case(b, b"true") {
        Some(true)
    } else if eq_ignore_case(b, b"n") || eq_ignore_case(b, b"no") || eq_ignore_case(b, b"0") ||
              eq_ignore_case(b, b"off") || eq_ignore_case(b, b"false") {
        Some(false)
    } else {
        None
    }
}

pub(super) fn parse_i64(s: *const c_char) -> Option<i64> {
    let b = trim_ascii(cstr_bytes(s)?);
    if b.is_empty() { return None; }
    let neg = b[0] == b'-';
    let digits = if neg || b[0] == b'+' { &b[1..] } else { b };
    let v = parse_u64_bytes(digits)?;
    if neg {
        if v == (i64::MAX as u64) + 1 { Some(i64::MIN) } else { (v <= i64::MAX as u64).then_some(-(v as i64)) }
    } else {
        (v <= i64::MAX as u64).then_some(v as i64)
    }
}

pub(super) fn parse_u64(s: *const c_char) -> Option<u64> {
    let b = trim_ascii(cstr_bytes(s)?);
    if b.is_empty() || b[0] == b'-' { return None; }
    let digits = if b[0] == b'+' { &b[1..] } else { b };
    parse_u64_bytes(digits)
}

fn parse_u64_bytes(b: &[u8]) -> Option<u64> {
    if b.is_empty() { return None; }
    let (base, digits) = if b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        (16u64, &b[2..])
    } else if b.len() > 1 && b[0] == b'0' {
        (8u64, &b[1..])
    } else {
        (10u64, b)
    };
    if digits.is_empty() { return Some(0); }
    let mut out = 0u64;
    for &c in digits {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => 10 + (c - b'a') as u64,
            b'A'..=b'F' => 10 + (c - b'A') as u64,
            _ => return None,
        };
        if d >= base { return None; }
        out = out.checked_mul(base)?.checked_add(d)?;
    }
    Some(out)
}

fn cstr_bytes(s: *const c_char) -> Option<&'static [u8]> {
    if s.is_null() { return None; }
    let mut n = 0usize;
    // SAFETY: caller supplies a NUL-terminated Linux parameter string.
    unsafe {
        while n < PARAM_SCAN_LIMIT && *s.add(n) != 0 { n += 1; }
        if n == PARAM_SCAN_LIMIT { return None; }
        Some(core::slice::from_raw_parts(s.cast::<u8>(), n))
    }
}

fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if !c.is_ascii_whitespace() { break; }
        b = rest;
    }
    while let Some((&c, rest)) = b.split_last() {
        if !c.is_ascii_whitespace() { break; }
        b = rest;
    }
    b
}

fn split_commas(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    b.split(|&c| c == b',').map(trim_ascii)
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| x.to_ascii_lowercase() == y)
}

pub(super) fn write_i64(buf: *mut c_char, v: i64) -> i32 {
    if buf.is_null() { return -LINUX_EINVAL; }
    let mut tmp = [0u8; 22];
    let mut n = 0usize;
    if v < 0 {
        tmp[0] = b'-';
        n = 1;
    }
    let mag = v.unsigned_abs();
    n += decimal_into(&mut tmp[n..], mag);
    tmp[n] = b'\n';
    write_bytes(buf, &tmp[..=n])
}

pub(super) fn write_u64(buf: *mut c_char, v: u64) -> i32 {
    if buf.is_null() { return -LINUX_EINVAL; }
    let mut tmp = [0u8; 21];
    let n = decimal_into(&mut tmp, v);
    tmp[n] = b'\n';
    write_bytes(buf, &tmp[..=n])
}

fn decimal_into(out: &mut [u8], mut v: u64) -> usize {
    let mut rev = [0u8; 20];
    let mut n = 0usize;
    loop {
        rev[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 { break; }
    }
    for i in 0..n { out[i] = rev[n - 1 - i]; }
    n
}

pub(super) fn write_bytes(buf: *mut c_char, bytes: &[u8]) -> i32 {
    if buf.is_null() { return -LINUX_EINVAL; }
    // SAFETY: Linux param get buffer is a page-sized writable output buffer.
    unsafe {
        for (i, &b) in bytes.iter().enumerate() { *buf.add(i) = b as c_char; }
        *buf.add(bytes.len()) = 0;
    }
    bytes.len() as i32
}

fn trim_param_newline(buf: *mut c_char, off: usize, len: usize) -> usize {
    if len == 0 { return 0; }
    // SAFETY: caller just wrote len bytes at buf+off.
    let last = unsafe { *buf.add(off + len - 1) as u8 };
    if last == b'\n' { len - 1 } else { len }
}

#[cfg(test)]
#[path = "linux_module/tests.rs"]
mod tests;
