extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void, VaList};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

use super::{
    config_item_get_if_live, item_depend, item_undepend, unregister_default_groups, ConfigGroup,
    ConfigItem, ConfigfsSubsystem, NAME_MAX,
};

const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;

static OWNED_NAMES: Spinlock<BTreeMap<usize, Box<[u8]>>, ModulesLockClass> =
    Spinlock::new(BTreeMap::new());

pub(super) unsafe extern "C" fn config_item_set_name(
    item: *mut ConfigItem,
    fmt: *const c_char,
    mut ap: ...
) -> i32 {
    if item.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    let mut out = Vec::new();
    // SAFETY: fmt is a NUL-terminated printf-style format and ap matches it.
    unsafe { format_c(&mut out, fmt, &mut ap); }
    if out.is_empty() || out.len() > NAME_MAX { return -LINUX_EINVAL; }
    out.push(0);
    let boxed = out.into_boxed_slice();
    let ptr = boxed.as_ptr() as *const c_char;
    OWNED_NAMES.lock().insert(item as usize, boxed);
    // SAFETY: item is caller-owned configfs storage and ptr is retained in OWNED_NAMES.
    unsafe { (*item).name = ptr; }
    LINUX_OK
}

pub(super) extern "C" fn config_item_get_unless_zero(item: *mut ConfigItem) -> *mut ConfigItem {
    config_item_get_if_live(item).unwrap_or(null_mut())
}

pub(super) extern "C" fn configfs_remove_default_groups(group: *mut ConfigGroup) {
    if group.is_null() { return; }
    // SAFETY: group is caller-owned configfs storage.
    unsafe { unregister_default_groups(&mut (*group).item); }
}

pub(super) extern "C" fn configfs_depend_item(
    _subsys: *mut ConfigfsSubsystem,
    target: *mut ConfigItem,
) -> i32 {
    if target.is_null() { return -LINUX_EINVAL; }
    if !item_depend(target) { return -LINUX_EINVAL; }
    LINUX_OK
}

pub(super) extern "C" fn configfs_undepend_item(
    _subsys: *mut ConfigfsSubsystem,
    target: *mut ConfigItem,
) {
    if target.is_null() { return; }
    item_undepend(target);
}

pub(super) fn drop_owned_name(item: *mut ConfigItem) {
    OWNED_NAMES.lock().remove(&(item as usize));
}

unsafe fn format_c(out: &mut Vec<u8>, fmt: *const c_char, ap: &mut VaList) {
    let mut i = 0usize;
    loop {
        // SAFETY: fmt is a NUL-terminated format string.
        let b = unsafe { *fmt.add(i) } as u8;
        if b == 0 { break; }
        if b != b'%' { out.push(b); i += 1; continue; }
        i += 1;
        // SAFETY: conversion byte is within the same NUL-terminated format string.
        let mut c = unsafe { *fmt.add(i) } as u8;
        if c == b'%' { out.push(b'%'); i += 1; continue; }
        let mut long = false;
        while matches!(c, b'l' | b'z') {
            long = true;
            i += 1;
            // SAFETY: length modifier consumed; read following conversion byte.
            c = unsafe { *fmt.add(i) } as u8;
        }
        match c {
            b's' => {
                // SAFETY: vararg type follows %s conversion.
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const c_char };
                push_cstr(out, p);
            }
            b'c' => {
                // SAFETY: char is int-promoted in C varargs.
                out.push(unsafe { ap.next_arg::<i32>() as u8 });
            }
            b'd' | b'i' => {
                let v = if long {
                    // SAFETY: vararg type follows signed long conversion.
                    unsafe { ap.next_arg::<i64>() }
                } else {
                    // SAFETY: vararg type follows signed int conversion.
                    unsafe { ap.next_arg::<i32>() as i64 }
                };
                push_i64(out, v);
            }
            b'u' | b'x' => {
                let v = if long {
                    // SAFETY: vararg type follows unsigned long conversion.
                    unsafe { ap.next_arg::<u64>() }
                } else {
                    // SAFETY: vararg type follows unsigned int conversion.
                    unsafe { ap.next_arg::<u32>() as u64 }
                };
                push_u64(out, v, if c == b'x' { 16 } else { 10 });
            }
            b'p' => {
                // SAFETY: vararg type follows pointer conversion.
                let p = unsafe { ap.next_arg::<*mut c_void>() as usize };
                out.extend_from_slice(b"0x");
                push_u64(out, p as u64, 16);
            }
            _ => { out.push(b'%'); out.push(c); }
        }
        i += 1;
    }
}

fn push_cstr(out: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() { out.extend_from_slice(b"(null)"); return; }
    let mut n = 0usize;
    // SAFETY: caller's format contract makes p a NUL-terminated C string.
    unsafe {
        while *p.add(n) != 0 {
            out.push(*p.add(n) as u8);
            n += 1;
        }
    }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 {
        out.push(b'-');
        push_u64(out, v.unsigned_abs(), 10);
    } else {
        push_u64(out, v as u64, 10);
    }
}

fn push_u64(out: &mut Vec<u8>, mut v: u64, base: u64) {
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    loop {
        i -= 1;
        let d = (v % base) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        v /= base;
        if v == 0 { break; }
    }
    out.extend_from_slice(&buf[i..]);
}
