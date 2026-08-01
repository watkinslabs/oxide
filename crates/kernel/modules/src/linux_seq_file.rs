extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void, VaList};
use core::ptr::null_mut;

use crate::linux_debugfs::{LinuxFile, LinuxInode};

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const MAX_SEQ_ITEMS: usize = 4096;
const MAX_SEQ_BYTES: usize = 1 << 20;

type StartFn = unsafe extern "C" fn(*mut SeqFile, *mut i64) -> *mut c_void;
type StopFn = unsafe extern "C" fn(*mut SeqFile, *mut c_void);
type NextFn = unsafe extern "C" fn(*mut SeqFile, *mut c_void, *mut i64) -> *mut c_void;
type ShowFn = unsafe extern "C" fn(*mut SeqFile, *mut c_void) -> i32;
type SingleShowFn = unsafe extern "C" fn(*mut SeqFile, *mut c_void) -> i32;

#[repr(C)]
pub struct SeqOperations {
    start: Option<StartFn>,
    stop:  Option<StopFn>,
    next:  Option<NextFn>,
    show:  Option<ShowFn>,
}

#[repr(C)]
pub struct SeqFile {
    private: *mut c_void,
}

#[repr(C)]
struct SeqState {
    seq: SeqFile,
    ops: usize,
    single_show: Option<SingleShowFn>,
    data: usize,
    body: Vec<u8>,
    generated: bool,
}

/// Register Linux seq_file KPI symbols. # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("seq_open",       seq_open       as *const () as usize),
        ("single_open",    single_open    as *const () as usize),
        ("seq_read",       seq_read       as *const () as usize),
        ("seq_lseek",      seq_lseek      as *const () as usize),
        ("seq_release",    seq_release    as *const () as usize),
        ("single_release", single_release as *const () as usize),
        ("seq_putc",       seq_putc       as *const () as usize),
        ("seq_puts",       seq_puts       as *const () as usize),
        ("seq_write",      seq_write      as *const () as usize),
        ("seq_printf",     seq_printf     as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn seq_open(file: *mut LinuxFile, ops: *const SeqOperations) -> i32 {
    if file.is_null() || ops.is_null() { return -EINVAL; }
    let state = Box::new(SeqState {
        seq: SeqFile { private: null_mut() },
        ops: ops as usize,
        single_show: None,
        data: 0,
        body: Vec::new(),
        generated: false,
    });
    // SAFETY: file is a live open file supplied by the caller.
    unsafe { (*file).private_data = Box::into_raw(state) as *mut c_void; }
    0
}

extern "C" fn single_open(file: *mut LinuxFile, show: Option<SingleShowFn>, data: *mut c_void) -> i32 {
    if file.is_null() || show.is_none() { return -EINVAL; }
    let state = Box::new(SeqState {
        seq: SeqFile { private: data },
        ops: 0,
        single_show: show,
        data: data as usize,
        body: Vec::new(),
        generated: false,
    });
    // SAFETY: file is a live open file supplied by the caller.
    unsafe { (*file).private_data = Box::into_raw(state) as *mut c_void; }
    0
}

extern "C" fn seq_read(file: *mut LinuxFile, buf: *mut c_char, count: usize, ppos: *mut i64) -> isize {
    let Some(state) = state_mut(file) else { return -EINVAL as isize; };
    if buf.is_null() || ppos.is_null() { return -EINVAL as isize; }
    if !state.generated {
        let rc = generate(state);
        if rc < 0 { return rc as isize; }
        state.generated = true;
    }
    // SAFETY: ppos is caller-owned position storage for this read operation.
    let off = unsafe { *ppos }.max(0) as usize;
    if off >= state.body.len() { return 0; }
    let n = (state.body.len() - off).min(count);
    // SAFETY: buf covers count bytes and ppos remains valid for this operation.
    unsafe {
        core::ptr::copy_nonoverlapping(state.body[off..off + n].as_ptr(), buf as *mut u8, n);
        *ppos += n as i64;
    }
    n as isize
}

extern "C" fn seq_lseek(_file: *mut LinuxFile, offset: i64, _whence: i32) -> i64 { offset.max(0) }

extern "C" fn seq_release(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    release_state(file);
    0
}

extern "C" fn single_release(inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    seq_release(inode, file)
}

extern "C" fn seq_putc(seq: *mut SeqFile, c: c_char) -> i32 {
    let Some(state) = seq_state_mut(seq) else { return -EINVAL; };
    if state.body.len() >= MAX_SEQ_BYTES { return -ENOMEM; }
    state.body.push(c as u8);
    0
}

pub(crate) extern "C" fn seq_puts(seq: *mut SeqFile, s: *const c_char) -> i32 {
    let Some(state) = seq_state_mut(seq) else { return -EINVAL; };
    if s.is_null() { return -EINVAL; }
    let mut i = 0usize;
    loop {
        // SAFETY: s is a caller-owned NUL-terminated C string.
        let b = unsafe { *s.add(i) } as u8;
        if b == 0 { break; }
        if state.body.len() >= MAX_SEQ_BYTES { return -ENOMEM; }
        state.body.push(b);
        i += 1;
    }
    0
}

pub(crate) extern "C" fn seq_write(seq: *mut SeqFile, data: *const c_void, len: usize) -> i32 {
    let Some(state) = seq_state_mut(seq) else { return -EINVAL; };
    if data.is_null() && len != 0 { return -EINVAL; }
    if state.body.len().saturating_add(len) > MAX_SEQ_BYTES { return -ENOMEM; }
    // SAFETY: data points to len readable bytes by seq_write contract.
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, len) };
    state.body.extend_from_slice(bytes);
    0
}

unsafe extern "C" fn seq_printf(seq: *mut SeqFile, fmt: *const c_char, mut ap: ...) -> i32 {
    let Some(state) = seq_state_mut(seq) else { return -EINVAL; };
    if fmt.is_null() { return -EINVAL; }
    // SAFETY: fmt and ap follow Linux printf-style varargs contract.
    unsafe { format_c(&mut state.body, fmt, &mut ap); }
    if state.body.len() > MAX_SEQ_BYTES { return -ENOMEM; }
    0
}

fn generate(state: &mut SeqState) -> i32 {
    if let Some(show) = state.single_show {
        // SAFETY: callback pointer comes from module-owned file_operations open path.
        return unsafe { show(&mut state.seq, state.data as *mut c_void) };
    }
    let ops = match seq_ops(state.ops) { Some(o) => o, None => return -EINVAL };
    let (Some(start), Some(next), Some(stop), Some(show)) = (ops.start, ops.next, ops.stop, ops.show) else { return -EINVAL };
    let mut pos = 0i64;
    // SAFETY: seq_operations callbacks belong to module-owned static operation storage.
    let mut item = unsafe { start(&mut state.seq, &mut pos) };
    let mut n = 0usize;
    while !item.is_null() && n < MAX_SEQ_ITEMS {
        // SAFETY: item was returned by start/next and remains valid until stop.
        let rc = unsafe { show(&mut state.seq, item) };
        if rc < 0 {
            // SAFETY: stop pairs with the active start/next iteration.
            unsafe { stop(&mut state.seq, item); }
            return rc;
        }
        // SAFETY: next advances the seq iterator and updates position.
        item = unsafe { next(&mut state.seq, item, &mut pos) };
        n += 1;
    }
    // SAFETY: stop pairs with the active start operation.
    unsafe { stop(&mut state.seq, item); }
    0
}

fn state_mut(file: *mut LinuxFile) -> Option<&'static mut SeqState> {
    if file.is_null() { return None; }
    // SAFETY: file is non-null and private_data is managed by seq_open/single_open.
    let ptr = unsafe { (*file).private_data as *mut SeqState };
    if ptr.is_null() { None } else {
        // SAFETY: state remains live until seq_release/single_release for this file.
        Some(unsafe { &mut *ptr })
    }
}

fn seq_state_mut(seq: *mut SeqFile) -> Option<&'static mut SeqState> {
    if seq.is_null() { return None; }
    let ptr = seq as *mut SeqState;
    // SAFETY: SeqState is repr(C) and seq is its first field.
    Some(unsafe { &mut *ptr })
}

fn release_state(file: *mut LinuxFile) {
    if file.is_null() { return; }
    // SAFETY: file is non-null and private_data belongs to seq_open/single_open.
    let ptr = unsafe { (*file).private_data as *mut SeqState };
    if !ptr.is_null() {
        // SAFETY: pointer was allocated by Box::into_raw in seq_open/single_open.
        unsafe { drop(Box::from_raw(ptr)); }
        // SAFETY: file is still owned by the active release callback.
        unsafe { (*file).private_data = null_mut(); }
    }
}

fn seq_ops(ptr: usize) -> Option<&'static SeqOperations> {
    if ptr == 0 { None } else {
        // SAFETY: pointer comes from module-owned static seq_operations.
        Some(unsafe { &*(ptr as *const SeqOperations) })
    }
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
            long = true; i += 1;
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
                // SAFETY: vararg type follows %p conversion.
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
    unsafe { while *p.add(n) != 0 { out.push(*p.add(n) as u8); n += 1; } }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); push_u64(out, v.unsigned_abs(), 10); } else { push_u64(out, v as u64, 10); }
}

fn push_u64(out: &mut Vec<u8>, mut v: u64, base: u64) {
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    loop {
        i -= 1;
        let d = (v % base) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v /= base;
        if v == 0 { break; }
    }
    out.extend_from_slice(&buf[i..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    unsafe extern "C" fn show(seq: *mut SeqFile, data: *mut c_void) -> i32 {
        // SAFETY: test passes a valid seq_file and NUL strings.
        unsafe {
            seq_puts(seq, b"name=\0".as_ptr() as *const c_char);
            seq_printf(seq, b"%s %u\n\0".as_ptr() as *const c_char, data, 7u32);
        }
        0
    }

    #[test]
    fn export_symbols_registers_seq_file_surface() {
        export_symbols();
        assert!(crate::is_exported("single_open"));
        assert!(crate::is_exported("seq_read"));
        assert!(crate::is_exported("seq_printf"));
    }

    #[test]
    fn single_open_read_release_materializes_show_output() {
        let mut file = LinuxFile { private_data: null_mut() };
        assert_eq!(single_open(&mut file, Some(show), b"demo\0".as_ptr() as *mut c_void), 0);
        let mut pos = 0i64;
        let mut buf = [0i8; 32];
        let n = seq_read(&mut file, buf.as_mut_ptr(), buf.len(), &mut pos);
        assert_eq!(n, 12);
        // SAFETY: buf is the 32-element i8 stack array passed to seq_read, and n is that call's
        // return value (asserted == 12), i.e. the number of bytes it actually wrote into buf, so
        // the slice covers only initialised, in-bounds elements of a still-live local.
        let got = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize) };
        assert_eq!(got, b"name=demo 7\n");
        assert_eq!(single_release(null_mut(), &mut file), 0);
        assert!(file.private_data.is_null());
    }
}
