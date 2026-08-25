use alloc::alloc::{alloc, dealloc, Layout};
use alloc::vec::Vec;
use core::ffi::VaList;
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, write_bytes};

use super::types::{ALLOC_MAGIC, Header};
use super::MIN_ALIGN;
use super::pages::align_up;
pub(crate) fn alloc_bytes(size: usize, align: usize, zero: bool) -> *mut u8 {
    if size == 0 { return null_mut(); }
    let align = align.max(MIN_ALIGN).next_power_of_two();
    let off = align_up(size_of::<Header>(), align);
    let total = match off.checked_add(size) { Some(v) => v, None => return null_mut() };
    let layout = match Layout::from_size_align(total, align.max(align_of::<Header>())) {
        Ok(v) => v,
        Err(_) => return null_mut(),
    };
    // SAFETY: alloc requires a non-zero-size layout; size != 0 was checked at entry and
    // total = off + size, so from_size_align above accepted a layout of at least `size` bytes.
    let base = unsafe { alloc(layout) };
    if base.is_null() { return null_mut(); }
    // SAFETY: off < total because total = off + size with size >= 1, so base.add(off) stays
    // inside the allocation `alloc` just returned for `layout`.
    let user = unsafe { base.add(off) };
    let h = Header { magic: ALLOC_MAGIC, total, align: layout.align(), off };
    // SAFETY: header slot is inside the allocation immediately before user.
    unsafe {
        (user.sub(size_of::<Header>()) as *mut Header).write(h);
        if zero { write_bytes(user, 0, size); }
    }
    user
}

pub(crate) unsafe fn free_bytes(ptr: *mut u8) {
    if ptr.is_null() { return; }
    // SAFETY: caller supplies the live result of alloc_bytes, so its immediately preceding Header is readable.
    let hp = unsafe { ptr.sub(size_of::<Header>()) as *mut Header };
    // SAFETY: the Header belongs to the live allocation supplied by the caller.
    let h = unsafe { *hp };
    if h.magic != ALLOC_MAGIC { return; }
    let layout = match Layout::from_size_align(h.total, h.align) {
        Ok(v) => v,
        Err(_) => return,
    };
    // SAFETY: base/layout are reconstructed from the header written by alloc_bytes.
    unsafe { dealloc(ptr.sub(h.off), layout); }
}
pub(crate) unsafe fn format_c(out: &mut Vec<u8>, fmt: *const u8, ap: &mut VaList) {
    let mut i = 0usize;
    loop {
        // SAFETY: fmt is a NUL-terminated format string.
        let b = unsafe { *fmt.add(i) };
        if b == 0 { break; }
        if b != b'%' { out.push(b); i += 1; continue; }
        i += 1;
        // SAFETY: reading the next format byte is within the NUL string.
        let mut c = unsafe { *fmt.add(i) };
        if c == b'%' { out.push(b'%'); i += 1; continue; }
        let mut long = false;
        if c == b'l' || c == b'z' {
            long = true; i += 1;
            // SAFETY: length modifier consumed; read conversion byte.
            c = unsafe { *fmt.add(i) };
            if c == b'l' {
                i += 1;
                // SAFETY: second l consumed; read conversion byte.
                c = unsafe { *fmt.add(i) };
            }
        }
        match c {
            b's' => {
                // SAFETY: kasprintf's contract is that the varargs match fmt; a %s conversion was
                // just parsed, so the next slot holds a char pointer and next_arg reads it as such.
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const u8 };
                push_cstr(out, p);
            }
            b'c' => {
                // SAFETY: char is int-promoted in C varargs.
                out.push(unsafe { ap.next_arg::<i32>() as u8 });
            }
            b'd' | b'i' => {
                let v = if long {
                    // SAFETY: the l/z modifier consumed above means the caller passed a long or
                    // ssize_t for this %ld/%zd, which is exactly i64 on both LP64 kernel targets.
                    unsafe { ap.next_arg::<i64>() }
                } else {
                    // SAFETY: no length modifier was parsed, so bare %d/%i takes a C int, which
                    // after default argument promotion is the i32 read here.
                    unsafe { ap.next_arg::<i32>() as i64 }
                };
                push_i64(out, v);
            }
            b'u' | b'x' => {
                let v = if long {
                    // SAFETY: the l/z modifier consumed above means this %lu/%zx slot holds an
                    // unsigned long or size_t, which is exactly u64 on both LP64 kernel targets.
                    unsafe { ap.next_arg::<u64>() }
                } else {
                    // SAFETY: no length modifier was parsed, so bare %u/%x takes an unsigned int,
                    // which after default argument promotion is the u32 read here.
                    unsafe { ap.next_arg::<u32>() as u64 }
                };
                push_u64(out, v, if c == b'x' { 16 } else { 10 });
            }
            b'p' => {
                // SAFETY: a %p conversion was just parsed, so the caller's matching vararg is a
                // pointer; it is only widened to usize for hex formatting, never dereferenced.
                let p = unsafe { ap.next_arg::<*mut c_void>() as usize };
                out.extend_from_slice(b"0x");
                push_u64(out, p as u64, 16);
            }
            _ => { out.push(b'%'); out.push(c); }
        }
        i += 1;
    }
}

fn push_cstr(out: &mut Vec<u8>, p: *const u8) {
    if p.is_null() { out.extend_from_slice(b"(null)"); return; }
    let mut n = 0usize;
    // SAFETY: caller's format contract makes p a NUL-terminated C string.
    unsafe { while *p.add(n) != 0 { out.push(*p.add(n)); n += 1; } }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); push_u64(out, v.unsigned_abs(), 10); }
    else { push_u64(out, v as u64, 10); }
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
