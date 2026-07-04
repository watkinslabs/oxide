// libresolv ns_* wire helpers (docs/59§6 §9.1, <arpa/nameser.h>): RFC1035 name
// codec primitives. Pure — no network. ns_name_ntop/pton convert between the
// label wire format and presentation text (with glibc's escaping); ns_name_skip
// walks a wire name (following a compression pointer's first byte). The big-
// endian ns_get*/ns_put* accessors round out the RR-field codec.
#![cfg(feature = "freestanding")]
use core::ffi::c_char;

const NS_CMPRSFLGS: u8 = 0xc0; // top 2 bits set ⇒ compression pointer
const EMSGSIZE: i32 = 90;

// glibc ns_name.c special(): chars that get a backslash escape in presentation.
fn special(c: u8) -> bool { matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') }
// printable per glibc: strictly between SP and DEL.
fn printable(c: u8) -> bool { c > 0x20 && c < 0x7f }

// SAFETY: generated aliases preserve each target's caller contract unchanged.
macro_rules! alias_unsafe {
    ($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $target:ident;) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
            // SAFETY: generated alias forwards the same C ABI contract unchanged.
            unsafe { $target($($arg),*) }
        }
    };
}

// # C: unsigned ns_get16(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get16(src: *const u8) -> u32 {
    // SAFETY: src points at ≥2 readable bytes of an RR field.
    unsafe { ((*src as u32) << 8) | *src.add(1) as u32 }
}
alias_unsafe!(__ns_get16(src: *const u8) -> u32 = ns_get16;);
// # C: unsigned long ns_get32(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get32(src: *const u8) -> u64 {
    // SAFETY: src points at ≥4 readable bytes of an RR field.
    unsafe { ((*src as u64) << 24) | ((*src.add(1) as u64) << 16) | ((*src.add(2) as u64) << 8) | *src.add(3) as u64 }
}
alias_unsafe!(__ns_get32(src: *const u8) -> u64 = ns_get32;);
// # C: void ns_put16(unsigned src, unsigned char *dst)
#[no_mangle]
pub unsafe extern "C" fn ns_put16(src: u32, dst: *mut u8) {
    // SAFETY: dst points at ≥2 writable bytes.
    unsafe { *dst = (src >> 8) as u8; *dst.add(1) = src as u8; }
}
// # C: void ns_put32(unsigned long src, unsigned char *dst)
#[no_mangle]
pub unsafe extern "C" fn ns_put32(src: u64, dst: *mut u8) {
    // SAFETY: dst points at ≥4 writable bytes.
    unsafe { *dst = (src >> 24) as u8; *dst.add(1) = (src >> 16) as u8; *dst.add(2) = (src >> 8) as u8; *dst.add(3) = src as u8; }
}

unsafe fn nlen(s: *const u8) -> usize { let mut n = 0; unsafe { while *s.add(n) != 0 { n += 1; } } n }
fn lc(c: u8) -> u8 { if c.is_ascii_uppercase() { c + 32 } else { c } }

fn res_printable(c: u8) -> bool { (0x21..0x7f).contains(&c) }
fn host_char(c: u8) -> bool { c.is_ascii_alphanumeric() || c == b'-' || c == b'_' }
const EINVAL: i32 = 22;

// Module manifest: name owns DNS label codecs; validate owns resolver name predicates; ttl owns TTL text; message owns ns_msg/ns_rr parsing and printing.
mod name;
mod validate;
mod ttl;
mod message;
pub use message::*;
pub use name::*;
pub use ttl::*;
pub use validate::*;
