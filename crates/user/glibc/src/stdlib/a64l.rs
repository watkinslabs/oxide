// a64l/l64a (docs/59§6) — radix-64 ⇄ long using glibc's alphabet
// [./0-9A-Za-z], 6 bits per char, least-significant first, on the low 32 bits.
// C ABI only.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;

fn val(c: u8) -> Option<i64> {
    Some(match c {
        b'.' => 0, b'/' => 1,
        b'0'..=b'9' => (c - b'0') as i64 + 2,
        b'A'..=b'Z' => (c - b'A') as i64 + 12,
        b'a'..=b'z' => (c - b'a') as i64 + 38,
        _ => return None,
    })
}
fn chr(v: i64) -> u8 {
    match v {
        0 => b'.', 1 => b'/',
        2..=11 => b'0' + (v - 2) as u8,
        12..=37 => b'A' + (v - 12) as u8,
        _ => b'a' + (v - 38) as u8,
    }
}

// # C: long a64l(const char *string)
#[no_mangle]
pub unsafe extern "C" fn a64l(s: *const u8) -> i64 {
    // SAFETY: s is a NUL-terminated C string; read up to 6 radix-64 digits,
    // stopping at the terminator or first out-of-alphabet byte.
    unsafe {
        let mut acc = 0i64;
        let mut i = 0;
        while i < 6 {
            match val(*s.add(i)) { Some(d) => { acc |= d << (6 * i); i += 1; } None => break }
        }
        acc & 0xffff_ffff // glibc a64l yields a 32-bit value (zero-extended)
    }
}

struct Buf(UnsafeCell<[u8; 7]>);
// SAFETY: process-global l64a scratch; single-threaded until TLS.
unsafe impl Sync for Buf {}
static BUF: Buf = Buf(UnsafeCell::new([0u8; 7]));

// # C: char *l64a(long n) — encodes the low 32 bits; n<=0 → ""
#[no_mangle]
pub unsafe extern "C" fn l64a(n: i64) -> *mut u8 {
    // SAFETY: writes up to 6 radix-64 chars + NUL into the process-global
    // buffer and returns it (glibc contract).
    unsafe {
        let b = &mut *BUF.0.get();
        let mut v = (n as u32) as i64; // low 32 bits, unsigned
        let mut k = 0;
        while v > 0 && k < 6 { b[k] = chr(v & 63); v >>= 6; k += 1; }
        b[k] = 0;
        b.as_mut_ptr()
    }
}
