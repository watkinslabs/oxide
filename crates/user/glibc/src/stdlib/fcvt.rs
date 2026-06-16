// Legacy number→string (ecvt/fcvt/gcvt + the _r reentrant forms), the C11
// strfromd/strfromf, and the printf customization API (register_printf_*,
// parse_printf_format, printf_size). docs/59§6 G7.
//
// ecvt/fcvt/gcvt reuse the crate's printf float engine (super::super::stdio::
// fmt) so digit strings round bit-identically to host glibc's %e/%f/%g. The
// long-double q* variants (qecvt/qfcvt/qgcvt, *_l) are UNSUPPORTED per
// glibc_unsupported.md and are not defined here.
#![cfg(feature = "freestanding")]
use crate::stdio::fmt::{self, Args, Sink};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};

// ---- one-f64 vararg adapter for the printf engine ---------------------------
struct OneF64 { v: f64 }
impl Args for OneF64 {
    unsafe fn next_i32(&mut self) -> i32 { 0 }
    unsafe fn next_i64(&mut self) -> i64 { 0 }
    unsafe fn next_u32(&mut self) -> u32 { 0 }
    unsafe fn next_u64(&mut self) -> u64 { 0 }
    unsafe fn next_ptr(&mut self) -> *const u8 { core::ptr::null() }
    unsafe fn next_f64(&mut self) -> f64 { self.v }
}

// Fixed-buffer sink: render a float into a stack buffer (≤ 512 bytes covers
// any finite double at any reasonable precision used here).
struct BufSink { b: [u8; 512], n: usize }
impl Sink for BufSink {
    fn push(&mut self, x: u8) { if self.n < self.b.len() { self.b[self.n] = x; self.n += 1; } }
    fn count(&self) -> usize { self.n }
}

// Format `v` with the conversion `conv` (b'e'/b'f'/b'g') at precision `prec`
// using the shared printf engine; returns the rendered bytes in `out[..n]`.
fn render(conv: u8, prec: usize, v: f64, out: &mut [u8; 512]) -> usize {
    let mut fmtbuf = [0u8; 16];
    // build "%.<prec><conv>\0"
    let mut k = 0usize;
    fmtbuf[k] = b'%'; k += 1;
    fmtbuf[k] = b'.'; k += 1;
    if prec == 0 { fmtbuf[k] = b'0'; k += 1; }
    else {
        let mut digs = [0u8; 10]; let mut d = 0usize; let mut p = prec;
        while p > 0 { digs[d] = b'0' + (p % 10) as u8; d += 1; p /= 10; }
        while d > 0 { d -= 1; fmtbuf[k] = digs[d]; k += 1; }
    }
    fmtbuf[k] = conv; k += 1;
    fmtbuf[k] = 0;
    let mut sink = BufSink { b: [0; 512], n: 0 };
    let mut args = OneF64 { v };
    // SAFETY: fmtbuf is NUL-terminated; args supplies the one f64 the single
    // conversion in fmtbuf consumes; sink buffer is 512 bytes.
    unsafe { fmt::vformat(&mut sink, fmtbuf.as_ptr(), &mut args); }
    let n = sink.n.min(512);
    out[..n].copy_from_slice(&sink.b[..n]);
    n
}

// Core ecvt: `ndigit` significant digits. Writes the digit string (NUL-term)
// into `buf` (≥ ndigit+1), sets *decpt and *sign. Empty/zero handled.
fn ecvt_core(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut u8, len: usize) -> c_int {
    let nd = if ndigit < 1 { 1usize } else { ndigit as usize };
    let neg = value.is_sign_negative() && !value.is_nan();
    let mag = if neg { -value } else { value };
    // SAFETY: decpt/sign are caller-provided out pointers per the C contract.
    unsafe { if !sign.is_null() { *sign = neg as c_int; } }
    let mut tmp = [0u8; 512];
    let n = render(b'e', nd - 1, mag, &mut tmp); // "d.ddde±XX"
    // extract mantissa digits + decimal exponent
    let mut digits = [0u8; 520];
    let mut dn = 0usize;
    let mut i = 0usize;
    while i < n && tmp[i] != b'e' && tmp[i] != b'E' { if tmp[i] != b'.' { digits[dn] = tmp[i]; dn += 1; } i += 1; }
    let mut exp = 0i32; let mut esign = 1i32;
    if i < n { i += 1; if i < n && tmp[i] == b'-' { esign = -1; i += 1; } else if i < n && tmp[i] == b'+' { i += 1; } }
    while i < n && tmp[i].is_ascii_digit() { exp = exp * 10 + (tmp[i] - b'0') as i32; i += 1; }
    exp *= esign;
    // SAFETY: decpt is a caller out pointer; decpt = exponent + 1 (glibc).
    unsafe { if !decpt.is_null() { *decpt = exp + 1; } }
    write_buf(buf, len, &digits[..dn.min(nd)])
}

// Core fcvt: `ndigit` digits after the decimal point. Writes the digit string
// (NUL-term) into `buf`, sets *decpt + *sign per glibc.
fn fcvt_core(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut u8, len: usize) -> c_int {
    let nd = if ndigit < 0 { 0usize } else { ndigit as usize };
    let neg = value.is_sign_negative() && !value.is_nan();
    let mag = if neg { -value } else { value };
    // SAFETY: sign is a caller out pointer per the C contract.
    unsafe { if !sign.is_null() { *sign = neg as c_int; } }
    // glibc quirk: an exactly-zero value yields "0" + ndigit fraction zeros
    // (ndigit+1 chars) with decpt = 1 — unlike a tiny nonzero that rounds away.
    if mag == 0.0 {
        let z = [b'0'; 521];
        // SAFETY: decpt is a caller out pointer.
        unsafe { if !decpt.is_null() { *decpt = 1; } }
        return write_buf(buf, len, &z[..(nd + 1).min(z.len())]);
    }
    let mut tmp = [0u8; 512];
    let n = render(b'f', nd, mag, &mut tmp); // "iii.fff" (or "iii")
    // split integer / fraction
    let mut dot = n;
    for (k, &c) in tmp[..n].iter().enumerate() { if c == b'.' { dot = k; break; } }
    let int_part = &tmp[..dot];
    let frac_part = if dot < n { &tmp[dot + 1..n] } else { &tmp[n..n] };
    // integer part nonzero? ("0" means magnitude < 1)
    let int_nonzero = int_part.iter().any(|&c| c != b'0');
    let mut digits = [0u8; 520];
    let mut dn = 0usize;
    let mut dp: i32;
    if int_nonzero {
        for &c in int_part { digits[dn] = c; dn += 1; }
        dp = int_part.len() as i32;
        for &c in frac_part { digits[dn] = c; dn += 1; }
    } else {
        // magnitude < 1: drop the leading "0", strip leading zeros from frac,
        // decpt = -(count of leading fraction zeros).
        let mut lead = 0usize;
        while lead < frac_part.len() && frac_part[lead] == b'0' { lead += 1; }
        dp = -(lead as i32);
        if lead == frac_part.len() { dp = -(nd as i32); dn = 0; } // all zero → empty string
        else { for &c in &frac_part[lead..] { digits[dn] = c; dn += 1; } }
    }
    // SAFETY: decpt is a caller out pointer.
    unsafe { if !decpt.is_null() { *decpt = dp; } }
    write_buf(buf, len, &digits[..dn])
}

// Copy `src` + NUL into a caller buffer of `len` bytes; returns 0 on success,
// -1 if it would overflow (the _r contract). For the non-_r forms `len` is the
// static-buffer size so overflow cannot occur.
fn write_buf(buf: *mut u8, len: usize, src: &[u8]) -> c_int {
    if src.len() + 1 > len { return -1; }
    // SAFETY: buf has `len` ≥ src.len()+1 bytes; we write src then a NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), buf, src.len());
        *buf.add(src.len()) = 0;
    }
    0
}

// Process-global static buffers for the non-reentrant ecvt/fcvt (glibc returns
// a pointer into a shared static). Single-threaded until TLS; matches the
// a64l/l64a pattern in this crate.
struct Scratch(UnsafeCell<[u8; 400]>);
// SAFETY: process-global ecvt/fcvt scratch; single-threaded use, like l64a.
unsafe impl Sync for Scratch {}
static ECVT_BUF: Scratch = Scratch(UnsafeCell::new([0u8; 400]));
static FCVT_BUF: Scratch = Scratch(UnsafeCell::new([0u8; 400]));

/// # C: char *ecvt(double value, int ndigit, int *decpt, int *sign)
#[no_mangle]
pub unsafe extern "C" fn ecvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut u8 {
    // SAFETY: writes ndigit significant digits into the process-global ECVT_BUF
    // (400 bytes ≫ any sane ndigit) and returns it; decpt/sign are out params.
    unsafe { let b = &mut *ECVT_BUF.0.get(); ecvt_core(value, ndigit, decpt, sign, b.as_mut_ptr(), b.len()); b.as_mut_ptr() }
}

/// # C: char *fcvt(double value, int ndigit, int *decpt, int *sign)
#[no_mangle]
pub unsafe extern "C" fn fcvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut u8 {
    // SAFETY: writes ndigit fractional digits into the process-global FCVT_BUF
    // and returns it; decpt/sign are caller out pointers.
    unsafe { let b = &mut *FCVT_BUF.0.get(); fcvt_core(value, ndigit, decpt, sign, b.as_mut_ptr(), b.len()); b.as_mut_ptr() }
}

/// # C: int ecvt_r(double value, int ndigit, int *decpt, int *sign, char *buf, size_t len)
#[no_mangle]
pub unsafe extern "C" fn ecvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut u8, len: usize) -> c_int {
    // SAFETY: buf is a caller buffer of `len` bytes; decpt/sign are out params.
    ecvt_core(value, ndigit, decpt, sign, buf, len)
}

/// # C: int fcvt_r(double value, int ndigit, int *decpt, int *sign, char *buf, size_t len)
#[no_mangle]
pub unsafe extern "C" fn fcvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut u8, len: usize) -> c_int {
    // SAFETY: buf is a caller buffer of `len` bytes; decpt/sign are out params.
    fcvt_core(value, ndigit, decpt, sign, buf, len)
}

/// # C: char *gcvt(double value, int ndigit, char *buf)
#[no_mangle]
pub unsafe extern "C" fn gcvt(value: f64, ndigit: c_int, buf: *mut u8) -> *mut u8 {
    // SAFETY: gcvt == sprintf(buf, "%.*g", ndigit, value); buf is caller-sized
    // (glibc requires ≥ ndigit+ slack). Render via the %g engine and copy.
    unsafe {
        let nd = if ndigit < 1 { 1usize } else { ndigit as usize };
        let mut tmp = [0u8; 512];
        let n = render(b'g', nd, value, &mut tmp);
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n);
        *buf.add(n) = 0;
        buf
    }
}

// ---- strfromd / strfromf (C11 7.22.1.3) -------------------------------------
// Format a double/float per a printf format string containing exactly one
// %a/%A/%e/%E/%f/%F/%g/%G conversion (no field width from a vararg). Behaves
// like snprintf(s, n, fmt, x): writes ≤ n-1 bytes + NUL, returns the count
// that *would* have been written.
struct SliceSink { buf: *mut u8, cap: usize, pos: usize, total: usize }
impl Sink for SliceSink {
    fn push(&mut self, b: u8) {
        if self.cap > 0 && self.pos < self.cap - 1 {
            // SAFETY: pos < cap-1, so buf[pos] is within the caller's buffer.
            unsafe { *self.buf.add(self.pos) = b; }
            self.pos += 1;
        }
        self.total += 1;
    }
    fn count(&self) -> usize { self.total }
}

unsafe fn strfrom(s: *mut u8, n: usize, fmt: *const u8, v: f64) -> c_int {
    // SAFETY: fmt is a NUL-terminated single-conversion format; s holds n bytes.
    unsafe {
        let mut sink = SliceSink { buf: s, cap: n, pos: 0, total: 0 };
        let mut args = OneF64 { v };
        let total = fmt::vformat(&mut sink, fmt, &mut args);
        if n > 0 { *s.add(sink.pos) = 0; }
        total as c_int
    }
}

/// # C: int strfromd(char *s, size_t n, const char *format, double fp)
#[no_mangle]
pub unsafe extern "C" fn strfromd(s: *mut u8, n: usize, format: *const u8, fp: f64) -> c_int {
    // SAFETY: forwards the C11 strfromd contract to the shared float engine.
    unsafe { strfrom(s, n, format, fp) }
}

/// # C: int strfromf(char *s, size_t n, const char *format, float fp)
#[no_mangle]
pub unsafe extern "C" fn strfromf(s: *mut u8, n: usize, format: *const u8, fp: f32) -> c_int {
    // SAFETY: widen the float arg to f64 (the engine's float path) and format.
    unsafe { strfrom(s, n, format, fp as f64) }
}

/// # C: int strfromf64(char *s, size_t n, const char *format, _Float64 fp)
/// _Float64 == double, so strfromf64 is identical to strfromd.
#[no_mangle]
pub unsafe extern "C" fn strfromf64(s: *mut u8, n: usize, format: *const u8, fp: f64) -> c_int {
    // SAFETY: forwards the strfromd contract (the _Float64 alias) to the engine.
    unsafe { strfrom(s, n, format, fp) }
}

// ---- printf customization API: PA_* argtype codes ---------------------------
// glibc <printf.h> constants. parse_printf_format fills *argtypes with these.
const PA_INT: c_int = 0;
const PA_CHAR: c_int = 1;
const PA_STRING: c_int = 3;
const PA_POINTER: c_int = 5;
const PA_DOUBLE: c_int = 7;
const PA_FLAG_LONG_DOUBLE: c_int = 256; // == PA_FLAG_LONG_LONG (long double share)
const PA_FLAG_LONG: c_int = 512;
const PA_FLAG_SHORT: c_int = 1024;
const PA_FLAG_PTR: c_int = 2048;

// Decode the conversion `conv` (already past flags/width/prec/length) into a
// PA_* argtype, given the parsed length flag. Mirrors glibc's collapse where
// l/ll/z/j/t all map to PA_FLAG_LONG on LP64 and hh/c map to PA_CHAR.
fn argtype_for(conv: u8, lenflag: c_int) -> c_int {
    match conv {
        b'd' | b'i' | b'x' | b'X' | b'o' | b'u' => PA_INT | lenflag,
        b'c' => PA_CHAR,
        b's' => PA_STRING,
        b'p' => PA_POINTER,
        b'n' => PA_INT | PA_FLAG_PTR,
        b'a' | b'A' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => PA_DOUBLE | lenflag,
        _ => -1,
    }
}

/// # C: size_t parse_printf_format(const char *fmt, size_t n, int *argtypes)
#[no_mangle]
pub unsafe extern "C" fn parse_printf_format(fmt: *const u8, n: usize, argtypes: *mut c_int) -> usize {
    // SAFETY: fmt is NUL-terminated; argtypes holds ≥ min(n, count) entries.
    // Walk each %-conversion, decode its argtype, and store up to n of them.
    unsafe {
        let mut count = 0usize;
        let mut i = 0usize;
        loop {
            let c = *fmt.add(i);
            if c == 0 { break; }
            if c != b'%' { i += 1; continue; }
            i += 1;
            if *fmt.add(i) == b'%' { i += 1; continue; }
            // skip flags ('I' is an i18n flag, not a specifier)
            while matches!(*fmt.add(i), b'-' | b'+' | b' ' | b'#' | b'0' | b'\'' | b'I') { i += 1; }
            // width: '*' consumes an int arg
            if *fmt.add(i) == b'*' { if count < n { *argtypes.add(count) = PA_INT; } count += 1; i += 1; }
            else { while (*fmt.add(i)).is_ascii_digit() { i += 1; } }
            // precision
            if *fmt.add(i) == b'.' {
                i += 1;
                if *fmt.add(i) == b'*' { if count < n { *argtypes.add(count) = PA_INT; } count += 1; i += 1; }
                else { while (*fmt.add(i)).is_ascii_digit() { i += 1; } }
            }
            // length modifier → flag (lenflag == -1 is the hh/PA_CHAR sentinel)
            let mut lenflag = 0;
            match *fmt.add(i) {
                b'h' => { i += 1; if *fmt.add(i) == b'h' { i += 1; lenflag = -1; } else { lenflag = PA_FLAG_SHORT; } }
                b'l' => { i += 1; if *fmt.add(i) == b'l' { i += 1; } lenflag = PA_FLAG_LONG; }
                b'z' | b'j' | b't' | b'q' => { i += 1; lenflag = PA_FLAG_LONG; }
                b'L' => { i += 1; lenflag = PA_FLAG_LONG_DOUBLE; }
                _ => {}
            }
            let conv = *fmt.add(i);
            i += 1;
            // hh on an integer conversion → PA_CHAR; otherwise decode normally.
            let at = if lenflag == -1 {
                match conv { b'd' | b'i' | b'x' | b'X' | b'o' | b'u' => PA_CHAR, _ => argtype_for(conv, 0) }
            } else { argtype_for(conv, lenflag) };
            if at >= 0 { if count < n { *argtypes.add(count) = at; } count += 1; }
        }
        count
    }
}

// ---- register_printf_* (functional registration table) ----------------------
// glibc lets a program install a handler + arginfo for a spec byte. Our printf
// engine does not yet dispatch user specifiers through vformat, so these record
// the registration (so repeated/conflicting registration is observable and the
// table is queryable) and printf_size below is callable directly. See the
// not-done note: %H/%I via printf(...) is not auto-dispatched.
type PrintfFn = extern "C" fn(*mut c_void, *const c_void, *const *const c_void) -> c_int;
type ArgInfoFn = extern "C" fn(*const c_void, usize, *mut c_int, *mut c_int) -> c_int;

struct RegTable { func: UnsafeCell<[usize; 256]>, info: UnsafeCell<[usize; 256]>, modbit: UnsafeCell<u32> }
// SAFETY: process-global printf registration table; single-threaded mutation
// like the other freestanding statics in this crate (no TLS yet).
unsafe impl Sync for RegTable {}
static REG: RegTable = RegTable { func: UnsafeCell::new([0; 256]), info: UnsafeCell::new([0; 256]), modbit: UnsafeCell::new(0) };

/// # C: int register_printf_specifier(int spec, printf_function func, printf_arginfo_size_function arginfo)
#[no_mangle]
pub unsafe extern "C" fn register_printf_specifier(spec: c_int, func: Option<PrintfFn>, arginfo: Option<ArgInfoFn>) -> c_int {
    // SAFETY: records the handler/arginfo pointers for the spec byte in the
    // process-global table; spec masked to a byte index.
    unsafe {
        if !(0..=255).contains(&spec) { return -1; }
        let idx = spec as usize;
        (*REG.func.get())[idx] = func.map_or(0, |f| f as usize);
        (*REG.info.get())[idx] = arginfo.map_or(0, |f| f as usize);
        0
    }
}

/// # C: int register_printf_function(int spec, printf_function func, printf_arginfo_function arginfo)
#[no_mangle]
pub unsafe extern "C" fn register_printf_function(spec: c_int, func: Option<PrintfFn>, arginfo: Option<ArgInfoFn>) -> c_int {
    // SAFETY: obsolete alias of register_printf_specifier (the arginfo signature
    // differs but both are stored opaquely); forwards under the same contract.
    unsafe { register_printf_specifier(spec, func, arginfo) }
}

/// # C: int register_printf_modifier(const wchar_t *str)
#[no_mangle]
pub unsafe extern "C" fn register_printf_modifier(str: *const i32) -> c_int {
    // SAFETY: str is a NUL-terminated wchar_t string (or null). glibc returns a
    // positive bit for the USER field; we allocate the next free bit (1..=15).
    unsafe {
        if str.is_null() || *str == 0 { return -1; }
        let bit = *REG.modbit.get();
        if bit >= 16 { return -1; }
        *REG.modbit.get() = bit + 1;
        (1i32) << bit
    }
}

// ---- printf_size / printf_size_info -----------------------------------------
// glibc's %H (SI 1000-scale) / %I (binary 1024-scale) handler. Formats the
// double arg as "<scaled>.<frac><suffix>" where suffix ∈ " KMGTPEZY". Negative
// or sub-base magnitudes are not scaled (glibc divides only while value ≥ base).
// The arg vector is `args[0]` → *const f64; output goes to the FILE via fputc.
// Callable directly (the test path); not auto-dispatched by vformat.
const SI_SUFFIX: &[u8; 9] = b" KMGTPEZY";

/// # C: int printf_size(FILE *fp, const struct printf_info *info, const void *const *args)
#[no_mangle]
pub unsafe extern "C" fn printf_size(fp: *mut c_void, info: *const c_void, args: *const *const c_void) -> c_int {
    extern "C" { fn fputc(c: c_int, f: *mut crate::stdio::file::FILE) -> c_int; }
    // SAFETY: info points at a glibc `struct printf_info`; we read prec (off 0),
    // width (off 4), spec (off 8), and the left-flag bit. args[0] → *const f64.
    unsafe {
        let prec = *(info as *const c_int); // struct printf_info.prec
        let width = *((info as *const c_int).add(1)); // .width
        let spec = *((info as *const c_int).add(2)) as u8; // .spec (wchar_t low byte)
        // bitfield word follows spec at offset 12; `left` is the 6th flag (bit 5).
        let flagword = *((info as *const u32).add(3));
        let left = (flagword & (1 << 5)) != 0;
        let value = *(*args as *const f64);
        let base: f64 = if spec == b'I' { 1024.0 } else { 1000.0 };
        // scale while ≥ base (glibc does not scale negatives, which are < base)
        let mut v = value;
        let mut sidx = 0usize;
        while v >= base && sidx + 1 < SI_SUFFIX.len() { v /= base; sidx += 1; }
        let p = if prec < 0 { 3usize } else { prec as usize };
        let mut tmp = [0u8; 512];
        let mut nlen = render(b'f', p, v, &mut tmp);
        tmp[nlen] = SI_SUFFIX[sidx]; nlen += 1;
        // field-width padding with spaces
        let w = if width < 0 { 0usize } else { width as usize };
        let pad = w.saturating_sub(nlen);
        let mut written = 0usize;
        let mut emit = |b: u8| { fputc(b as c_int, fp as *mut crate::stdio::file::FILE); written += 1; };
        if !left { for _ in 0..pad { emit(b' '); } }
        for &b in &tmp[..nlen] { emit(b); }
        if left { for _ in 0..pad { emit(b' '); } }
        written as c_int
    }
}

/// # C: int printf_size_info(const struct printf_info *info, size_t n, int *argtypes, int *size)
#[no_mangle]
pub unsafe extern "C" fn printf_size_info(_info: *const c_void, n: usize, argtypes: *mut c_int, _size: *mut c_int) -> c_int {
    // SAFETY: argtypes holds ≥1 entry when n≥1; the %H/%I arg is one double.
    unsafe { if n >= 1 && !argtypes.is_null() { *argtypes = PA_DOUBLE; } 1 }
}

// No #[cfg(test)] here: the module is gated `#![cfg(feature = "freestanding")]`
// (a no_std final artifact with its own panic handler), so it cannot link as a
// hosted test binary. Validation is the differential harness userspace/
// glibc_conformance/t_fcvt.c (xtask glibc-test).
