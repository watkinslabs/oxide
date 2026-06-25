// Wide formatted I/O (docs/59§6 G6) — wprintf/wscanf families built on the
// narrow printf/scanf engines. Output: the wide format template (wchar_t) is
// transcoded to a UTF-8 narrow format string, with bare %c→%lc and %s→%ls so
// the narrow engine reads the wide varargs; the produced UTF-8 bytes go to the
// stream as-is, or are decoded back to wchar_t for swprintf. Input: a focused
// wide scanf reads wide chars from a string/FILE source.
#![cfg(feature = "freestanding")]
use super::file::{set_unget, stdin_ptr, stdout_ptr, FILE};
use super::fmt::{self, Args, Sink};
use super::memstream::stream_write;
use super::wide::{getwc_raw, WEOF};
use crate::locale::wchar::{decode_utf8, encode_utf8};
use alloc::vec::Vec;
use core::ffi::{c_void, VaList};

// Transcode a wchar_t format string to a UTF-8 byte format string, rewriting a
// bare conversion's `c`/`s`/`[` (which in a wide function name wide args) into
// their `l`-prefixed forms so the narrow engine fetches a wchar_t / wchar_t*.
fn wfmt_to_narrow(wfmt: *const i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    // SAFETY: wfmt is a NUL-terminated wchar_t format string; we walk it to the
    // terminator, never reading past it.
    unsafe {
        loop {
            let wc = *wfmt.add(i);
            if wc == 0 { break; }
            let (o, len) = encode_utf8(wc as u32);
            out.extend_from_slice(&o[..len]);
            if wc == '%' as i32 {
                i += 1;
                // copy flags/width/precision/length verbatim until the conversion
                let mut saw_l = false;
                loop {
                    let c = *wfmt.add(i);
                    if c == 0 { break; }
                    let cb = c as u8;
                    match cb {
                        b'l' | b'h' | b'L' | b'j' | b'z' | b't' | b'q' => { if cb == b'l' { saw_l = true; } out.push(cb); i += 1; }
                        b'-' | b'+' | b' ' | b'#' | b'.' | b'*' | b'\'' => { out.push(cb); i += 1; }
                        b'0'..=b'9' => { out.push(cb); i += 1; }
                        b'c' | b's' if !saw_l => { out.push(b'l'); out.push(cb); i += 1; break; }
                        _ => { let (oo, ll) = encode_utf8(c as u32); out.extend_from_slice(&oo[..ll]); i += 1; break; }
                    }
                }
                continue;
            }
            i += 1;
        }
    }
    out
}

struct Va<'a, 'b>(&'a mut VaList<'b>);
impl Args for Va<'_, '_> {
    unsafe fn next_i32(&mut self) -> i32 { unsafe { self.0.next_arg() } }
    unsafe fn next_i64(&mut self) -> i64 { unsafe { self.0.next_arg() } }
    unsafe fn next_u32(&mut self) -> u32 { unsafe { self.0.next_arg() } }
    unsafe fn next_u64(&mut self) -> u64 { unsafe { self.0.next_arg() } }
    unsafe fn next_ptr(&mut self) -> *const u8 { unsafe { self.0.next_arg::<*mut c_void>() as *const u8 } }
    unsafe fn next_f64(&mut self) -> f64 { unsafe { self.0.next_arg() } }
}

// Sink that writes the produced UTF-8 byte stream to a FILE (as bytes).
struct StreamSink { f: *mut FILE, buf: [u8; 256], len: usize, total: usize }
impl StreamSink {
    fn new(f: *mut FILE) -> Self { StreamSink { f, buf: [0; 256], len: 0, total: 0 } }
    fn flush(&mut self) {
        if self.len > 0 {
            // SAFETY: buf[..len] is initialised; stream_write reads len bytes.
            unsafe { stream_write(self.f, self.buf.as_ptr(), self.len); }
            self.len = 0;
        }
    }
}
impl Sink for StreamSink {
    fn push(&mut self, b: u8) {
        self.buf[self.len] = b; self.len += 1; self.total += 1;
        if self.len == self.buf.len() { self.flush(); }
    }
    fn count(&self) -> usize { self.total }
}

// Sink that decodes the UTF-8 byte stream back into a wchar_t buffer of cap
// wchars (incl. terminator); counts wchars that would be produced (swprintf
// returns the wchar count, -1 on overflow per C99 7.29.2.3).
struct WBufSink { dst: *mut i32, cap: usize, w: usize, pend: [u8; 4], plen: usize, total: usize, overflow: bool }
impl WBufSink {
    fn new(dst: *mut i32, cap: usize) -> Self { WBufSink { dst, cap, w: 0, pend: [0; 4], plen: 0, total: 0, overflow: false } }
    fn emit(&mut self, wc: i32) {
        self.total += 1;
        if self.w + 1 < self.cap {
            // SAFETY: w+1 < cap, so dst[w] is within the caller's wchar buffer.
            unsafe { *self.dst.add(self.w) = wc; }
            self.w += 1;
        } else { self.overflow = true; }
    }
    fn terminate(&self) {
        if self.cap > 0 {
            let idx = self.w.min(self.cap - 1);
            // SAFETY: idx < cap by construction, so dst[idx] is in bounds.
            unsafe { *self.dst.add(idx) = 0; }
        }
    }
}
impl Sink for WBufSink {
    fn push(&mut self, b: u8) {
        self.pend[self.plen] = b; self.plen += 1;
        match decode_utf8(&self.pend[..self.plen]) {
            Ok((cp, _)) => { self.plen = 0; self.emit(cp as i32); }
            Err(-2) if self.plen < 4 => {} // accumulate
            _ => { self.plen = 0; self.emit('\u{FFFD}' as i32); }
        }
    }
    fn count(&self) -> usize { self.total }
}

unsafe fn wprintf_stream(f: *mut FILE, wfmt: *const i32, ap: &mut VaList) -> i32 {
    // SAFETY: wfmt NUL-terminated; ap holds the matching varargs; bytes routed
    // through stream_write (the stream is byte/UTF-8 backed).
    unsafe {
        let nfmt = wfmt_to_narrow(wfmt);
        let mut sink = StreamSink::new(f);
        let mut a = Va(ap);
        fmt::vformat(&mut sink, nfmt.as_ptr(), &mut a);
        sink.flush();
        sink.total as i32
    }
}
unsafe fn wprintf_buf(dst: *mut i32, cap: usize, wfmt: *const i32, ap: &mut VaList) -> i32 {
    // SAFETY: dst writable for cap wchars; wfmt/ap per the C contract.
    unsafe {
        let nfmt = wfmt_to_narrow(wfmt);
        let mut sink = WBufSink::new(dst, cap);
        let mut a = Va(ap);
        fmt::vformat(&mut sink, nfmt.as_ptr(), &mut a);
        sink.terminate();
        if sink.overflow { -1 } else { sink.w as i32 }
    }
}

// # C: int vfwprintf(FILE *f, const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vfwprintf(f: *mut FILE, fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: f is a valid stream; routes through the wide stream formatter.
    unsafe { wprintf_stream(f, fmt, &mut ap) }
}
// # C: int fwprintf(FILE *f, const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn fwprintf(f: *mut FILE, fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: f is a valid stream; ap supplies the named varargs.
    unsafe { wprintf_stream(f, fmt, &mut ap) }
}
// # C: int vwprintf(const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vwprintf(fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: writes to stdout; ap holds the matching varargs.
    unsafe { wprintf_stream(stdout_ptr(), fmt, &mut ap) }
}
// # C: int wprintf(const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn wprintf(fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: writes to stdout; ap supplies the named varargs.
    unsafe { wprintf_stream(stdout_ptr(), fmt, &mut ap) }
}
// # C: int vswprintf(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vswprintf(s: *mut i32, n: usize, fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: s writable for n wchars; wide buffer formatter terminates it.
    unsafe { wprintf_buf(s, n, fmt, &mut ap) }
}
// # C: int swprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn swprintf(s: *mut i32, n: usize, fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: s writable for n wchars; ap supplies the named varargs.
    unsafe { wprintf_buf(s, n, fmt, &mut ap) }
}

// ---- wide scanf ----

// A source of wide chars (a wchar_t string or a FILE decoded as UTF-8) with one
// char of lookahead. peek/bump yield WEOF at end.
trait WSource {
    fn peek(&mut self) -> i32;
    fn bump(&mut self) -> i32;
    fn consumed(&self) -> usize;
    fn finish(&mut self) {}
}
struct WStr { p: *const i32, pos: usize }
impl WSource for WStr {
    fn peek(&mut self) -> i32 {
        // SAFETY: p is a NUL-terminated wide string; pos stops at the NUL.
        let c = unsafe { *self.p.add(self.pos) };
        if c == 0 { WEOF } else { c }
    }
    fn bump(&mut self) -> i32 { let c = self.peek(); if c != WEOF { self.pos += 1; } c }
    fn consumed(&self) -> usize { self.pos }
}
struct WFile { f: *mut FILE, ahead: i32, primed: bool, n: usize }
impl WSource for WFile {
    fn peek(&mut self) -> i32 {
        if !self.primed {
            // SAFETY: f is a valid readable stream; read one wide char ahead.
            self.ahead = unsafe { getwc_raw(self.f) };
            self.primed = true;
        }
        self.ahead
    }
    fn bump(&mut self) -> i32 { let c = self.peek(); if c != WEOF { self.primed = false; self.n += 1; } c }
    fn consumed(&self) -> usize { self.n }
    fn finish(&mut self) {
        if self.primed && self.ahead != WEOF {
            // SAFETY: f is a valid stream; push the unconsumed lookahead char as
            // its UTF-8 bytes (the byte-pushback slot) so the position matches.
            unsafe {
                let (o, len) = encode_utf8(self.ahead as u32);
                for k in (0..len).rev() { set_unget(self.f, o[k]); }
            }
            self.primed = false;
        }
    }
}

struct WArgs<'a, 'b>(&'a mut VaList<'b>);
impl WArgs<'_, '_> {
    unsafe fn ptr(&mut self) -> *mut u8 { unsafe { self.0.next_arg::<*mut c_void>() as *mut u8 } }
}

unsafe fn wscan_str_va(s: *const i32, fmt: *const i32, ap: &mut VaList) -> i32 {
    // SAFETY: s/fmt are NUL-terminated wide strings; ap holds pointer args.
    unsafe {
        let mut src = WStr { p: s, pos: 0 };
        let mut a = WArgs(ap);
        wscan(&mut src, fmt, &mut a)
    }
}

unsafe fn wscan_file_va(f: *mut FILE, fmt: *const i32, ap: &mut VaList) -> i32 {
    // SAFETY: f is a readable stream; fmt NUL-terminated; ap pointer args.
    unsafe {
        let mut src = WFile { f, ahead: WEOF, primed: false, n: 0 };
        let mut a = WArgs(ap);
        let r = wscan(&mut src, fmt, &mut a);
        src.finish();
        r
    }
}

fn is_ws(c: i32) -> bool { matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d) }
fn digit_val(c: i32, base: i64) -> Option<i64> {
    let d = match c { 0x30..=0x39 => c - 0x30, 0x61..=0x7a => c - 0x61 + 10, 0x41..=0x5a => c - 0x41 + 10, _ => return None };
    if (d as i64) < base { Some(d as i64) } else { None }
}

unsafe fn wstore_int(p: *mut u8, len: u8, v: i64) {
    // SAFETY: p is a caller object of the C integer type implied by `len`.
    unsafe {
        match len { 1 => *(p as *mut i8) = v as i8, 2 => *(p as *mut i16) = v as i16, 4 => *(p as *mut i32) = v as i32, _ => *(p as *mut i64) = v }
    }
}

unsafe fn wscan(src: &mut dyn WSource, wfmt: *const i32, args: &mut WArgs) -> i32 {
    // SAFETY: wfmt is a NUL-terminated wide format; args yields one pointer per
    // non-suppressed conversion, each matching the conversion's C type.
    unsafe {
        let mut i = 0usize;
        let mut assigned = 0i32;
        loop {
            let fc = *wfmt.add(i);
            if fc == 0 { break; }
            if is_ws(fc) { while is_ws(src.peek()) { src.bump(); } i += 1; continue; }
            if fc != '%' as i32 {
                if src.peek() != fc { break; }
                src.bump(); i += 1; continue;
            }
            i += 1; // past '%'
            if *wfmt.add(i) == '%' as i32 { while is_ws(src.peek()) { src.bump(); } if src.peek() == '%' as i32 { src.bump(); i += 1; continue; } else { break; } }
            let suppress = *wfmt.add(i) == '*' as i32; if suppress { i += 1; }
            let mut width = 0usize;
            while (0x30..=0x39).contains(&*wfmt.add(i)) { width = width * 10 + (*wfmt.add(i) - 0x30) as usize; i += 1; }
            // length modifier (we only need its size for integers; l/ls/lc → wide)
            let mut ilen: u8 = 4; let mut long_mod = false;
            loop {
                match *wfmt.add(i) as u8 {
                    b'h' => { i += 1; ilen = if *wfmt.add(i) == 'h' as i32 { i += 1; 1 } else { 2 }; }
                    b'l' => { i += 1; long_mod = true; if *wfmt.add(i) == 'l' as i32 { i += 1; } ilen = 8; }
                    b'L' | b'q' => { i += 1; ilen = 8; }
                    b'j' | b'z' | b't' => { i += 1; ilen = 8; }
                    _ => break,
                }
            }
            let conv = *wfmt.add(i) as u8; i += 1;
            let cap = if width == 0 { usize::MAX } else { width };
            let ok = match conv {
                b'n' => { if !suppress { wstore_int(args.ptr(), ilen, src.consumed() as i64); } continue; }
                b'd' | b'i' | b'u' | b'o' | b'x' | b'X' => {
                    let base: i64 = match conv { b'd' | b'u' => 10, b'o' => 8, b'x' | b'X' => 16, _ => 0 };
                    wconv_int(src, args, suppress, cap, ilen, base)
                }
                b'f' | b'e' | b'g' | b'E' | b'G' | b'a' | b'A' => wconv_float(src, args, suppress, cap, ilen),
                b'c' => wconv_char(src, args, suppress, if width == 0 { 1 } else { width }, long_mod),
                b's' => wconv_str(src, args, suppress, cap, long_mod),
                _ => break,
            };
            if !ok { if assigned == 0 && src.peek() == WEOF { src.finish(); return -1; } break; }
            if !suppress { assigned += 1; }
        }
        src.finish();
        assigned
    }
}

unsafe fn wconv_int(src: &mut dyn WSource, args: &mut WArgs, suppress: bool, cap: usize, ilen: u8, mut base: i64) -> bool {
    // SAFETY: stores the parsed value through the next vararg pointer (unless
    // suppressed), matching the C integer type implied by ilen.
    unsafe {
        while is_ws(src.peek()) { src.bump(); }
        let mut taken = 0usize; let mut neg = false;
        if (src.peek() == '+' as i32 || src.peek() == '-' as i32) && taken < cap { neg = src.peek() == '-' as i32; src.bump(); taken += 1; }
        let autodetect = base == 0;
        if autodetect { base = 10; }
        let mut val: i64 = 0; let mut any = false;
        if (base == 16 || autodetect) && taken < cap && src.peek() == '0' as i32 {
            src.bump(); taken += 1; any = true;
            if taken < cap && (src.peek() == 'x' as i32 || src.peek() == 'X' as i32) { src.bump(); taken += 1; any = false; base = 16; }
            else if autodetect { base = 8; }
        }
        while taken < cap { match digit_val(src.peek(), base) { Some(d) => { val = val * base + d; src.bump(); taken += 1; any = true; } None => break } }
        if !any { return false; }
        if !suppress { wstore_int(args.ptr(), ilen, if neg { -val } else { val }); }
        true
    }
}

unsafe fn wconv_float(src: &mut dyn WSource, args: &mut WArgs, suppress: bool, cap: usize, ilen: u8) -> bool {
    // SAFETY: collects a float token (ASCII), parses it, stores f32/f64.
    unsafe {
        while is_ws(src.peek()) { src.bump(); }
        let mut buf = [0u8; 64]; let mut n = 0usize; let mut any = false;
        let mut push = |c: i32, n: &mut usize| { if *n < buf.len() { buf[*n] = c as u8; } *n += 1; };
        if (src.peek() == '+' as i32 || src.peek() == '-' as i32) && n < cap { push(src.bump(), &mut n); }
        while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); any = true; }
        if src.peek() == '.' as i32 && n < cap { push(src.bump(), &mut n); while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); any = true; } }
        if any && (src.peek() == 'e' as i32 || src.peek() == 'E' as i32) && n < cap {
            push(src.bump(), &mut n);
            if (src.peek() == '+' as i32 || src.peek() == '-' as i32) && n < cap { push(src.bump(), &mut n); }
            while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); }
        }
        if !any || n > buf.len() { return false; }
        let s = match core::str::from_utf8(&buf[..n]) { Ok(s) => s, Err(_) => return false };
        let v: f64 = match s.parse() { Ok(v) => v, Err(_) => return false };
        if !suppress { let p = args.ptr(); if ilen >= 8 { *(p as *mut f64) = v; } else { *(p as *mut f32) = v as f32; } }
        true
    }
}

unsafe fn wconv_char(src: &mut dyn WSource, args: &mut WArgs, suppress: bool, cap: usize, wide: bool) -> bool {
    // SAFETY: writes exactly `cap` chars; wide → wchar_t store, else a UTF-8
    // byte store (each scalar value here is in the multibyte source).
    unsafe {
        if src.peek() == WEOF { return false; }
        let dst = if suppress { core::ptr::null_mut() } else { args.ptr() };
        let mut n = 0usize;
        while n < cap && src.peek() != WEOF {
            let c = src.bump();
            if !suppress {
                if wide { *(dst as *mut i32).add(n) = c; }
                else { let (o, len) = encode_utf8(c as u32); core::ptr::copy_nonoverlapping(o.as_ptr(), dst.add(n), len); }
            }
            n += 1;
        }
        n == cap
    }
}

unsafe fn wconv_str(src: &mut dyn WSource, args: &mut WArgs, suppress: bool, cap: usize, wide: bool) -> bool {
    // SAFETY: writes the whitespace-delimited token + NUL into the caller buffer
    // (wchar_t* when wide, else UTF-8 char*).
    unsafe {
        while is_ws(src.peek()) { src.bump(); }
        if src.peek() == WEOF || is_ws(src.peek()) { return false; }
        let dst = if suppress { core::ptr::null_mut() } else { args.ptr() };
        let mut n = 0usize; // wchars consumed
        let mut boff = 0usize; // byte offset for narrow store
        while n < cap && src.peek() != WEOF && !is_ws(src.peek()) {
            let c = src.bump();
            if !suppress {
                if wide { *(dst as *mut i32).add(n) = c; }
                else { let (o, len) = encode_utf8(c as u32); core::ptr::copy_nonoverlapping(o.as_ptr(), dst.add(boff), len); boff += len; }
            }
            n += 1;
        }
        if n == 0 { return false; }
        if !suppress { if wide { *(dst as *mut i32).add(n) = 0; } else { *dst.add(boff) = 0; } }
        true
    }
}

// # C: int vswscanf(const wchar_t *s, const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vswscanf(s: *const i32, fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: s/fmt are NUL-terminated wide strings; ap holds pointer args.
    unsafe { wscan_str_va(s, fmt, &mut ap) }
}
// # C: int swscanf(const wchar_t *s, const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn swscanf(s: *const i32, fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: s/fmt NUL-terminated wide strings; ap supplies the pointer args.
    unsafe { wscan_str_va(s, fmt, &mut ap) }
}
// # C: int vfwscanf(FILE *f, const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vfwscanf(f: *mut FILE, fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: f is a readable stream; fmt NUL-terminated; ap pointer args.
    unsafe { wscan_file_va(f, fmt, &mut ap) }
}
// # C: int fwscanf(FILE *f, const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn fwscanf(f: *mut FILE, fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: f is a readable stream; ap supplies the pointer args.
    unsafe { wscan_file_va(f, fmt, &mut ap) }
}
// # C: int vwscanf(const wchar_t *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vwscanf(fmt: *const i32, mut ap: VaList) -> i32 {
    // SAFETY: reads from stdin; fmt NUL-terminated; ap pointer args.
    unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
}
// # C: int wscanf(const wchar_t *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn wscanf(fmt: *const i32, mut ap: ...) -> i32 {
    // SAFETY: reads from stdin; ap supplies the pointer args.
    unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
}

// glibc 2.38+ headers redirect the wide scanf family to __isoc23_* (older to
// __isoc99_*). Same contract; provide both aliases for each entry point.
macro_rules! isoc_swscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *s, const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(s: *const i32, fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: s/fmt NUL-terminated wide strings; ap supplies pointer args.
            unsafe { wscan_str_va(s, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_fwscanf {
    ($name:ident) => {
        /// # C: int $name(FILE *f, const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(f: *mut FILE, fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: f is a readable stream; ap supplies the pointer args.
            unsafe { wscan_file_va(f, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_wscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *fmt, ...)
        #[no_mangle]
        pub unsafe extern "C" fn $name(fmt: *const i32, mut ap: ...) -> i32 {
            // SAFETY: reads from stdin; ap supplies the pointer args.
            unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vswscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *s, const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(s: *const i32, fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract as vswscanf.
            unsafe { wscan_str_va(s, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vfwscanf {
    ($name:ident) => {
        /// # C: int $name(FILE *f, const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(f: *mut FILE, fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract as vfwscanf.
            unsafe { wscan_file_va(f, fmt, &mut ap) }
        }
    };
}
macro_rules! isoc_vwscanf {
    ($name:ident) => {
        /// # C: int $name(const wchar_t *fmt, va_list ap)
        #[no_mangle]
        pub unsafe extern "C" fn $name(fmt: *const i32, mut ap: VaList) -> i32 {
            // SAFETY: same ABI contract and va_list layout as vwscanf.
            unsafe { wscan_file_va(stdin_ptr(), fmt, &mut ap) }
        }
    };
}
isoc_swscanf!(__isoc23_swscanf);
isoc_swscanf!(__isoc99_swscanf);
isoc_fwscanf!(__isoc23_fwscanf);
isoc_fwscanf!(__isoc99_fwscanf);
isoc_wscanf!(__isoc23_wscanf);
isoc_wscanf!(__isoc99_wscanf);
isoc_vswscanf!(__isoc23_vswscanf);
isoc_vswscanf!(__isoc99_vswscanf);
isoc_vfwscanf!(__isoc23_vfwscanf);
isoc_vfwscanf!(__isoc99_vfwscanf);
isoc_vwscanf!(__isoc23_vwscanf);
isoc_vwscanf!(__isoc99_vwscanf);
