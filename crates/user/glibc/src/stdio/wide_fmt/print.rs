use super::*;
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

