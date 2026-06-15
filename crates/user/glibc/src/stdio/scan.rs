// scanf format engine (docs/59§6 G6). Reads from a `Source` (a string for
// sscanf, a FILE for fscanf/scanf — G6c) and stores into vararg pointers
// via `ScanArgs`. Conversions d/i/u/o/x/c/s/f(+e/g) with width, '*'
// suppression and length modifiers; whitespace in the format matches a
// run of input whitespace, other literals must match. Scanset %[ and %n
// are a follow-up. Differentially tested vs host sscanf.

pub(crate) trait Source {
    fn peek(&mut self) -> i32; // current byte or -1 at end (may read for FILE)
    fn bump(&mut self) -> i32; // consume + return it, or -1
    fn consumed(&self) -> usize;
}

pub(crate) trait ScanArgs {
    // next destination pointer (skipped for '*' suppression).
    unsafe fn next_ptr(&mut self) -> *mut u8;
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Len { Char, Short, Int, Long, LongLong, Size, IntMax }

pub(crate) struct StrSource { p: *const u8, pos: usize }
impl StrSource {
    /// # C: wrap a NUL-terminated C string as a scanf input source
    pub(crate) fn new(p: *const u8) -> Self { StrSource { p, pos: 0 } }
}
impl Source for StrSource {
    fn peek(&mut self) -> i32 {
        // SAFETY: p is a NUL-terminated C string; pos stops at the NUL.
        let b = unsafe { *self.p.add(self.pos) };
        if b == 0 { -1 } else { b as i32 }
    }
    fn bump(&mut self) -> i32 { let c = self.peek(); if c >= 0 { self.pos += 1; } c }
    fn consumed(&self) -> usize { self.pos }
}

fn is_ws(c: i32) -> bool { matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d) }
fn skip_ws(src: &mut dyn Source) { while is_ws(src.peek()) { src.bump(); } }
fn digit_val(c: i32, base: i64) -> Option<i64> {
    let d = match c { 0x30..=0x39 => c - 0x30, 0x61..=0x7a => c - 0x61 + 10, 0x41..=0x5a => c - 0x41 + 10, _ => return None };
    if (d as i64) < base { Some(d as i64) } else { None }
}

unsafe fn store_int(ptr: *mut u8, len: Len, v: i64) {
    // SAFETY: ptr is a caller-supplied object of the C type implied by len.
    unsafe {
        match len {
            Len::Char => *(ptr as *mut i8) = v as i8,
            Len::Short => *(ptr as *mut i16) = v as i16,
            Len::Int => *(ptr as *mut i32) = v as i32,
            _ => *(ptr as *mut i64) = v,
        }
    }
}

// parse an integer conversion; returns true if a value was assigned.
unsafe fn conv_int(src: &mut dyn Source, args: &mut dyn ScanArgs, suppress: bool, width: usize, len: Len, mut base: i64, signed: bool) -> bool {
    // SAFETY: on success we store through the next vararg pointer (unless
    // suppressed); the pointer matches the C type per `len`.
    unsafe {
        skip_ws(src);
        let mut taken = 0usize;
        let cap = if width == 0 { usize::MAX } else { width };
        let mut neg = false;
        if (src.peek() == b'+' as i32 || src.peek() == b'-' as i32) && taken < cap {
            neg = src.peek() == b'-' as i32; src.bump(); taken += 1;
        }
        // base autodetect for %i / 0x / 0
        if base == 0 {
            base = 10;
            if src.peek() == b'0' as i32 {
                // tentatively consume the 0
                if taken < cap { src.bump(); taken += 1; }
                if (src.peek() == b'x' as i32 || src.peek() == b'X' as i32) && taken < cap {
                    src.bump(); taken += 1; base = 16;
                } else { base = 8; /* already consumed a leading 0 = valid digit */ }
                // the consumed '0' counts as a digit for octal/zero value
                let mut val: i64 = 0; let mut any = base == 8; // the leading 0 is a digit
                while taken < cap { match digit_val(src.peek(), base) { Some(d) => { val = val * base + d; src.bump(); taken += 1; any = true; } None => break } }
                if !any { return false; }
                if !suppress { store_int(args.next_ptr(), len, if neg { -val } else { val }); }
                return true;
            }
        }
        let mut val: i64 = 0; let mut any = false;
        // base 16 accepts an optional "0x"/"0X" prefix (the leading 0 is itself
        // a valid hex digit, so "0" alone still matches).
        if base == 16 && taken < cap && src.peek() == b'0' as i32 {
            src.bump(); taken += 1; any = true;
            if taken < cap && (src.peek() == b'x' as i32 || src.peek() == b'X' as i32) {
                src.bump(); taken += 1; any = false; // require ≥1 hex digit after 0x
            }
        }
        while taken < cap { match digit_val(src.peek(), base) { Some(d) => { val = val * base + d; src.bump(); taken += 1; any = true; } None => break } }
        if !any { return false; }
        let _ = signed;
        if !suppress { store_int(args.next_ptr(), len, if neg { -val } else { val }); }
        true
    }
}

unsafe fn conv_str(src: &mut dyn Source, args: &mut dyn ScanArgs, suppress: bool, width: usize) -> bool {
    // SAFETY: on success we write the token + NUL into the caller's buffer.
    unsafe {
        skip_ws(src);
        if src.peek() < 0 || is_ws(src.peek()) { return false; }
        let cap = if width == 0 { usize::MAX } else { width };
        let dst = if suppress { core::ptr::null_mut() } else { args.next_ptr() };
        let mut n = 0usize;
        while n < cap && src.peek() >= 0 && !is_ws(src.peek()) {
            let c = src.bump() as u8;
            if !suppress { *dst.add(n) = c; }
            n += 1;
        }
        if n == 0 { return false; }
        if !suppress { *dst.add(n) = 0; }
        true
    }
}

// %[...]: read the longest run of chars in (or, for %[^...], not in) `set`,
// up to `width`. Unlike %s it does NOT skip leading whitespace. Fails (returns
// false) if zero chars match, per C.
unsafe fn conv_scanset(src: &mut dyn Source, args: &mut dyn ScanArgs, suppress: bool, width: usize, set: &[bool; 256], negate: bool) -> bool {
    // SAFETY: on success we write the matched run + NUL into the caller's buffer.
    unsafe {
        let cap = if width == 0 { usize::MAX } else { width };
        let dst = if suppress { core::ptr::null_mut() } else { args.next_ptr() };
        let mut n = 0usize;
        while n < cap {
            let c = src.peek();
            if c < 0 || set[c as usize] == negate { break; }
            src.bump();
            if !suppress { *dst.add(n) = c as u8; }
            n += 1;
        }
        if n == 0 { return false; }
        if !suppress { *dst.add(n) = 0; }
        true
    }
}

unsafe fn conv_char(src: &mut dyn Source, args: &mut dyn ScanArgs, suppress: bool, width: usize) -> bool {
    // SAFETY: writes exactly `width` (default 1) raw bytes; no NUL added.
    unsafe {
        let cap = if width == 0 { 1 } else { width };
        if src.peek() < 0 { return false; }
        let dst = if suppress { core::ptr::null_mut() } else { args.next_ptr() };
        let mut n = 0usize;
        while n < cap && src.peek() >= 0 { let c = src.bump() as u8; if !suppress { *dst.add(n) = c; } n += 1; }
        n == cap
    }
}

unsafe fn conv_float(src: &mut dyn Source, args: &mut dyn ScanArgs, suppress: bool, width: usize, is_double: bool) -> bool {
    // SAFETY: collects a float token, parses it, stores f32/f64 per length.
    unsafe {
        skip_ws(src);
        let cap = if width == 0 { usize::MAX } else { width };
        let mut buf = [0u8; 64]; let mut n = 0usize;
        let mut push = |c: i32, n: &mut usize| { if *n < buf.len() { buf[*n] = c as u8; } *n += 1; };
        if (src.peek() == b'+' as i32 || src.peek() == b'-' as i32) && n < cap { push(src.bump(), &mut n); }
        let mut any = false;
        while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); any = true; }
        if src.peek() == b'.' as i32 && n < cap { push(src.bump(), &mut n);
            while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); any = true; } }
        if any && (src.peek() == b'e' as i32 || src.peek() == b'E' as i32) && n < cap {
            push(src.bump(), &mut n);
            if (src.peek() == b'+' as i32 || src.peek() == b'-' as i32) && n < cap { push(src.bump(), &mut n); }
            while n < cap && (0x30..=0x39).contains(&src.peek()) { push(src.bump(), &mut n); }
        }
        if !any || n > buf.len() { return false; }
        let s = match core::str::from_utf8(&buf[..n]) { Ok(s) => s, Err(_) => return false };
        let v: f64 = match s.parse() { Ok(v) => v, Err(_) => return false };
        if !suppress { let p = args.next_ptr(); if is_double { *(p as *mut f64) = v; } else { *(p as *mut f32) = v as f32; } }
        true
    }
}

pub(crate) unsafe fn vscan(src: &mut dyn Source, fmt: *const u8, args: &mut dyn ScanArgs) -> i32 {
    // SAFETY: fmt is NUL-terminated; args yields one pointer per
    // non-suppressed conversion, each matching the conversion's C type.
    unsafe {
        let mut i = 0usize;
        let mut assigned = 0i32;
        loop {
            let fc = *fmt.add(i);
            if fc == 0 { break; }
            if is_ws(fc as i32) { skip_ws(src); i += 1; continue; }
            if fc != b'%' { // literal must match
                let c = src.peek();
                if c != fc as i32 { break; }
                src.bump(); i += 1; continue;
            }
            i += 1; // past '%'
            if *fmt.add(i) == b'%' { skip_ws(src); if src.peek() == b'%' as i32 { src.bump(); i += 1; continue; } else { break; } }
            let suppress = *fmt.add(i) == b'*'; if suppress { i += 1; }
            let mut width = 0usize;
            while (*fmt.add(i)).is_ascii_digit() { width = width * 10 + (*fmt.add(i) - b'0') as usize; i += 1; }
            let len = match *fmt.add(i) {
                b'h' => { i += 1; if *fmt.add(i) == b'h' { i += 1; Len::Char } else { Len::Short } }
                b'l' => { i += 1; if *fmt.add(i) == b'l' { i += 1; Len::LongLong } else { Len::Long } }
                b'z' => { i += 1; Len::Size } b'j' => { i += 1; Len::IntMax } b'L' => { i += 1; Len::LongLong }
                _ => Len::Int,
            };
            let conv = *fmt.add(i); i += 1;
            let ok = match conv {
                b'd' => conv_int(src, args, suppress, width, len, 10, true),
                b'i' => conv_int(src, args, suppress, width, len, 0, true),
                b'u' => conv_int(src, args, suppress, width, len, 10, false),
                b'o' => conv_int(src, args, suppress, width, len, 8, false),
                b'x' | b'X' => conv_int(src, args, suppress, width, len, 16, false),
                b's' => conv_str(src, args, suppress, width),
                b'c' => conv_char(src, args, suppress, width),
                b'f' | b'e' | b'g' | b'E' | b'G' => conv_float(src, args, suppress, width, matches!(len, Len::Long | Len::LongLong)),
                b'[' => {
                    // parse the scanset from the format: optional leading '^'
                    // (negate); a ']' right after '['/'^' is a literal member.
                    let mut negate = false;
                    if *fmt.add(i) == b'^' { negate = true; i += 1; }
                    let mut set = [false; 256];
                    let mut first = true;
                    let mut prev: i32 = -1; // last literal char, for a-z range syntax
                    loop {
                        let ch = *fmt.add(i);
                        if ch == 0 { break; }
                        if ch == b']' && !first { i += 1; break; }
                        let next = *fmt.add(i + 1);
                        if ch == b'-' && prev >= 0 && next != b']' && next != 0 {
                            let mut c = prev as u16; // inclusive range prev..=next
                            while c <= next as u16 { set[c as usize] = true; c += 1; }
                            prev = -1; first = false; i += 2; continue;
                        }
                        set[ch as usize] = true; prev = ch as i32; first = false; i += 1;
                    }
                    conv_scanset(src, args, suppress, width, &set, negate)
                }
                _ => break,
            };
            if !ok { if assigned == 0 && src.peek() < 0 { return -1; } break; }
            if !suppress { assigned += 1; }
        }
        assigned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String, vec::Vec};

    struct PtrArgs { ptrs: Vec<*mut u8>, i: usize }
    impl ScanArgs for PtrArgs { unsafe fn next_ptr(&mut self) -> *mut u8 { let p = self.ptrs[self.i]; self.i += 1; p } }

    fn ours_int(input: &str, fmt: &str) -> (i32, i64) {
        let cin = format!("{input}\0");
        let cf = format!("{fmt}\0");
        let mut out: i64 = 0;
        let mut src = StrSource::new(cin.as_ptr());
        let mut args = PtrArgs { ptrs: alloc::vec![&mut out as *mut i64 as *mut u8], i: 0 };
        // SAFETY: cin/cf NUL-terminated; out matches a %ld-sized store.
        let n = unsafe { vscan(&mut src, cf.as_ptr(), &mut args) };
        (n, out)
    }
    fn host_int(input: &str, fmt: &str) -> (i32, i64) {
        let cin = format!("{input}\0"); let cf = format!("{fmt}\0");
        let mut out: i64 = 0;
        // SAFETY: NUL-terminated; %ld matches a long* (i64) destination.
        let n = unsafe { libc::sscanf(cin.as_ptr() as *const _, cf.as_ptr() as *const _, &mut out as *mut i64) };
        (n, out)
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn dec_matches(v in any::<i32>(), pad in 0usize..3) {
            let sp: String = core::iter::repeat(' ').take(pad).collect();
            let input = format!("{sp}{v}");
            prop_assert_eq!(ours_int(&input, "%ld"), host_int(&input, "%ld"), "in={:?}", input);
        }
        #[test]
        fn hex_matches(v in 0u32..=0xffffff) {
            let input = format!("{:x}", v);
            prop_assert_eq!(ours_int(&input, "%lx"), host_int(&input, "%lx"), "in={:?}", input);
        }
        #[test]
        fn two_fields(a in -1000i32..1000, b in -1000i32..1000) {
            let input = format!("{a} {b}");
            let cin = format!("{input}\0");
            let (mut x, mut y): (i64, i64) = (0, 0);
            let mut src = StrSource::new(cin.as_ptr());
            let mut args = PtrArgs { ptrs: alloc::vec![&mut x as *mut i64 as *mut u8, &mut y as *mut i64 as *mut u8], i: 0 };
            // SAFETY: two long* destinations match "%ld %ld".
            let n = unsafe { vscan(&mut src, b"%ld %ld\0".as_ptr(), &mut args) };
            prop_assert_eq!((n, x, y), (2, a as i64, b as i64));
        }
    }
}
