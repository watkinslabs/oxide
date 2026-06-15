// locale/iconv — charset conversion (docs/59§6 G16d). Pure per-charset
// decode(bytes->codepoint) / encode(codepoint->bytes) over a common u32 scalar
// pivot; convert() drives the loop with iconv's E2BIG/EILSEQ/EINVAL semantics.
// Supported: UTF-8, UTF-16/32 LE+BE, UCS-2 LE+BE, UCS-4, LATIN1/ISO-8859-1,
// ASCII. The UTF-8 leg reuses locale/wchar. Pure logic hosted-tested vs Rust
// core (encode_utf16, to/from byte arrays); the iconv_* C ABI wraps it.
use super::wchar::{decode_utf8, encode_utf8};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charset { Utf8, Utf16Le, Utf16Be, Utf32Le, Utf32Be, Ucs2Le, Ucs2Be, Latin1, Ascii }

pub(crate) const F_TRANSLIT: u8 = 1;
pub(crate) const F_IGNORE: u8 = 2;

// per-step results
enum Dec { Cp(u32, usize), Incomplete, Invalid }
enum Enc { Wrote(usize), TooBig, Unrep }

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum Status { Ok, E2big, Eilseq, Einval }

pub(crate) struct Conv { pub in_used: usize, pub out_used: usize, pub nonrev: usize, pub status: Status }

fn rd16(b: &[u8], le: bool) -> u16 { if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) } }
fn rd32(b: &[u8], le: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
}
fn is_surrogate(cp: u32) -> bool { (0xD800..=0xDFFF).contains(&cp) }

/// Decode one codepoint of `cs` from the front of `b`.
/// # C: per-charset multibyte decode to a Unicode scalar
fn decode_one(cs: Charset, b: &[u8]) -> Dec {
    match cs {
        Charset::Utf8 => match decode_utf8(b) {
            Ok((cp, n)) => Dec::Cp(cp, n),
            Err(-2) => Dec::Incomplete,
            _ => Dec::Invalid,
        },
        Charset::Utf16Le | Charset::Utf16Be => {
            let le = cs == Charset::Utf16Le;
            if b.len() < 2 { return Dec::Incomplete; }
            let w = rd16(b, le);
            if (0xD800..=0xDBFF).contains(&w) {
                if b.len() < 4 { return Dec::Incomplete; }
                let w2 = rd16(&b[2..], le);
                if !(0xDC00..=0xDFFF).contains(&w2) { return Dec::Invalid; }
                let cp = 0x10000 + (((w - 0xD800) as u32) << 10) + (w2 - 0xDC00) as u32;
                Dec::Cp(cp, 4)
            } else if (0xDC00..=0xDFFF).contains(&w) { Dec::Invalid } else { Dec::Cp(w as u32, 2) }
        }
        Charset::Ucs2Le | Charset::Ucs2Be => {
            let le = cs == Charset::Ucs2Le;
            if b.len() < 2 { return Dec::Incomplete; }
            let w = rd16(b, le) as u32;
            if is_surrogate(w) { Dec::Invalid } else { Dec::Cp(w, 2) }
        }
        Charset::Utf32Le | Charset::Utf32Be => {
            let le = cs == Charset::Utf32Le;
            if b.len() < 4 { return Dec::Incomplete; }
            let cp = rd32(b, le);
            if cp > 0x10FFFF || is_surrogate(cp) { Dec::Invalid } else { Dec::Cp(cp, 4) }
        }
        Charset::Latin1 => { if b.is_empty() { Dec::Incomplete } else { Dec::Cp(b[0] as u32, 1) } }
        Charset::Ascii => {
            if b.is_empty() { Dec::Incomplete } else if b[0] < 0x80 { Dec::Cp(b[0] as u32, 1) } else { Dec::Invalid }
        }
    }
}

/// Encode scalar `cp` (a valid Unicode scalar) into `out` as `cs`.
/// # C: per-charset encode of a Unicode scalar
fn encode_one(cs: Charset, cp: u32, out: &mut [u8]) -> Enc {
    match cs {
        Charset::Utf8 => {
            let (o, n) = encode_utf8(cp);
            if out.len() < n { return Enc::TooBig; }
            out[..n].copy_from_slice(&o[..n]);
            Enc::Wrote(n)
        }
        Charset::Utf16Le | Charset::Utf16Be => {
            let le = cs == Charset::Utf16Le;
            if cp <= 0xFFFF {
                if out.len() < 2 { return Enc::TooBig; }
                let w = (cp as u16).to_le_bytes();
                let w = if le { w } else { (cp as u16).to_be_bytes() };
                out[..2].copy_from_slice(&w);
                Enc::Wrote(2)
            } else {
                if out.len() < 4 { return Enc::TooBig; }
                let v = cp - 0x10000;
                let hi = 0xD800 + (v >> 10) as u16;
                let lo = 0xDC00 + (v & 0x3FF) as u16;
                let (a, b) = if le { (hi.to_le_bytes(), lo.to_le_bytes()) } else { (hi.to_be_bytes(), lo.to_be_bytes()) };
                out[..2].copy_from_slice(&a);
                out[2..4].copy_from_slice(&b);
                Enc::Wrote(4)
            }
        }
        Charset::Ucs2Le | Charset::Ucs2Be => {
            if cp > 0xFFFF { return Enc::Unrep; }
            if out.len() < 2 { return Enc::TooBig; }
            let le = cs == Charset::Ucs2Le;
            let w = if le { (cp as u16).to_le_bytes() } else { (cp as u16).to_be_bytes() };
            out[..2].copy_from_slice(&w);
            Enc::Wrote(2)
        }
        Charset::Utf32Le | Charset::Utf32Be => {
            if out.len() < 4 { return Enc::TooBig; }
            let le = cs == Charset::Utf32Le;
            let w = if le { cp.to_le_bytes() } else { cp.to_be_bytes() };
            out[..4].copy_from_slice(&w);
            Enc::Wrote(4)
        }
        Charset::Latin1 => {
            if cp > 0xFF { return Enc::Unrep; }
            if out.is_empty() { return Enc::TooBig; }
            out[0] = cp as u8;
            Enc::Wrote(1)
        }
        Charset::Ascii => {
            if cp > 0x7F { return Enc::Unrep; }
            if out.is_empty() { return Enc::TooBig; }
            out[0] = cp as u8;
            Enc::Wrote(1)
        }
    }
}

/// Convert `inp` (charset `from`) into `out` (charset `to`); pure, no errno.
/// # C: iconv() inner loop — returns bytes used/written, non-reversible count, status
pub(crate) fn convert(from: Charset, to: Charset, flags: u8, inp: &[u8], out: &mut [u8]) -> Conv {
    let mut i = 0;
    let mut o = 0;
    let mut nonrev = 0;
    while i < inp.len() {
        let (cp, n) = match decode_one(from, &inp[i..]) {
            Dec::Cp(cp, n) => (cp, n),
            Dec::Incomplete => return Conv { in_used: i, out_used: o, nonrev, status: Status::Einval },
            Dec::Invalid => return Conv { in_used: i, out_used: o, nonrev, status: Status::Eilseq },
        };
        match encode_one(to, cp, &mut out[o..]) {
            Enc::Wrote(m) => { o += m; i += n; }
            Enc::TooBig => return Conv { in_used: i, out_used: o, nonrev, status: Status::E2big },
            Enc::Unrep => {
                if flags & F_IGNORE != 0 { i += n; nonrev += 1; continue; }
                if flags & F_TRANSLIT != 0 {
                    match encode_one(to, b'?' as u32, &mut out[o..]) {
                        Enc::Wrote(m) => { o += m; i += n; nonrev += 1; continue; }
                        Enc::TooBig => return Conv { in_used: i, out_used: o, nonrev, status: Status::E2big },
                        Enc::Unrep => return Conv { in_used: i, out_used: o, nonrev, status: Status::Eilseq },
                    }
                }
                return Conv { in_used: i, out_used: o, nonrev, status: Status::Eilseq };
            }
        }
    }
    Conv { in_used: i, out_used: o, nonrev, status: Status::Ok }
}

/// Parse an iconv charset name (case-insensitive), peeling //TRANSLIT,//IGNORE.
/// # C: maps an iconv_open code string to (Charset, flags)
pub(crate) fn parse_charset(name: &[u8]) -> Option<(Charset, u8)> {
    // uppercase into a stack buffer, split flags at the first "//"
    let mut buf = [0u8; 40];
    let mut n = 0;
    let mut flags = 0u8;
    let mut k = 0;
    while k < name.len() {
        if k + 1 < name.len() && name[k] == b'/' && name[k + 1] == b'/' {
            let suf = &name[k + 2..];
            if suf_eq(suf, b"TRANSLIT") { flags |= F_TRANSLIT; }
            else if suf_eq(suf, b"IGNORE") { flags |= F_IGNORE; }
            else if suf_eq(suf, b"TRANSLIT//IGNORE") || suf_eq(suf, b"IGNORE//TRANSLIT") { flags |= F_TRANSLIT | F_IGNORE; }
            break;
        }
        if n >= buf.len() { return None; }
        buf[n] = name[k].to_ascii_uppercase();
        n += 1;
        k += 1;
    }
    let cs = match &buf[..n] {
        b"UTF-8" | b"UTF8" => Charset::Utf8,
        b"UTF-16LE" | b"UTF16LE" => Charset::Utf16Le,
        b"UTF-16BE" | b"UTF16BE" => Charset::Utf16Be,
        b"UTF-16" | b"UTF16" => Charset::Utf16Le, // no-BOM host LE
        b"UTF-32LE" | b"UTF32LE" | b"UCS-4LE" | b"UCS4LE" => Charset::Utf32Le,
        b"UTF-32BE" | b"UTF32BE" | b"UCS-4BE" | b"UCS4BE" => Charset::Utf32Be,
        b"UTF-32" | b"UTF32" | b"UCS-4" | b"UCS4" => Charset::Utf32Le,
        b"UCS-2LE" | b"UCS2LE" | b"UCS-2" | b"UCS2" => Charset::Ucs2Le,
        b"UCS-2BE" | b"UCS2BE" => Charset::Ucs2Be,
        b"LATIN1" | b"ISO-8859-1" | b"ISO8859-1" | b"L1" | b"CP819" => Charset::Latin1,
        b"ASCII" | b"US-ASCII" | b"ANSI_X3.4-1968" | b"ANSI_X3.4" => Charset::Ascii,
        _ => return None,
    };
    Some((cs, flags))
}

fn suf_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == *y)
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::internal::errno;

    const EILSEQ: i32 = 84;
    const EINVAL: i32 = 22;
    const E2BIG: i32 = 7;

    // iconv_t = a non-null, non-(-1) packed handle: bit24 marker | flags<<16 | to<<8 | from.
    const MARK: usize = 1 << 24;
    fn pack(from: Charset, to: Charset, flags: u8) -> usize { MARK | ((flags as usize) << 16) | ((to as u8 as usize) << 8) | (from as u8 as usize) }
    fn unpack(h: usize) -> Option<(Charset, Charset, u8)> {
        if h & MARK == 0 { return None; }
        Some((id_cs((h & 0xFF) as u8)?, id_cs(((h >> 8) & 0xFF) as u8)?, ((h >> 16) & 0xFF) as u8))
    }
    fn id_cs(i: u8) -> Option<Charset> {
        Some(match i {
            0 => Charset::Utf8, 1 => Charset::Utf16Le, 2 => Charset::Utf16Be, 3 => Charset::Utf32Le,
            4 => Charset::Utf32Be, 5 => Charset::Ucs2Le, 6 => Charset::Ucs2Be, 7 => Charset::Latin1,
            8 => Charset::Ascii, _ => return None,
        })
    }

    // # C: iconv_t iconv_open(const char *tocode, const char *fromcode)
    #[no_mangle]
    pub unsafe extern "C" fn iconv_open(tocode: *const u8, fromcode: *const u8) -> *mut core::ffi::c_void {
        // SAFETY: tocode/fromcode are NUL-terminated charset names; read each
        // as a byte slice and parse. Returns (iconv_t)-1 on an unknown name.
        unsafe {
            let err = usize::MAX as *mut core::ffi::c_void; // (iconv_t)-1
            let (to, tf) = match parse_charset(cstr(tocode)) { Some(v) => v, None => { errno::set(EINVAL); return err; } };
            let (from, _) = match parse_charset(cstr(fromcode)) { Some(v) => v, None => { errno::set(EINVAL); return err; } };
            pack(from, to, tf) as *mut core::ffi::c_void
        }
    }

    // # C: int iconv_close(iconv_t cd)
    #[no_mangle]
    pub extern "C" fn iconv_close(_cd: *mut core::ffi::c_void) -> i32 { 0 }

    // # C: size_t iconv(iconv_t, char **in, size_t *inleft, char **out, size_t *outleft)
    #[no_mangle]
    pub unsafe extern "C" fn iconv(cd: *mut core::ffi::c_void, inbuf: *mut *mut u8, inleft: *mut usize, outbuf: *mut *mut u8, outleft: *mut usize) -> usize {
        // SAFETY: cd is a handle from iconv_open; inbuf/outbuf (when non-null)
        // point to caller buffers of *inleft / *outleft bytes; on success the
        // pointers and counts are advanced by the bytes consumed/produced.
        unsafe {
            let (from, to, flags) = match unpack(cd as usize) { Some(v) => v, None => { errno::set(EINVAL); return usize::MAX; } };
            if inbuf.is_null() || (*inbuf).is_null() { return 0; } // reset (stateless)
            let inp = core::slice::from_raw_parts(*inbuf, *inleft);
            let out = core::slice::from_raw_parts_mut(*outbuf, *outleft);
            let r = convert(from, to, flags, inp, out);
            *inbuf = (*inbuf).add(r.in_used);
            *inleft -= r.in_used;
            *outbuf = (*outbuf).add(r.out_used);
            *outleft -= r.out_used;
            match r.status {
                Status::Ok => r.nonrev,
                Status::E2big => { errno::set(E2BIG); usize::MAX }
                Status::Eilseq => { errno::set(EILSEQ); usize::MAX }
                Status::Einval => { errno::set(EINVAL); usize::MAX }
            }
        }
    }

    unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
        // SAFETY: p is a NUL-terminated C string; scan to the terminator and
        // return the bytes before it as a slice borrowing the caller's memory.
        unsafe {
            if p.is_null() { return &[]; }
            let mut n = 0;
            while *p.add(n) != 0 { n += 1; }
            core::slice::from_raw_parts(p, n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use alloc::{vec, vec::Vec};

    fn conv(from: Charset, to: Charset, inp: &[u8]) -> (Vec<u8>, Status, usize) {
        let mut out = [0u8; 256];
        let r = convert(from, to, 0, inp, &mut out);
        (out[..r.out_used].to_vec(), r.status, r.in_used)
    }

    proptest! {
        #[test]
        fn utf8_utf32_roundtrip(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some());
            let mut u8buf = [0u8; 4];
            let s = char::from_u32(cp).unwrap().encode_utf8(&mut u8buf);
            // UTF-8 -> UTF-32LE -> UTF-8 round-trips losslessly
            let (u32le, st1, _) = conv(Charset::Utf8, Charset::Utf32Le, s.as_bytes());
            prop_assert_eq!(st1, Status::Ok);
            prop_assert_eq!(&u32le, &cp.to_le_bytes());
            let (back, st2, _) = conv(Charset::Utf32Le, Charset::Utf8, &u32le);
            prop_assert_eq!(st2, Status::Ok);
            prop_assert_eq!(&back, s.as_bytes());
        }

        #[test]
        fn utf8_utf16_roundtrip(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some());
            let c = char::from_u32(cp).unwrap();
            let mut u8buf = [0u8; 4];
            let s = c.encode_utf8(&mut u8buf);
            let (u16le, st, _) = conv(Charset::Utf8, Charset::Utf16Le, s.as_bytes());
            prop_assert_eq!(st, Status::Ok);
            // oracle: core's encode_utf16 (LE units -> LE bytes)
            let mut units = [0u16; 2];
            let enc = c.encode_utf16(&mut units);
            let want: Vec<u8> = enc.iter().flat_map(|w| w.to_le_bytes()).collect();
            prop_assert_eq!(&u16le, &want);
            let (back, st2, _) = conv(Charset::Utf16Le, Charset::Utf8, &u16le);
            prop_assert_eq!(st2, Status::Ok);
            prop_assert_eq!(&back, s.as_bytes());
        }

        #[test]
        fn latin1_roundtrip(b in 0u8..=255) {
            // LATIN1 byte b == codepoint b; UTF-8 -> LATIN1 round-trips for cp<256
            let cp = b as u32;
            let mut u8buf = [0u8; 4];
            let s = char::from_u32(cp).unwrap().encode_utf8(&mut u8buf);
            let (l1, st, _) = conv(Charset::Utf8, Charset::Latin1, s.as_bytes());
            prop_assert_eq!(st, Status::Ok);
            prop_assert_eq!(l1.as_slice(), &[b]);
        }
    }

    #[test]
    fn known_vectors() {
        // € U+20AC
        let eur = "€".as_bytes();
        assert_eq!(conv(Charset::Utf8, Charset::Utf16Le, eur).0, vec![0xAC, 0x20]);
        assert_eq!(conv(Charset::Utf8, Charset::Utf32Le, eur).0, vec![0xAC, 0x20, 0x00, 0x00]);
        // € not representable in LATIN1
        assert_eq!(conv(Charset::Utf8, Charset::Latin1, eur).1, Status::Eilseq);
        // 𝄞 U+1D11E surrogate pair, UTF-16LE [34 D8 1E DD]
        let clef = "𝄞".as_bytes();
        assert_eq!(conv(Charset::Utf8, Charset::Utf16Le, clef).0, vec![0x34, 0xD8, 0x1E, 0xDD]);
        // BE forms
        assert_eq!(conv(Charset::Utf8, Charset::Utf16Be, eur).0, vec![0x20, 0xAC]);
        // incomplete UTF-8 -> EINVAL
        assert_eq!(conv(Charset::Utf8, Charset::Utf8, &[0xE2, 0x82]).1, Status::Einval);
        // invalid UTF-8 -> EILSEQ
        assert_eq!(conv(Charset::Utf8, Charset::Utf8, &[0x80]).1, Status::Eilseq);
        // ASCII rejects high byte
        assert_eq!(conv(Charset::Ascii, Charset::Utf8, &[0xC3]).1, Status::Eilseq);
        // name parsing
        assert!(matches!(parse_charset(b"utf-8"), Some((Charset::Utf8, 0))));
        assert!(matches!(parse_charset(b"ISO-8859-1//TRANSLIT"), Some((Charset::Latin1, F_TRANSLIT))));
        assert!(parse_charset(b"NOPE-7").is_none());
    }

    #[test]
    fn translit_and_ignore() {
        let eur = "€".as_bytes();
        // IGNORE: € dropped, nonrev counted
        let mut out = [0u8; 16];
        let r = convert(Charset::Utf8, Charset::Latin1, F_IGNORE, eur, &mut out);
        assert_eq!(r.status, Status::Ok);
        assert_eq!(r.out_used, 0);
        assert_eq!(r.nonrev, 1);
        // TRANSLIT: € -> '?'
        let r2 = convert(Charset::Utf8, Charset::Latin1, F_TRANSLIT, eur, &mut out);
        assert_eq!(r2.status, Status::Ok);
        assert_eq!(&out[..r2.out_used], b"?");
        assert_eq!(r2.nonrev, 1);
    }

    #[test]
    fn e2big_stops_at_boundary() {
        // "AB" UTF-8 -> UTF-32LE needs 8 bytes; give 4 -> writes 'A', stops E2BIG
        let mut out = [0u8; 4];
        let r = convert(Charset::Utf8, Charset::Utf32Le, 0, b"AB", &mut out);
        assert_eq!(r.status, Status::E2big);
        assert_eq!(r.in_used, 1);
        assert_eq!(r.out_used, 4);
    }
}
