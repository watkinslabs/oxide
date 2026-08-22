#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use syscall::errno::Errno;

use crate::ioctl_user as user;

// `struct console_font_op { u32 op, flags, width, height, charcount; u8 *data; }`
// — `data` is 8-byte aligned, so four bytes of padding follow `charcount` and
// the struct is 32 bytes.
const OP_OP:        u64 = 0;
const OP_WIDTH:     u64 = 8;
const OP_HEIGHT:    u64 = 12;
const OP_CHARCOUNT: u64 = 16;
const OP_DATA:      u64 = 24;
const OP_BYTES:     usize = 32;

// `struct unimapdesc { u16 entry_ct; struct unipair *entries; }` — the pointer
// is 8-byte aligned, so the struct is 16 bytes.
const UD_ENTRY_CT: u64 = 0;
const UD_ENTRIES:  u64 = 8;
const UD_BYTES:    usize = 16;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn ld_u32(b: &[u8], off: u64) -> u32 {
    let o = off as usize;
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn ld_u64(b: &[u8], off: u64) -> u64 {
    let o = off as usize;
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_ne_bytes(v)
}

fn st_u32(b: &mut [u8], off: u64, v: u32) {
    let o = off as usize;
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}

/// KDFONTOP + PIO/GIO_UNIMAP — the `setfont` font + unicode-map path
/// (Linux `con_font_op` / `con_set_unimap`). KDFONTOP loads/reads the glyph
/// bitmaps (32 bytes/glyph buffer); the unicode map is set separately by
/// PIO_UNIMAP (codepoint→glyph-index), so `conv_uni_to_pc` follows a custom
/// font. Every caller access copies through the fault-recovering usercopy: the
/// glyph buffer and the unipair array are caller memory and can be unmapped
/// under the call. # C: O(charcount*height) on a font load.
pub(super) fn handle_font_ioctl(req: u64, arg: u64) -> Option<i64> {
    match req {
        vt::KDFONTOP => Some(font_op(arg)),
        vt::PIO_UNIMAP => Some(set_unimap(arg)),
        vt::GIO_UNIMAP => Some(get_unimap(arg)),
        vt::PIO_UNIMAPCLR => { fbcon::font::clear_unimap(); Some(0) }
        _ => None,
    }
}

/// The reference copies the whole `console_font_op` in, runs the operation, and
/// copies it back only on success — an error leaves the caller's struct as it
/// was. # C: O(charcount*32)
fn font_op(arg: u64) -> i64 {
    let mut op = match user::get_bytes::<OP_BYTES>(arg) { Ok(b) => b, Err(rv) => return rv };
    let data_ptr = ld_u64(&op, OP_DATA);
    match ld_u32(&op, OP_OP) {
        vt::KD_FONT_OP_SET => {
            // The reference refuses a null glyph buffer with EINVAL, BEFORE it
            // looks at the character count.
            if data_ptr == 0 { return errno(Errno::Einval); }
            let bytes = match user::font_glyph_bytes(ld_u32(&op, OP_CHARCOUNT)) {
                Ok(n) => n, Err(rv) => return rv,
            };
            let mut buf = alloc::vec![0u8; bytes];
            if let Err(rv) = user::get_into(data_ptr, &mut buf) { return rv; }
            match fbcon::font::set_font(ld_u32(&op, OP_WIDTH), ld_u32(&op, OP_HEIGHT),
                                        ld_u32(&op, OP_CHARCOUNT), user::FONT_GLYPH_STRIDE, &buf) {
                Ok(()) => {}
                Err(()) => return errno(Errno::Einval),
            }
        }
        vt::KD_FONT_OP_GET => {
            let (w, h, c, data) = fbcon::font::get_font(user::FONT_GLYPH_STRIDE);
            // The caller's dimensions and (when copying glyphs) charcount are
            // capacities. Refuse a short field with the struct untouched.
            if let Err(rv) = user::font_get_fits(
                ld_u32(&op, OP_WIDTH), ld_u32(&op, OP_HEIGHT), ld_u32(&op, OP_CHARCOUNT),
                w, h, c, data_ptr != 0,
            ) { return rv; }
            if data_ptr != 0 {
                let bytes = c as usize * user::FONT_GLYPH_STRIDE;
                let n = bytes.min(data.len());
                if let Err(rv) = user::put_bytes(data_ptr, &data[..n]) { return rv; }
            }
            st_u32(&mut op, OP_WIDTH, w);
            st_u32(&mut op, OP_HEIGHT, h);
            st_u32(&mut op, OP_CHARCOUNT, c);
        }
        vt::KD_FONT_OP_SET_DEFAULT => fbcon::font::set_default(),
        _ => return errno(Errno::Einval), // KD_FONT_OP_COPY unsupported
    }
    match user::put_bytes(arg, &op) { Ok(()) => 0, Err(rv) => rv }
}

/// PIO_UNIMAP: replace the codepoint→glyph map from the caller's array.
/// # C: O(entry_ct)
fn set_unimap(arg: u64) -> i64 {
    let desc = match user::get_bytes::<UD_BYTES>(arg) { Ok(b) => b, Err(rv) => return rv };
    let ct = u16::from_ne_bytes([desc[UD_ENTRY_CT as usize], desc[UD_ENTRY_CT as usize + 1]]) as usize;
    let entries = ld_u64(&desc, UD_ENTRIES);
    let span = match user::unimap_span(ct) { Ok(n) => n, Err(rv) => return rv };
    let mut raw = alloc::vec![0u8; span as usize];
    if span != 0 {
        if let Err(rv) = user::get_into(entries, &mut raw) { return rv; }
    }
    let mut pairs = alloc::vec::Vec::with_capacity(ct);
    for i in 0..ct {
        let o = i * user::UNIMAP_PAIR_BYTES as usize;
        pairs.push((u16::from_ne_bytes([raw[o], raw[o + 1]]) as u32,
                    u16::from_ne_bytes([raw[o + 2], raw[o + 3]])));
    }
    fbcon::font::set_unimap(&pairs);
    0
}

/// GIO_UNIMAP: export the map. The reference writes as many pairs as fit AND
/// the true entry count, then reports `ENOMEM` when the caller's array was too
/// small — a short buffer still learns the count it needs. # C: O(entries)
fn get_unimap(arg: u64) -> i64 {
    let desc = match user::get_bytes::<UD_BYTES>(arg) { Ok(b) => b, Err(rv) => return rv };
    let cap = u16::from_ne_bytes([desc[UD_ENTRY_CT as usize], desc[UD_ENTRY_CT as usize + 1]]) as usize;
    let entries = ld_u64(&desc, UD_ENTRIES);
    let map = fbcon::font::unimap();
    let n = map.len().min(cap);
    if n != 0 {
        let mut raw = alloc::vec![0u8; n * user::UNIMAP_PAIR_BYTES as usize];
        for (i, &(uni, pos)) in map.iter().take(n).enumerate() {
            let o = i * user::UNIMAP_PAIR_BYTES as usize;
            raw[o..o + 2].copy_from_slice(&(uni as u16).to_ne_bytes());
            raw[o + 2..o + 4].copy_from_slice(&pos.to_ne_bytes());
        }
        if let Err(rv) = user::put_bytes(entries, &raw) { return rv; }
    }
    if let Err(rv) = user::put_u16(arg + UD_ENTRY_CT, map.len() as u16) { return rv; }
    if map.len() > cap { return errno(Errno::Enomem); }
    0
}
