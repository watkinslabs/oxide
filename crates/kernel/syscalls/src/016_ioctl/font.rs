#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use syscall::errno::Errno;

/// KDFONTOP + PIO/GIO_UNIMAP — the `setfont` font + unicode-map path
/// (Linux `con_font_op` / `con_set_unimap`). KDFONTOP loads/reads the glyph
/// bitmaps (32 bytes/glyph buffer); the unicode map is set separately by
/// PIO_UNIMAP (codepoint→glyph-index), so `conv_uni_to_pc` follows a custom
/// font. # C: O(charcount*height) on a font load.
pub(super) fn handle_font_ioctl(req: u64, arg: u64) -> Option<i64> {
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    const STRIDE: usize = 32;       // KDFONTOP: 32 bytes per glyph
    const MAX_GLYPHS: u32 = 512;
    const MAX_UNI: usize = 8192;    // unimap entry cap (sanity bound)
    match req {
        vt::KDFONTOP => {
            // struct console_font_op { u32 op,flags,width,height,charcount;
            // u8 *data; } — `data` is 8-byte aligned → offset 24 (4 bytes pad
            // after charcount@16); struct size 32.
            if arg == 0 || arg + 32 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 32; read the console_font_op fields from the caller's AS at their padded offsets.
            let (op, width, height, charcount, data_ptr) = unsafe {(
                core::ptr::read_volatile(arg as *const u32),
                core::ptr::read_volatile((arg + 8) as *const u32),
                core::ptr::read_volatile((arg + 12) as *const u32),
                core::ptr::read_volatile((arg + 16) as *const u32),
                core::ptr::read_volatile((arg + 24) as *const u64),
            )};
            match op {
                vt::KD_FONT_OP_SET => {
                    if charcount == 0 || charcount > MAX_GLYPHS { return Some(errno(Errno::Einval)); }
                    let bytes = charcount as usize * STRIDE;
                    if data_ptr == 0 || data_ptr + bytes as u64 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
                    let mut buf = alloc::vec![0u8; bytes];
                    // SAFETY: data_ptr validated for `bytes`; copy the glyph bitmaps from the caller's AS.
                    unsafe { for i in 0..bytes { buf[i] = core::ptr::read_volatile((data_ptr + i as u64) as *const u8); } }
                    match fbcon::font::set_font(width, height, charcount, STRIDE, &buf) {
                        Ok(()) => Some(0),
                        Err(()) => Some(errno(Errno::Einval)),
                    }
                }
                vt::KD_FONT_OP_GET => {
                    let (w, h, c, data) = fbcon::font::get_font(STRIDE);
                    // The caller's charcount is its buffer capacity (in glyphs).
                    if charcount < c {
                        // SAFETY: arg validated above; report the needed count.
                        unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, c); }
                        return Some(errno(Errno::Enospc));
                    }
                    // SAFETY: arg validated; write back the real width/height/charcount.
                    unsafe {
                        core::ptr::write_volatile((arg + 8) as *mut u32, w);
                        core::ptr::write_volatile((arg + 12) as *mut u32, h);
                        core::ptr::write_volatile((arg + 16) as *mut u32, c);
                    }
                    let bytes = c as usize * STRIDE;
                    if data_ptr == 0 || data_ptr + bytes as u64 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
                    // SAFETY: data_ptr validated for `bytes`; copy glyph bitmaps out to the caller's AS.
                    unsafe { for i in 0..bytes.min(data.len()) { core::ptr::write_volatile((data_ptr + i as u64) as *mut u8, data[i]); } }
                    Some(0)
                }
                vt::KD_FONT_OP_SET_DEFAULT => { fbcon::font::set_default(); Some(0) }
                _ => Some(errno(Errno::Einval)), // KD_FONT_OP_COPY unsupported
            }
        }
        vt::PIO_UNIMAP => {
            // struct unimapdesc { u16 entry_ct; struct unipair *entries; } —
            // entries at offset 8 (64-bit alignment). unipair = {u16 unicode, u16 fontpos}.
            if arg == 0 || arg + 16 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 16; read entry_ct (u16) + entries ptr (u64) from the caller's AS.
            let (ct, entries) = unsafe {(
                core::ptr::read_volatile(arg as *const u16) as usize,
                core::ptr::read_volatile((arg + 8) as *const u64),
            )};
            if ct > MAX_UNI { return Some(errno(Errno::Einval)); }
            let span = ct as u64 * 4;
            if ct > 0 && (entries == 0 || entries + span >= hal::USER_VA_END) { return Some(errno(Errno::Efault)); }
            let mut pairs = alloc::vec::Vec::with_capacity(ct);
            for i in 0..ct {
                let p = entries + (i as u64) * 4;
                // SAFETY: entries validated for `span`; read each 4-byte unipair (unicode, fontpos) from the caller's AS.
                let (uni, pos) = unsafe {(
                    core::ptr::read_volatile(p as *const u16) as u32,
                    core::ptr::read_volatile((p + 2) as *const u16),
                )};
                pairs.push((uni, pos));
            }
            fbcon::font::set_unimap(&pairs);
            Some(0)
        }
        vt::GIO_UNIMAP => {
            if arg == 0 || arg + 16 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 16; read the caller's buffer capacity (entry_ct) + dest ptr.
            let (cap, entries) = unsafe {(
                core::ptr::read_volatile(arg as *const u16) as usize,
                core::ptr::read_volatile((arg + 8) as *const u64),
            )};
            let map = fbcon::font::unimap();
            if cap < map.len() {
                // SAFETY: arg validated; report the needed entry count.
                unsafe { core::ptr::write_volatile(arg as *mut u16, map.len() as u16); }
                return Some(errno(Errno::Enomem));
            }
            let span = map.len() as u64 * 4;
            if !map.is_empty() && (entries == 0 || entries + span >= hal::USER_VA_END) { return Some(errno(Errno::Efault)); }
            for (i, &(uni, pos)) in map.iter().enumerate() {
                let p = entries + (i as u64) * 4;
                // SAFETY: entries validated for `span`; write each 4-byte unipair out to the caller's AS.
                unsafe {
                    core::ptr::write_volatile(p as *mut u16, uni as u16);
                    core::ptr::write_volatile((p + 2) as *mut u16, pos);
                }
            }
            // SAFETY: arg validated; write back the actual entry count.
            unsafe { core::ptr::write_volatile(arg as *mut u16, map.len() as u16); }
            Some(0)
        }
        vt::PIO_UNIMAPCLR => { fbcon::font::clear_unimap(); Some(0) }
        _ => None,
    }
}
