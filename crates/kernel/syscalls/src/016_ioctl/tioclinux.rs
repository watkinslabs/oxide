#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use crate::ioctl_user as user;

/// TIOCLINUX (Linux `tty_io.c` → `vt.c tioclinux`): `*arg[0]` is the
/// subfunction selector; the rest of the layout depends on it. Operates on the
/// FOREGROUND console (Linux uses `fg_console` for the screen subfunctions).
/// Returns the syscall result (0 / -errno / a value for GET subfunctions).
/// Unknown subfunction → EINVAL (never a faked success). # C: O(rows*cols) on
/// SETSEL, else O(1).
pub(super) fn handle_tioclinux(arg: u64) -> i64 {
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    let sub = match user::get_u8(arg + user::TIOCL_SUBCODE) { Ok(v) => v, Err(rv) => return rv };
    match sub {
        vt::tiocl::TIOCL_SETSEL => {
            // struct tiocl_selection { u16 xs, ys, xe, ye, sel_mode; }. The
            // reference hands the subfunction the BYTE-addressed parameter
            // block, so the rectangle starts at arg+1 and every field of it is
            // misaligned by one.
            let mut f = [0u16; 5];
            for (i, out) in f.iter_mut().enumerate() {
                *out = match user::get_u16(arg + user::tiocl_sel_field(i as u64)) {
                    Ok(v) => v, Err(rv) => return rv,
                };
            }
            let (xs, ys, xe, ye, mode) = (f[0], f[1], f[2], f[3], f[4]);
            // Linux SETSEL coords are 1-based (xs/ys start at 1); normalise to
            // 0-based grid cells. A 0 stays 0 (clamped by resolve_selection).
            let z = |v: u16| v.saturating_sub(1);
            let (rows, cols) = match fbcon::kernel::console_dims() {
                Some(d) => d, None => return errno(Errno::Einval),
            };
            let (start, end) = match vt::tiocl::resolve_selection(z(xs), z(ys), z(xe), z(ye), mode, rows, cols) {
                Some(r) => r, None => return errno(Errno::Einval),
            };
            // Glyph dump of the fg screen (rows*cols Latin-1 bytes).
            let screen = fbcon::kernel::screen_dump(false);
            if screen.is_empty() { vt::tiocl::set_selection(alloc::vec::Vec::new()); return 0; }
            let lut = vt::tiocl::sel_lut();
            let (s, e) = if mode == vt::tiocl::TIOCL_SELWORD {
                vt::tiocl::widen_to_words(&screen, &lut, cols, start, end)
            } else { (start, end) };
            // Extract the cells [s, e] inclusive, inserting a newline at each
            // row boundary (Linux `sel_buffer` appends '\r' at EOL of a
            // multi-line char/line selection; we emit '\n' so a paste reads as
            // typed lines). Trailing blanks per row are trimmed (Linux does the
            // same via `clear_selection` / the `set_selection` space-trim).
            let e = e.min(screen.len().saturating_sub(1));
            let s = s.min(e);
            let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let cols_u = cols as usize;
            let mut i = s;
            while i <= e {
                let row_end = (i / cols_u) * cols_u + (cols_u - 1);
                let line_end = row_end.min(e);
                // trim trailing spaces on this row's slice
                let mut j = line_end;
                while j >= i && screen[j] == b' ' { if j == i { break; } j -= 1; }
                let upto = if screen[j] == b' ' { i } else { j + 1 };
                out.extend_from_slice(&screen[i..upto]);
                if line_end < e { out.push(b'\n'); }
                i = row_end + 1;
            }
            vt::tiocl::set_selection(out);
            0
        }
        vt::tiocl::TIOCL_PASTESEL => {
            // Inject the stored selection into the fg console's tty INPUT,
            // byte-by-byte through the same path the keyboard uses (Linux
            // `paste_selection` → `tty_insert_flip_*`). When the foreground
            // VT has bracketed-paste (`?2004`) on, wrap the payload in the
            // paste markers so the program can tell paste from typed input.
            let bracket = tty::live::fg_bracketed_paste();
            if bracket { for &b in b"\x1b[200~" { tty::live::input_push_byte(b); } }
            let sel = vt::tiocl::selection();
            for &b in sel.iter() { tty::live::input_push_byte(b); }
            if bracket { for &b in b"\x1b[201~" { tty::live::input_push_byte(b); } }
            0
        }
        vt::tiocl::TIOCL_UNBLANKSCREEN => { vt::unblank(); 0 }
        vt::tiocl::TIOCL_SELLOADLUT => {
            // 32 bytes (256 bits) of word-select char-class LUT, in the
            // WORD-addressed parameter block.
            let mut lut = [0u8; 32];
            if let Err(rv) = user::get_into(arg + user::TIOCL_PARAM32, &mut lut) { return rv; }
            vt::tiocl::set_sel_lut(lut);
            0
        }
        vt::tiocl::TIOCL_GETSHIFTSTATE => {
            // The reference answers in the SUBCODE byte itself, not in the
            // parameter block: the caller passes a one-byte buffer.
            let bits = vt::tiocl::linux_shift_state(drv_virtio_input::keymap::mods().bits());
            match user::put_u8(arg + user::TIOCL_SUBCODE, bits) { Ok(()) => 0, Err(rv) => rv }
        }
        vt::tiocl::TIOCL_SETVESABLANK => {
            // Blank interval (minutes) in the byte parameter block. No hw
            // blank timer; store it.
            let mins = match user::get_u8(arg + user::TIOCL_PARAM) { Ok(v) => v as u32, Err(rv) => return rv };
            vt::tiocl::set_blank_interval(mins);
            0
        }
        vt::tiocl::TIOCL_SETKMSGREDIRECT => {
            // Target VT for kernel printk redirect, in the byte parameter
            // block. Store it.
            let vt = match user::get_u8(arg + user::TIOCL_PARAM) { Ok(v) => v, Err(rv) => return rv };
            vt::tiocl::set_kmsg_redirect(vt);
            0
        }
        vt::tiocl::TIOCL_GETFGCONSOLE => {
            // 0-based fg console index, returned as the syscall value (Linux
            // tioclinux returns `fg_console`).
            vt::active().saturating_sub(1) as i64
        }
        vt::tiocl::TIOCL_SCROLLCONSOLE => {
            // s32 lines delta in the WORD-addressed parameter block
            // (`scrollfront`/`scrollback`), four bytes in — not one.
            let lines = match user::get_i32(arg + user::TIOCL_PARAM32) { Ok(v) => v, Err(rv) => return rv };
            vt::scrolldelta(lines as isize);
            0
        }
        vt::tiocl::TIOCL_BLANKSCREEN => { vt::blank(); 0 }
        vt::tiocl::TIOCL_BLANKEDSCREEN => {
            // Return the blank-flag state as the syscall value (Linux returns
            // `console_blanked`).
            if vt::tiocl::blanked() { 1 } else { 0 }
        }
        vt::tiocl::TIOCL_GETKMSGREDIRECT => {
            // Return the stored kmsg-redirect target VT as the syscall value.
            vt::tiocl::kmsg_redirect() as i64
        }
        _ => errno(Errno::Einval),
    }
}
