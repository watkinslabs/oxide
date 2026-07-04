#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use syscall::errno::Errno;

/// True if `[ptr, ptr+len)` lies wholly in the userspace VA window. Mirrors the
/// `arg==0 || arg>=USER_VA_END` guard used across this file but for a multi-byte
/// span (used by the TIOCLINUX struct reads/writes). # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && len != 0 && ptr.checked_add(len).map_or(false, |end| end <= hal::USER_VA_END)
}

/// TIOCLINUX (Linux `tty_io.c` → `vt.c tioclinux`): `*arg[0]` is the
/// subfunction selector; the rest of the layout depends on it. Operates on the
/// FOREGROUND console (Linux uses `fg_console` for the screen subfunctions).
/// Returns the syscall result (0 / -errno / a value for GET subfunctions).
/// Unknown subfunction → EINVAL (never a faked success). # C: O(rows*cols) on
/// SETSEL, else O(1).
pub(super) fn handle_tioclinux(arg: u64) -> i64 {
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    if !user_ok(arg, 1) { return errno(Errno::Efault); }
    // SAFETY: arg validated in-userspace for 1 byte; CPL=0 read of the subfunction selector from the caller's AS.
    let sub = unsafe { core::ptr::read_volatile(arg as *const u8) };
    match sub {
        vt::tiocl::TIOCL_SETSEL => {
            // struct tiocl_selection { u16 xs, ys, xe, ye, sel_mode; } at arg+2.
            if !user_ok(arg, 2 + 10) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 12 bytes; read the 5×u16 selection rectangle from the caller's AS.
            let (xs, ys, xe, ye, mode) = unsafe {(
                core::ptr::read_volatile((arg + 2) as *const u16),
                core::ptr::read_volatile((arg + 4) as *const u16),
                core::ptr::read_volatile((arg + 6) as *const u16),
                core::ptr::read_volatile((arg + 8) as *const u16),
                core::ptr::read_volatile((arg + 10) as *const u16),
            )};
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
            // arg+4 holds 32 bytes (256 bits) of word-select char-class LUT.
            if !user_ok(arg, 4 + 32) { return errno(Errno::Efault); }
            let mut lut = [0u8; 32];
            // SAFETY: arg validated in-userspace for 36 bytes; read the 32-byte word-select LUT from the caller's AS.
            unsafe { for i in 0..32 { lut[i] = core::ptr::read_volatile((arg + 4 + i as u64) as *const u8); } }
            vt::tiocl::set_sel_lut(lut);
            0
        }
        vt::tiocl::TIOCL_GETSHIFTSTATE => {
            // Linux writes the shift-state byte to ((char*)arg)[1].
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            let bits = vt::tiocl::linux_shift_state(drv_virtio_input::keymap::mods().bits());
            // SAFETY: arg validated in-userspace for 2 bytes; CPL=0 write of the shift-state byte into ((char*)arg)[1].
            unsafe { core::ptr::write_volatile((arg + 1) as *mut u8, bits); }
            0
        }
        vt::tiocl::TIOCL_SETVESABLANK => {
            // arg+1 = blank interval (minutes). No hw blank timer; store it.
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 2 bytes; read the VESA blank-interval byte from the caller's AS.
            let mins = unsafe { core::ptr::read_volatile((arg + 1) as *const u8) } as u32;
            vt::tiocl::set_blank_interval(mins);
            0
        }
        vt::tiocl::TIOCL_SETKMSGREDIRECT => {
            // arg+1 = target VT for kernel printk redirect. Store it.
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 2 bytes; read the kmsg-redirect target VT byte from the caller's AS.
            let vt = unsafe { core::ptr::read_volatile((arg + 1) as *const u8) };
            vt::tiocl::set_kmsg_redirect(vt);
            0
        }
        vt::tiocl::TIOCL_GETFGCONSOLE => {
            // 0-based fg console index, returned as the syscall value (Linux
            // tioclinux returns `fg_console`).
            vt::active().saturating_sub(1) as i64
        }
        vt::tiocl::TIOCL_SCROLLCONSOLE => {
            // arg+1 = s32 lines delta (Linux `scrollfront`/`scrollback`).
            if !user_ok(arg, 1 + 4) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 5 bytes; read the s32 scroll-lines delta from the caller's AS.
            let lines = unsafe { core::ptr::read_volatile((arg + 1) as *const i32) };
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
