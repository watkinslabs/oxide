//! Scancode-Set-1 → Linux keycode decoder (x86_64, i8042). The
//! controller's translation bit gives us set-1 codes regardless of the
//! keyboard's native set, so we decode set-1 here.
//!
//! Set-1 layout: a make code is `0x01..=0x58`; the matching break code is
//! `make | 0x80`. Extended keys are prefixed with one `0xE0` byte (a few
//! with `0xE1`, e.g. Pause — ignored). The base-block make codes were the
//! source of Linux's `KEY_*` numbering, so for the non-extended block the
//! Linux keycode is the set-1 make code verbatim (KEY_ESC=1 … KEY_F12=0x58).
//!
//! `decode_byte` is a tiny state machine fed one raw port-0x60 byte at a
//! time; it returns `Some((linux_keycode, pressed))` once a full key is
//! assembled, `None` while consuming a prefix or an unmapped code.

use core::sync::atomic::{AtomicBool, Ordering};

const SCANCODE_EXTENDED: u8 = 0xE0;
const SCANCODE_PAUSE: u8 = 0xE1;
const CONTROLLER_ACK: u8 = 0xFA;
const CONTROLLER_RESEND: u8 = 0xFE;
const CONTROLLER_BAT_OK: u8 = 0xAA;
const SCANCODE_SET1_LAST: u8 = 0x58;

/// Set true after a 0xE0 byte; the next byte is an extended make/break.
static E0_PENDING: AtomicBool = AtomicBool::new(false);
/// Set true after a 0xE1 byte (Pause/Break 6-byte sequence); we swallow
/// the following bytes rather than decode the multi-byte Pause code.
static E1_SWALLOW: AtomicBool = AtomicBool::new(false);

/// Extended (0xE0-prefixed) set-1 make code → Linux keycode. Covers the
/// grey navigation cluster, keypad Enter/slash, right Ctrl/Alt, Meta/Menu
/// and media keys. The make code here is the *low* 7 bits (break = +0x80).
/// `0` = unmapped.
const E0_KEYCODE: [u16; 0x80] = build_e0_table();

const fn build_e0_table() -> [u16; 0x80] {
    let mut t = [0u16; 0x80];
    // Linux KEY_* values (include/uapi/linux/input-event-codes.h).
    t[0x1C] = 96; // KP_ENTER
    t[0x1D] = 97; // RIGHTCTRL
    t[0x35] = 98; // KPSLASH
    t[0x38] = 100; // RIGHTALT (AltGr)
    t[0x47] = 102; // HOME
    t[0x48] = 103; // UP
    t[0x49] = 104; // PAGEUP
    t[0x4B] = 105; // LEFT
    t[0x4D] = 106; // RIGHT
    t[0x4F] = 107; // END
    t[0x50] = 108; // DOWN
    t[0x51] = 109; // PAGEDOWN
    t[0x52] = 110; // INSERT
    t[0x53] = 111; // DELETE
    t[0x5B] = 125; // LEFTMETA  (Super/Win)
    t[0x5C] = 126; // RIGHTMETA
    t[0x5D] = 127; // COMPOSE / Menu
    // Common media / ACPI keys (best-effort; harmless if the keymap
    // has no entry — translate() returns Out::NONE).
    t[0x10] = 165; // PREVIOUSSONG
    t[0x19] = 163; // NEXTSONG
    t[0x20] = 113; // MUTE
    t[0x22] = 164; // PLAYPAUSE
    t[0x24] = 166; // STOPCD
    t[0x2E] = 114; // VOLUMEDOWN
    t[0x30] = 115; // VOLUMEUP
    t
}

/// Feed one raw byte from the i8042 data port. Returns the decoded
/// `(linux_keycode, pressed)` once a complete key is assembled.
/// `pressed=false` is a key release (break code, bit7 set).
/// # C: O(1)
pub fn decode_byte(byte: u8) -> Option<(u16, bool)> {
    // A 0xE1 sequence (Pause) is 6 bytes; swallow the rest after the lead
    // byte. We approximate by dropping the next two bytes (E1 1D 45 …).
    if E1_SWALLOW.swap(false, Ordering::Relaxed) {
        return None;
    }
    match byte {
        SCANCODE_EXTENDED => {
            E0_PENDING.store(true, Ordering::Relaxed);
            None
        }
        SCANCODE_PAUSE => {
            E1_SWALLOW.store(true, Ordering::Relaxed);
            None
        }
        // 0xFA (ACK) / 0xFE (resend) / 0xAA (BAT) can leak into the stream
        // after a command; never treat them as keys.
        CONTROLLER_ACK | CONTROLLER_RESEND | CONTROLLER_BAT_OK | 0x00 | 0xFF => {
            E0_PENDING.store(false, Ordering::Relaxed);
            None
        }
        _ => {
            let pressed = byte & 0x80 == 0;
            let code = byte & 0x7F;
            if E0_PENDING.swap(false, Ordering::Relaxed) {
                let kc = E0_KEYCODE[code as usize];
                if kc == 0 {
                    return None;
                }
                Some((kc, pressed))
            } else {
                // Base block: Linux keycode == set-1 make code. Valid range
                // is 0x01..=0x58 (1..=88); anything above is unmapped here.
                if code == 0 || code > SCANCODE_SET1_LAST {
                    return None;
                }
                Some((code as u16, pressed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_make_break_is_keycode() {
        // 0x1E = 'a' make → KEY_A (30) pressed; 0x9E = release.
        assert_eq!(decode_byte(0x1E), Some((30, true)));
        assert_eq!(decode_byte(0x9E), Some((30, false)));
    }

    #[test]
    fn esc_and_f12_bounds() {
        assert_eq!(decode_byte(0x01), Some((1, true)));   // KEY_ESC
        assert_eq!(decode_byte(0x58), Some((88, true)));  // KEY_F12
        assert_eq!(decode_byte(0x59), None);              // out of base block
    }

    #[test]
    fn extended_arrow_keys() {
        // E0 48 = Up pressed (KEY_UP=103); E0 C8 = Up released.
        assert_eq!(decode_byte(0xE0), None);
        assert_eq!(decode_byte(0x48), Some((103, true)));
        assert_eq!(decode_byte(0xE0), None);
        assert_eq!(decode_byte(0xC8), Some((103, false)));
    }

    #[test]
    fn extended_right_ctrl() {
        assert_eq!(decode_byte(0xE0), None);
        assert_eq!(decode_byte(0x1D), Some((97, true))); // KEY_RIGHTCTRL
    }

    #[test]
    fn ack_and_bat_bytes_drop() {
        assert_eq!(decode_byte(0xFA), None);
        assert_eq!(decode_byte(0xAA), None);
    }

    #[test]
    fn pause_e1_sequence_swallowed() {
        // E1 1D 45 … — lead byte sets swallow, next byte dropped.
        assert_eq!(decode_byte(0xE1), None);
        assert_eq!(decode_byte(0x1D), None); // swallowed
    }
}
