// UEFI `LoadOptions` decoding: UTF-16 code units -> UTF-8 command-line bytes.
//
// The aarch64 EFI boot path receives its kernel command line as the UTF-16
// `LoadOptions` buffer on the loaded-image protocol, because the firmware this
// kernel boots under publishes no device tree and therefore has no
// `/chosen/bootargs` to carry it. The kernel cmdline slot holds UTF-8 bytes,
// so the transition needs a decode.
//
// Kept free of the kernel-target gate and of any static state so the decode
// rules are exercised by hosted tests; the EFI stub only supplies the byte
// sink. Decoding stops at the first NUL (UEFI terminates `LoadOptions`
// in-band, and `LoadOptionsSize` may cover trailing slack).

/// Unicode replacement character, substituted for an unpaired surrogate.
const REPLACEMENT: u32 = 0xFFFD;
/// UTF-16 surrogate ranges.
const HI_SURROGATE_FIRST: u16 = 0xD800;
const HI_SURROGATE_LAST: u16 = 0xDBFF;
const LO_SURROGATE_FIRST: u16 = 0xDC00;
const LO_SURROGATE_LAST: u16 = 0xDFFF;
/// Code points at or above this need a surrogate pair in UTF-16.
const SUPPLEMENTARY_BASE: u32 = 0x1_0000;
/// Bits of a supplementary code point carried by each surrogate half.
const SURROGATE_BITS: u32 = 10;
const SURROGATE_MASK: u32 = 0x3FF;

/// Decode `units` (a UEFI `LoadOptions` buffer) into UTF-8, handing each byte
/// to `emit`. Stops at the first NUL code unit, at the end of `units`, or when
/// `emit` returns `false` (sink full). Returns the number of bytes emitted.
///
/// A code point is emitted whole or not at all: when the sink rejects a byte
/// mid-sequence the earlier bytes of that sequence are already out, so `emit`
/// must only refuse at a boundary it can live with — the caller sizes its sink
/// with headroom rather than truncating mid-character.
/// # C: O(units.len())
pub fn utf16_to_utf8(units: &[u16], mut emit: impl FnMut(u8) -> bool) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < units.len() {
        let u = units[i];
        if u == 0 { break; }
        i += 1;
        let cp = if (HI_SURROGATE_FIRST..=HI_SURROGATE_LAST).contains(&u) {
            // High surrogate: consume the low half when it is really there.
            match units.get(i) {
                Some(&lo) if (LO_SURROGATE_FIRST..=LO_SURROGATE_LAST).contains(&lo) => {
                    i += 1;
                    SUPPLEMENTARY_BASE
                        + (((u as u32) & SURROGATE_MASK) << SURROGATE_BITS)
                        + ((lo as u32) & SURROGATE_MASK)
                }
                _ => REPLACEMENT,
            }
        } else if (LO_SURROGATE_FIRST..=LO_SURROGATE_LAST).contains(&u) {
            // Lone low surrogate — no valid pairing is possible.
            REPLACEMENT
        } else {
            u as u32
        };
        if !encode_utf8(cp, &mut n, &mut emit) { break; }
    }
    n
}

/// Emit `cp` as UTF-8 through `emit`, counting bytes into `n`. Returns `false`
/// once the sink refuses a byte.
fn encode_utf8(cp: u32, n: &mut usize, emit: &mut impl FnMut(u8) -> bool) -> bool {
    let mut put = |b: u8, n: &mut usize| { if emit(b) { *n += 1; true } else { false } };
    if cp < 0x80 {
        put(cp as u8, n)
    } else if cp < 0x800 {
        put(0xC0 | (cp >> 6) as u8, n)
            && put(0x80 | (cp & 0x3F) as u8, n)
    } else if cp < SUPPLEMENTARY_BASE {
        put(0xE0 | (cp >> 12) as u8, n)
            && put(0x80 | ((cp >> 6) & 0x3F) as u8, n)
            && put(0x80 | (cp & 0x3F) as u8, n)
    } else {
        put(0xF0 | (cp >> 18) as u8, n)
            && put(0x80 | ((cp >> 12) & 0x3F) as u8, n)
            && put(0x80 | ((cp >> 6) & 0x3F) as u8, n)
            && put(0x80 | (cp & 0x3F) as u8, n)
    }
}

/// Number of whole UTF-16 code units in a `LoadOptions` buffer of
/// `load_options_size` bytes. UEFI reports the size in bytes and firmware is
/// free to report an odd count; the trailing half unit is not decodable.
/// # C: O(1)
pub fn load_options_units(load_options_size: u32) -> usize {
    (load_options_size as usize) / core::mem::size_of::<u16>()
}

#[cfg(test)]
mod tests {
    use super::{load_options_units, utf16_to_utf8};
    use alloc::vec::Vec;

    fn decode(units: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        utf16_to_utf8(units, |b| { out.push(b); true });
        out
    }

    fn utf16(s: &str) -> Vec<u16> { s.encode_utf16().collect() }

    /// The shape the bootloader actually hands over: an ASCII kernel command
    /// line, NUL-terminated inside the reported buffer.
    #[test]
    fn ascii_command_line_round_trips() {
        let line = "BOOT_IMAGE=/boot/oxide-aarch64.Image root=/dev/oxide0 rw quiet \
                    console=ttyAMA0,115200 console=tty0 oxide.bootargs=grub";
        let mut units = utf16(line);
        units.push(0);
        assert_eq!(decode(&units), line.as_bytes());
    }

    /// `LoadOptionsSize` routinely covers slack past the terminator; the NUL
    /// ends the line, not the buffer length.
    #[test]
    fn stops_at_nul_ignoring_trailing_slack() {
        let mut units = utf16("quiet");
        units.push(0);
        units.extend_from_slice(&[0x41, 0x42, 0x43]);
        assert_eq!(decode(&units), b"quiet");
    }

    /// No terminator at all: decode the whole buffer rather than run off it.
    #[test]
    fn unterminated_buffer_decodes_fully() {
        assert_eq!(decode(&utf16("ro")), b"ro");
    }

    #[test]
    fn empty_buffer_yields_nothing() {
        assert_eq!(decode(&[]), b"");
        assert_eq!(decode(&[0]), b"");
    }

    /// Non-ASCII must widen correctly — two- and three-byte forms.
    #[test]
    fn two_and_three_byte_code_points() {
        assert_eq!(decode(&utf16("é")), "é".as_bytes());
        assert_eq!(decode(&utf16("€")), "€".as_bytes());
        assert_eq!(decode(&utf16("a\u{7FF}b\u{FFFF}c")), "a\u{7FF}b\u{FFFF}c".as_bytes());
    }

    /// Supplementary planes arrive as a surrogate pair and must recombine into
    /// one four-byte sequence, not two replacement characters.
    #[test]
    fn surrogate_pair_recombines() {
        let units = utf16("\u{1F600}");
        assert_eq!(units.len(), 2, "supplementary code point is a pair in UTF-16");
        assert_eq!(decode(&units), "\u{1F600}".as_bytes());
    }

    /// Malformed input must not swallow the rest of the line or desynchronize.
    #[test]
    fn unpaired_surrogates_become_replacement_and_decoding_continues() {
        assert_eq!(decode(&[0xD800, 0x0041]), "\u{FFFD}A".as_bytes());
        assert_eq!(decode(&[0xDC00, 0x0041]), "\u{FFFD}A".as_bytes());
        assert_eq!(decode(&[0xD800]), "\u{FFFD}".as_bytes());
    }

    /// A full sink stops the decode at the byte that did not fit; the caller
    /// gets the count it accepted, never a write past its buffer.
    #[test]
    fn sink_refusal_stops_and_reports_accepted_bytes() {
        let mut out = Vec::new();
        let cap = 3;
        let n = utf16_to_utf8(&utf16("abcdef"), |b| {
            if out.len() == cap { return false; }
            out.push(b);
            true
        });
        assert_eq!(out, b"abc");
        assert_eq!(n, cap);
    }

    /// Byte size -> code-unit count, including the odd-size case firmware may
    /// report.
    #[test]
    fn load_options_units_halves_the_byte_size() {
        assert_eq!(load_options_units(0), 0);
        assert_eq!(load_options_units(2), 1);
        assert_eq!(load_options_units(64), 32);
        assert_eq!(load_options_units(65), 32, "trailing half unit is not decodable");
    }
}
