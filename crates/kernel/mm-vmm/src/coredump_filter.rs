// Per-mm core-dump filter — the nine `mm_struct` flag bits that decide which
// VMA classes a core dump of this process contains.
//
// The value is per-mm (so all threads of a process share it), inherited by a
// forked child, carried across `execve`, and exposed read/write through
// `/proc/<pid>/coredump_filter`. This module owns the value: its bit meanings,
// its default, and the exact text form the proc file reads and writes. The
// storage lives on the address space (`address_space::mmfields`), and the
// per-VMA decision ladder that consumes it lives with the dump writer.

bitflags::bitflags! {
    /// Core-dump filter bits, in the numbering the `/proc` file uses (the
    /// in-flags word stores them shifted above the two reserved dumpability
    /// bits; that shift is an internal detail of the flags word and never
    /// reaches userspace, so this type holds the unshifted value).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Hash)]
    pub struct CoredumpFilter: u32 {
        /// Anonymous private mappings — the heap, private stacks, brk.
        const ANON_PRIVATE    = 1 << 0;
        /// Anonymous shared mappings — shared memory with no directory entry.
        const ANON_SHARED     = 1 << 1;
        /// File-backed private mappings.
        const MAPPED_PRIVATE  = 1 << 2;
        /// File-backed shared mappings.
        const MAPPED_SHARED   = 1 << 3;
        /// First page of a file-backed private mapping that starts at file
        /// offset zero, so the dump records which object was mapped there.
        const ELF_HEADERS     = 1 << 4;
        /// Private huge-page mappings.
        const HUGETLB_PRIVATE = 1 << 5;
        /// Shared huge-page mappings.
        const HUGETLB_SHARED  = 1 << 6;
        /// Private mappings of directly-addressable persistent memory.
        const DAX_PRIVATE     = 1 << 7;
        /// Shared mappings of directly-addressable persistent memory.
        const DAX_SHARED      = 1 << 8;
    }
}

/// Number of filter bits userspace can set. A write applies exactly these and
/// discards anything above them.
pub const FILTER_BITS: u32 = 9;

/// Hex digits the rendered value is padded to.
const HEX_DIGITS: usize = 8;

/// Bytes the proc file renders: [`HEX_DIGITS`] hex digits plus a newline.
pub const FILTER_TEXT_LEN: usize = HEX_DIGITS + 1;

/// Longest input a write consumes before the remainder is ignored, matching the
/// fixed kernel-side staging buffer for a string-to-integer conversion from
/// user memory.
const PARSE_INPUT_MAX: usize = 66;

/// Rejection reasons for a `/proc/<pid>/coredump_filter` write.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FilterParseError {
    /// No digits, or trailing bytes after the number (EINVAL).
    Invalid,
    /// The number does not fit an unsigned 32-bit value (ERANGE).
    Range,
}

impl CoredumpFilter {
    /// Filter a process starts with: both anonymous classes, private huge
    /// pages, and the file-mapping header page.
    pub const DEFAULT: CoredumpFilter = CoredumpFilter::ANON_PRIVATE
        .union(CoredumpFilter::ANON_SHARED)
        .union(CoredumpFilter::ELF_HEADERS)
        .union(CoredumpFilter::HUGETLB_PRIVATE);

    /// Text form of the value: eight zero-padded lowercase hex digits plus a
    /// newline.
    /// # C: O(1)
    pub fn text(self) -> [u8; FILTER_TEXT_LEN] {
        const HEX: [u8; 16] = *b"0123456789abcdef";
        let mut out = [b'0'; FILTER_TEXT_LEN];
        let bits = self.bits();
        for (i, slot) in out[..HEX_DIGITS].iter_mut().enumerate() {
            let shift = 4 * (HEX_DIGITS - 1 - i);
            *slot = HEX[((bits >> shift) & 0xf) as usize];
        }
        out[HEX_DIGITS] = b'\n';
        out
    }

    /// Decode a write. The numeric base follows the leading characters: `0x`
    /// hex, a leading `0` octal, otherwise decimal. One trailing newline is
    /// accepted; anything else after the number is rejected. Bits above the
    /// nine defined ones are discarded rather than refused.
    /// # C: O(len)
    pub fn parse(src: &[u8]) -> Result<Self, FilterParseError> {
        let s = &src[..src.len().min(PARSE_INPUT_MAX)];
        let s = match s.iter().position(|&b| b == 0) { Some(i) => &s[..i], None => s };
        Ok(Self::from_bits_truncate(parse_uint(s)?))
    }
}

const BASE_HEX: u32 = 16;
const BASE_OCT: u32 = 8;
const BASE_DEC: u32 = 10;
const LOWER_CASE_BIT: u8 = 0x20;

fn digit_value(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a') as u32 + BASE_DEC),
        b'A'..=b'F' => Some((b - b'A') as u32 + BASE_DEC),
        _ => None,
    }
}

/// Pick the base from the leading characters and skip a `0x` prefix.
fn fixup_radix(s: &[u8]) -> (u32, &[u8]) {
    if s.first() == Some(&b'0') {
        let hex_prefix = s.len() > 2
            && (s[1] | LOWER_CASE_BIT) == b'x'
            && digit_value(s[2]).is_some_and(|d| d < BASE_HEX);
        if hex_prefix { return (BASE_HEX, &s[2..]); }
        return (BASE_OCT, s);
    }
    (BASE_DEC, s)
}

fn parse_uint(s: &[u8]) -> Result<u32, FilterParseError> {
    let s = if s.first() == Some(&b'+') { &s[1..] } else { s };
    let (base, digits) = fixup_radix(s);
    let mut acc: u32 = 0;
    let mut used = 0usize;
    for &b in digits {
        let Some(d) = digit_value(b) else { break };
        if d >= base { break; }
        // An overflowing number is out of range whatever follows it, so the
        // width check precedes the trailing-junk check.
        acc = acc.checked_mul(base).and_then(|a| a.checked_add(d))
            .ok_or(FilterParseError::Range)?;
        used += 1;
    }
    if used == 0 { return Err(FilterParseError::Invalid); }
    let mut tail = &digits[used..];
    if tail.first() == Some(&b'\n') { tail = &tail[1..]; }
    if !tail.is_empty() { return Err(FilterParseError::Invalid); }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selects_both_anon_classes_huge_private_and_the_header_page() {
        let d = CoredumpFilter::DEFAULT;
        assert!(d.contains(CoredumpFilter::ANON_PRIVATE));
        assert!(d.contains(CoredumpFilter::ANON_SHARED));
        assert!(d.contains(CoredumpFilter::HUGETLB_PRIVATE));
        assert!(d.contains(CoredumpFilter::ELF_HEADERS));
        assert!(!d.contains(CoredumpFilter::MAPPED_PRIVATE));
        assert!(!d.contains(CoredumpFilter::MAPPED_SHARED));
        assert!(!d.contains(CoredumpFilter::HUGETLB_SHARED));
        assert!(!d.contains(CoredumpFilter::DAX_PRIVATE));
        assert!(!d.contains(CoredumpFilter::DAX_SHARED));
        assert_eq!(d.bits(), 0x33);
    }

    #[test]
    fn every_defined_bit_has_the_documented_position() {
        assert_eq!(CoredumpFilter::ANON_PRIVATE.bits(),    0x001);
        assert_eq!(CoredumpFilter::ANON_SHARED.bits(),     0x002);
        assert_eq!(CoredumpFilter::MAPPED_PRIVATE.bits(),  0x004);
        assert_eq!(CoredumpFilter::MAPPED_SHARED.bits(),   0x008);
        assert_eq!(CoredumpFilter::ELF_HEADERS.bits(),     0x010);
        assert_eq!(CoredumpFilter::HUGETLB_PRIVATE.bits(), 0x020);
        assert_eq!(CoredumpFilter::HUGETLB_SHARED.bits(),  0x040);
        assert_eq!(CoredumpFilter::DAX_PRIVATE.bits(),     0x080);
        assert_eq!(CoredumpFilter::DAX_SHARED.bits(),      0x100);
        assert_eq!(CoredumpFilter::all().bits(), (1u32 << FILTER_BITS) - 1);
    }

    #[test]
    fn text_is_eight_zero_padded_lowercase_hex_digits_and_a_newline() {
        assert_eq!(&CoredumpFilter::DEFAULT.text(), b"00000033\n");
        assert_eq!(&CoredumpFilter::empty().text(), b"00000000\n");
        assert_eq!(&CoredumpFilter::all().text(), b"000001ff\n");
        assert_eq!(&CoredumpFilter::DAX_SHARED.text(), b"00000100\n");
    }

    #[test]
    fn parse_reads_decimal_hex_and_octal_by_prefix() {
        assert_eq!(CoredumpFilter::parse(b"51\n").unwrap(), CoredumpFilter::DEFAULT);
        assert_eq!(CoredumpFilter::parse(b"0x33").unwrap(), CoredumpFilter::DEFAULT);
        assert_eq!(CoredumpFilter::parse(b"0X33").unwrap(), CoredumpFilter::DEFAULT);
        assert_eq!(CoredumpFilter::parse(b"063").unwrap(), CoredumpFilter::DEFAULT);
        assert_eq!(CoredumpFilter::parse(b"+51").unwrap(), CoredumpFilter::DEFAULT);
        assert_eq!(CoredumpFilter::parse(b"0").unwrap(), CoredumpFilter::empty());
    }

    #[test]
    fn parse_discards_bits_above_the_nine_defined_ones() {
        assert_eq!(CoredumpFilter::parse(b"0xffffffff").unwrap(), CoredumpFilter::all());
        assert_eq!(CoredumpFilter::parse(b"0x200").unwrap(), CoredumpFilter::empty());
    }

    #[test]
    fn parse_rejects_empty_junk_and_a_digit_outside_the_chosen_base() {
        assert_eq!(CoredumpFilter::parse(b""), Err(FilterParseError::Invalid));
        assert_eq!(CoredumpFilter::parse(b"\n"), Err(FilterParseError::Invalid));
        assert_eq!(CoredumpFilter::parse(b"zz"), Err(FilterParseError::Invalid));
        assert_eq!(CoredumpFilter::parse(b"-1"), Err(FilterParseError::Invalid));
        assert_eq!(CoredumpFilter::parse(b"33 "), Err(FilterParseError::Invalid));
        assert_eq!(CoredumpFilter::parse(b"33\n\n"), Err(FilterParseError::Invalid));
        // A leading zero selects octal, so `9` terminates the number and is
        // then rejected as trailing junk.
        assert_eq!(CoredumpFilter::parse(b"09"), Err(FilterParseError::Invalid));
        // `0x` with no hex digit after it is octal zero followed by junk.
        assert_eq!(CoredumpFilter::parse(b"0x"), Err(FilterParseError::Invalid));
    }

    #[test]
    fn parse_reports_range_for_a_value_wider_than_thirty_two_bits() {
        assert_eq!(CoredumpFilter::parse(b"0x100000000"), Err(FilterParseError::Range));
        assert_eq!(CoredumpFilter::parse(b"4294967296"), Err(FilterParseError::Range));
        assert_eq!(CoredumpFilter::parse(b"4294967295").unwrap(), CoredumpFilter::all());
    }

    #[test]
    fn parse_accepts_exactly_one_trailing_newline() {
        assert_eq!(CoredumpFilter::parse(b"1\n").unwrap(), CoredumpFilter::ANON_PRIVATE);
        assert_eq!(CoredumpFilter::parse(b"1").unwrap(), CoredumpFilter::ANON_PRIVATE);
    }

    #[test]
    fn parse_stops_at_a_nul_and_at_the_staging_buffer_length() {
        assert_eq!(CoredumpFilter::parse(b"1\0garbage").unwrap(), CoredumpFilter::ANON_PRIVATE);
        let mut long = alloc::vec![b'0'; PARSE_INPUT_MAX];
        long.push(b'x');
        assert_eq!(CoredumpFilter::parse(&long).unwrap(), CoredumpFilter::empty());
    }

    /// Reading the file and writing its own output back does NOT round-trip:
    /// the rendered value is zero-padded, and a leading zero selects octal on
    /// the way back in. Pinned because a "helpful" decimal-only parser would
    /// silently disagree with every existing consumer.
    #[test]
    fn writing_back_the_rendered_text_reinterprets_it_as_octal() {
        let text = CoredumpFilter::DEFAULT.text();
        assert_eq!(&text, b"00000033\n");
        assert_eq!(CoredumpFilter::parse(&text).unwrap().bits(), 0o33);
    }

    #[test]
    fn every_bit_survives_a_write_of_its_own_hex_value() {
        for bit in 0..FILTER_BITS {
            let f = CoredumpFilter::from_bits_truncate(1 << bit);
            let text = alloc::format!("0x{:x}", f.bits());
            assert_eq!(CoredumpFilter::parse(text.as_bytes()).unwrap(), f, "bit {bit}");
        }
    }
}
