// East-Asian-width / combining width table (`57§9.2`). `char_width(cp)`
// returns the terminal cell width of a codepoint: 0 (combining mark — no
// advance), 1 (narrow, the default), or 2 (wide: CJK, fullwidth forms,
// many emoji). Interval tables are sorted, half-open-free (inclusive
// `[lo,hi]`), and binary-searched. Derived from the Unicode EAW property
// (`W`/`F` → 2) + the combining/zero-width set, the same classification
// Markus Kuhn's reference `wcwidth` uses; trimmed to the ranges a console
// realistically renders. No external `unicode-width` crate (`#![no_std]`).

/// Cell width of `cp`: 0 = combining/zero-width, 1 = narrow, 2 = wide.
/// C0/C1 controls are width 0 here (the caller handles them before
/// printing); U+0000 maps to 1 to keep blank cells well-formed.
/// # C: O(log N) — two binary searches.
pub fn char_width(cp: u32) -> u8 {
    if cp == 0 {
        return 1;
    }
    // Control range: not printed as glyphs; treat as zero so a stray
    // control never advances the cursor if it reaches here.
    if cp < 0x20 || (0x7f..0xa0).contains(&cp) {
        return 0;
    }
    if in_table(cp, &ZERO_WIDTH) {
        return 0;
    }
    if in_table(cp, &WIDE) {
        return 2;
    }
    1
}

/// Inclusive-range binary search.
/// # C: O(log N).
fn in_table(cp: u32, table: &[(u32, u32)]) -> bool {
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (a, b) = table[mid];
        if cp < a {
            hi = mid;
        } else if cp > b {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// Combining / zero-width codepoints (Mn, Me, Cf default-ignorable, and the
/// Hangul-Jamo medial/final conjoining ranges). Sorted ascending.
static ZERO_WIDTH: &[(u32, u32)] = &[
    (0x0300, 0x036f), // combining diacritical marks
    (0x0483, 0x0489),
    (0x0591, 0x05bd),
    (0x05bf, 0x05bf),
    (0x05c1, 0x05c2),
    (0x05c4, 0x05c5),
    (0x0610, 0x061a),
    (0x064b, 0x065f),
    (0x0670, 0x0670),
    (0x06d6, 0x06dc),
    (0x06df, 0x06e4),
    (0x06e7, 0x06e8),
    (0x06ea, 0x06ed),
    (0x0711, 0x0711),
    (0x0730, 0x074a),
    (0x07a6, 0x07b0),
    (0x07eb, 0x07f3),
    (0x0901, 0x0903),
    (0x093c, 0x093c),
    (0x0941, 0x0948),
    (0x094d, 0x094d),
    (0x0951, 0x0957),
    (0x0e31, 0x0e31),
    (0x0e34, 0x0e3a),
    (0x0e47, 0x0e4e),
    (0x1ab0, 0x1aff),
    (0x1dc0, 0x1dff),
    (0x200b, 0x200f), // ZWSP..RLM
    (0x202a, 0x202e),
    (0x2060, 0x2064),
    (0x20d0, 0x20f0), // combining marks for symbols
    (0xfe00, 0xfe0f), // variation selectors
    (0xfe20, 0xfe2f), // combining half marks
    (0xfeff, 0xfeff), // ZWNBSP / BOM
    (0xe0100, 0xe01ef),
];

/// Wide (EAW `W`/`F`) codepoints. Sorted ascending. Covers the CJK blocks,
/// Hangul syllables, fullwidth forms, and the common emoji planes.
static WIDE: &[(u32, u32)] = &[
    (0x1100, 0x115f), // Hangul Jamo (conjoining leading)
    (0x2329, 0x232a), // angle brackets
    (0x2e80, 0x303e), // CJK radicals .. CJK symbols
    (0x3041, 0x33ff), // Hiragana .. CJK compat
    (0x3400, 0x4dbf), // CJK Ext A
    (0x4e00, 0x9fff), // CJK Unified
    (0xa000, 0xa4cf), // Yi
    (0xa960, 0xa97f), // Hangul Jamo Extended-A
    (0xac00, 0xd7a3), // Hangul syllables
    (0xf900, 0xfaff), // CJK compat ideographs
    (0xfe10, 0xfe19), // vertical forms
    (0xfe30, 0xfe6f), // CJK compat forms .. small forms
    (0xff00, 0xff60), // fullwidth forms
    (0xffe0, 0xffe6), // fullwidth signs
    (0x16fe0, 0x16fe4),
    (0x17000, 0x18d08), // Tangut
    (0x1b000, 0x1b2fb), // Kana supplement/extended
    (0x1f004, 0x1f004), // mahjong red dragon
    (0x1f0cf, 0x1f0cf), // playing card black joker
    (0x1f18e, 0x1f18e),
    (0x1f191, 0x1f19a),
    (0x1f200, 0x1f320),
    (0x1f330, 0x1f335),
    (0x1f337, 0x1f37c),
    (0x1f380, 0x1f393),
    (0x1f3a0, 0x1f3ca),
    (0x1f3cf, 0x1f3d3),
    (0x1f3e0, 0x1f3f0),
    (0x1f400, 0x1f4fc),
    (0x1f500, 0x1f53d),
    (0x1f550, 0x1f567),
    (0x1f600, 0x1f64f), // emoticons
    (0x1f680, 0x1f6c5), // transport
    (0x1f900, 0x1f9ff), // supplemental symbols + emoji
    (0x20000, 0x3fffd), // CJK Ext B..F + supplement
];

#[cfg(test)]
mod tests {
    use super::char_width;

    #[test]
    fn ascii_is_narrow() {
        assert_eq!(char_width('A' as u32), 1);
        assert_eq!(char_width(' ' as u32), 1);
        assert_eq!(char_width('~' as u32), 1);
    }

    #[test]
    fn cjk_is_wide() {
        assert_eq!(char_width('中' as u32), 2);
        assert_eq!(char_width('日' as u32), 2);
        assert_eq!(char_width('한' as u32), 2); // Hangul syllable
        assert_eq!(char_width(0xff21), 2); // fullwidth A
    }

    #[test]
    fn combining_is_zero() {
        assert_eq!(char_width(0x0301), 0); // combining acute
        assert_eq!(char_width(0x200b), 0); // ZWSP
        assert_eq!(char_width(0xfe0f), 0); // variation selector-16
    }

    #[test]
    fn emoji_is_wide() {
        assert_eq!(char_width(0x1f600), 2); // grinning face
        assert_eq!(char_width(0x1f680), 2); // rocket
    }

    #[test]
    fn controls_are_zero() {
        assert_eq!(char_width(0x07), 0);
        assert_eq!(char_width(0x1b), 0);
        assert_eq!(char_width(0), 1); // NUL keeps blank cells well-formed
    }
}
