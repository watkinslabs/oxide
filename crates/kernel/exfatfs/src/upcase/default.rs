//! The table used when a volume carries none of its own.
//!
//! Built from the case-pair RULES of each script rather than stored as data:
//! most of the 16-bit range is identity, and the parts that are not fall into
//! a handful of regular shapes — a whole block shifted by a constant, or
//! alternating upper/lower pairs one apart.
//!
//! This path is reached only by a volume with no up-case directory entry,
//! which every formatter writes. A volume that HAS one is folded by that
//! table, so the characters this misses cannot change how a real medium reads.

use alloc::vec::Vec;

use crate::uapi::UPCASE_ENTRIES;

/// A block of characters whose upper case is a constant distance away.
struct Shift {
    from: u16,
    to: u16,
    delta: i32,
}

/// Blocks that fold by a fixed distance.
const SHIFTS: &[Shift] = &[
    // Basic Latin.
    Shift { from: 0x0061, to: 0x007A, delta: -0x20 },
    // Latin-1 Supplement, either side of the division sign.
    Shift { from: 0x00E0, to: 0x00F6, delta: -0x20 },
    Shift { from: 0x00F8, to: 0x00FE, delta: -0x20 },
    // Greek.
    Shift { from: 0x03B1, to: 0x03C1, delta: -0x20 },
    Shift { from: 0x03C3, to: 0x03CB, delta: -0x20 },
    Shift { from: 0x03AD, to: 0x03AF, delta: -0x25 },
    Shift { from: 0x03CD, to: 0x03CE, delta: -0x3F },
    // Cyrillic, and its supplement.
    Shift { from: 0x0430, to: 0x044F, delta: -0x20 },
    Shift { from: 0x0450, to: 0x045F, delta: -0x50 },
    // Armenian.
    Shift { from: 0x0561, to: 0x0586, delta: -0x30 },
    // Roman numeral forms.
    Shift { from: 0x2170, to: 0x217F, delta: -0x10 },
    // Circled letters.
    Shift { from: 0x24D0, to: 0x24E9, delta: -0x1A },
    // Glagolitic.
    Shift { from: 0x2C30, to: 0x2C5E, delta: -0x30 },
    // Fullwidth forms.
    Shift { from: 0xFF41, to: 0xFF5A, delta: -0x20 },
];

/// A block of alternating upper/lower pairs one apart.
struct Pairs {
    /// First LOWER-case character of the block.
    from: u16,
    /// Last lower-case character of the block.
    to: u16,
}

/// Blocks laid out as upper, lower, upper, lower.
const PAIRED: &[Pairs] = &[
    // Latin Extended-A, in its four separately-aligned runs.
    Pairs { from: 0x0101, to: 0x0137 },
    Pairs { from: 0x013A, to: 0x0148 },
    Pairs { from: 0x014B, to: 0x0177 },
    Pairs { from: 0x017A, to: 0x017E },
    // Cyrillic historic and extended letters.
    Pairs { from: 0x0461, to: 0x0481 },
    Pairs { from: 0x048B, to: 0x04BF },
    Pairs { from: 0x04C2, to: 0x04CE },
    Pairs { from: 0x04D1, to: 0x052F },
    // Latin Extended Additional.
    Pairs { from: 0x1E01, to: 0x1E95 },
    Pairs { from: 0x1EA1, to: 0x1EFF },
];

/// Characters whose upper case is nowhere near them.
const SINGLES: &[(u16, u16)] = &[
    // Micro sign folds to capital Mu.
    (0x00B5, 0x039C),
    // Small y with diaeresis folds to a capital in Latin Extended-A.
    (0x00FF, 0x0178),
    // Long s folds to plain S.
    (0x017F, 0x0053),
    // Final sigma folds to the same capital as the medial one.
    (0x03C2, 0x03A3),
    // Accented Greek vowels outside the runs above.
    (0x03AC, 0x0386),
    (0x03CC, 0x038C),
];

/// The built-in table, in the form [`super::UpCase`] holds: zero means the
/// character is its own upper case. # C: O(UPCASE_ENTRIES)
pub fn table() -> Vec<u16> {
    let mut out = alloc::vec![0u16; UPCASE_ENTRIES];
    for shift in SHIFTS {
        for unit in shift.from..=shift.to {
            out[unit as usize] = (i32::from(unit) + shift.delta) as u16;
        }
    }
    for block in PAIRED {
        let mut unit = block.from;
        while unit <= block.to {
            out[unit as usize] = unit - 1;
            unit += 2;
        }
    }
    for (lower, upper) in SINGLES {
        out[*lower as usize] = *upper;
    }
    out
}
