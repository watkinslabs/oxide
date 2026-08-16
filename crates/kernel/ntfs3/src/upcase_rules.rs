//! The case pairs the built-in table folds, when a volume's own `$UpCase`
//! cannot be read.
//!
//! Built from the case-pair RULES of each script rather than stored as data:
//! most of the 16-bit range is identity, and the parts that are not fall into
//! a handful of regular shapes. Reached only by a volume whose `$UpCase` is
//! unreadable, which every formatter writes — a volume that HAS one is folded
//! and ordered by that table, so what this misses cannot change how a real
//! medium reads.

/// Every pair this table folds, as (lower, upper).
///
/// Materialised once at mount rather than described as ranges at each lookup,
/// because a fold happens per character of every name comparison in a B-tree
/// descent.
pub static PAIRS: &[(u16, u16)] = &{
    // A const block, so the table is laid out at compile time and costs no
    // startup work beyond the copy.
    const COUNT: usize = count();
    let mut out = [(0u16, 0u16); COUNT];
    let mut n = 0usize;
    let mut i = 0usize;
    while i < SHIFTS.len() {
        let (from, to, delta) = SHIFTS[i];
        let mut unit = from;
        while unit <= to {
            out[n] = (unit, (unit as i32 + delta) as u16);
            n += 1;
            unit += 1;
        }
        i += 1;
    }
    i = 0;
    while i < PAIRED.len() {
        let (from, to) = PAIRED[i];
        let mut unit = from;
        while unit <= to {
            out[n] = (unit, unit - 1);
            n += 1;
            unit += 2;
        }
        i += 1;
    }
    i = 0;
    while i < SINGLES.len() {
        out[n] = SINGLES[i];
        n += 1;
        i += 1;
    }
    out
};

/// How many pairs the rules below produce. # C: O(blocks)
const fn count() -> usize {
    let mut total = 0usize;
    let mut i = 0usize;
    while i < SHIFTS.len() {
        total += (SHIFTS[i].1 - SHIFTS[i].0) as usize + 1;
        i += 1;
    }
    i = 0;
    while i < PAIRED.len() {
        total += ((PAIRED[i].1 - PAIRED[i].0) as usize) / 2 + 1;
        i += 1;
    }
    total + SINGLES.len()
}

/// Blocks whose upper case is a constant distance away: (first, last, delta).
const SHIFTS: &[(u16, u16, i32)] = &[
    // Basic Latin.
    (0x0061, 0x007A, -0x20),
    // Latin-1 Supplement, either side of the division sign.
    (0x00E0, 0x00F6, -0x20),
    (0x00F8, 0x00FE, -0x20),
    // Greek.
    (0x03B1, 0x03C1, -0x20),
    (0x03C3, 0x03CB, -0x20),
    (0x03AD, 0x03AF, -0x25),
    (0x03CD, 0x03CE, -0x3F),
    // Cyrillic, and its supplement.
    (0x0430, 0x044F, -0x20),
    (0x0450, 0x045F, -0x50),
    // Armenian.
    (0x0561, 0x0586, -0x30),
    // Roman numeral forms.
    (0x2170, 0x217F, -0x10),
    // Circled letters.
    (0x24D0, 0x24E9, -0x1A),
    // Glagolitic.
    (0x2C30, 0x2C5E, -0x30),
    // Fullwidth forms.
    (0xFF41, 0xFF5A, -0x20),
];

/// Blocks laid out as upper, lower, upper, lower: (first LOWER, last lower).
const PAIRED: &[(u16, u16)] = &[
    // Latin Extended-A, in its four separately-aligned runs.
    (0x0101, 0x0137),
    (0x013A, 0x0148),
    (0x014B, 0x0177),
    (0x017A, 0x017E),
    // Cyrillic historic and extended letters.
    (0x0461, 0x0481),
    (0x048B, 0x04BF),
    (0x04C2, 0x04CE),
    (0x04D1, 0x052F),
    // Latin Extended Additional.
    (0x1E01, 0x1E95),
    (0x1EA1, 0x1EFF),
];

/// Characters whose upper case is nowhere near them.
const SINGLES: &[(u16, u16)] = &[
    // Micro sign folds to capital Mu.
    (0x00B5, 0x039C),
    // Small y with diaeresis folds to a capital in Latin Extended-A.
    (0x00FF, 0x0178),
    // Long s folds to plain S.
    (0x017F, 0x0053),
    // Both sigmas fold to the same capital.
    (0x03C2, 0x03A3),
    // Accented Greek vowels outside the runs above.
    (0x03AC, 0x0386),
    (0x03CC, 0x038C),
];
