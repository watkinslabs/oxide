//! Algorithmic Hangul syllable decomposition (Unicode core specification,
//! "Hangul Syllable Decomposition"). Excluded from the generated table because
//! all 11172 syllables follow the arithmetic below; the generator's self-test
//! checks the arithmetic against the database for every one of them.

const SBASE: u32 = 0xAC00;
const LBASE: u32 = 0x1100;
const VBASE: u32 = 0x1161;
const TBASE: u32 = 0x11A7;
const LCOUNT: u32 = 19;
const VCOUNT: u32 = 21;
const TCOUNT: u32 = 28;
const NCOUNT: u32 = VCOUNT * TCOUNT;
const SCOUNT: u32 = LCOUNT * NCOUNT;

/// Longest decomposition: leading, vowel, trailing jamo.
pub(crate) const MAX_JAMO: u8 = 3;

/// # C: O(1)
pub(crate) fn is_syllable(cp: u32) -> bool { cp >= SBASE && cp < SBASE + SCOUNT }

/// Number of jamo `cp` decomposes to (2 without a trailing jamo, 3 with).
/// # C: O(1)
pub(crate) fn jamo_count(cp: u32) -> u8 {
    if (cp - SBASE) % TCOUNT == 0 { MAX_JAMO - 1 } else { MAX_JAMO }
}

/// `idx`-th jamo of the decomposition of syllable `cp`. Every jamo is a starter
/// (combining class 0), so a decomposed syllable never reorders. # C: O(1)
pub(crate) fn jamo(cp: u32, idx: u8) -> u32 {
    let si = cp - SBASE;
    match idx {
        0 => LBASE + si / NCOUNT,
        1 => VBASE + (si % NCOUNT) / TCOUNT,
        _ => TBASE + si % TCOUNT,
    }
}
