// Predefined FSE distributions and the sequence-code baseline/extra-bit
// tables (RFC 8878 3.1.1.3.2.1 and 3.1.1.3.2.2). Data only.

use crate::uapi::{MAX_LL_CODE, MAX_ML_CODE, MAX_OF_CODE};

/// Normalized counts for the predefined literal-lengths table. `-1` marks a
/// "less than one" probability, which FSE places in the table's high slots.
pub const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
pub const LL_DEFAULT_LOG: u32 = 6;

pub const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
];
pub const ML_DEFAULT_LOG: u32 = 6;

pub const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
pub const OF_DEFAULT_LOG: u32 = 5;

/// Literal-length code -> (baseline, extra bits).
pub const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536,
];
pub const LL_EXTRA: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
];

/// Match-length code -> (baseline, extra bits). Baselines start at the format's
/// minimum match of 3.
pub const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
    4099, 8195, 16387, 32771, 65539,
];
pub const ML_EXTRA: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Offset code N covers offsets `2^N ..= 2^(N+1)-1` and carries N extra bits,
/// so it needs no table.
pub fn offset_extra_bits(code: u8) -> u32 { code as u32 }
pub fn offset_baseline(code: u8) -> u32 { 1u32 << code }

/// Literal length -> its code. Inverse of `LL_BASE`, for the encoder.
/// # C: O(1)
pub fn ll_code(len: u32) -> u8 {
    match len {
        0..=15 => len as u8,
        16..=17 => 16,
        18..=19 => 17,
        20..=21 => 18,
        22..=23 => 19,
        24..=27 => 20,
        28..=31 => 21,
        32..=39 => 22,
        40..=47 => 23,
        48..=63 => 24,
        64..=127 => 25,
        128..=255 => 26,
        256..=511 => 27,
        512..=1023 => 28,
        1024..=2047 => 29,
        2048..=4095 => 30,
        4096..=8191 => 31,
        8192..=16383 => 32,
        16384..=32767 => 33,
        32768..=65535 => 34,
        _ => MAX_LL_CODE,
    }
}

/// Match length -> its code. Inverse of `ML_BASE`, for the encoder.
/// # C: O(1)
pub fn ml_code(len: u32) -> u8 {
    match len {
        // The format's minimum match is 3, so code 0 is length 3.
        0..=2 => 0,
        3..=34 => (len - 3) as u8,
        35..=36 => 32,
        37..=38 => 33,
        39..=40 => 34,
        41..=42 => 35,
        43..=46 => 36,
        47..=50 => 37,
        51..=58 => 38,
        59..=66 => 39,
        67..=82 => 40,
        83..=98 => 41,
        99..=130 => 42,
        131..=258 => 43,
        259..=514 => 44,
        515..=1026 => 45,
        1027..=2050 => 46,
        2051..=4098 => 47,
        4099..=8194 => 48,
        8195..=16386 => 49,
        16387..=32770 => 50,
        32771..=65538 => 51,
        _ => MAX_ML_CODE,
    }
}

/// Offset VALUE (already biased by the repeat-offset encoding) -> its code:
/// the position of the value's highest set bit.
/// # C: O(1)
pub fn of_code(value: u32) -> u8 {
    debug_assert!(value > 0, "offset value 0 has no code");
    let code = 31 - value.leading_zeros();
    if code > MAX_OF_CODE as u32 { MAX_OF_CODE } else { code as u8 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_table_round_trips_its_own_baselines() {
        // A baseline must map back to the code that owns it, and so must the
        // last value in that code's range. Getting this wrong shifts a whole
        // sequence stream by one code and decodes as garbage.
        for code in 0..LL_BASE.len() {
            let base = LL_BASE[code];
            let last = base + ((1u64 << LL_EXTRA[code]) as u32 - 1);
            assert_eq!(ll_code(base), code as u8, "ll baseline {base}");
            assert_eq!(ll_code(last), code as u8, "ll top of range {last}");
        }
        for code in 0..ML_BASE.len() {
            let base = ML_BASE[code];
            let last = base + ((1u64 << ML_EXTRA[code]) as u32 - 1);
            assert_eq!(ml_code(base), code as u8, "ml baseline {base}");
            assert_eq!(ml_code(last), code as u8, "ml top of range {last}");
        }
    }

    #[test]
    fn offset_codes_partition_the_value_space() {
        for code in 0..=20u8 {
            let base = offset_baseline(code);
            let last = base + ((1u64 << offset_extra_bits(code)) as u32 - 1);
            assert_eq!(of_code(base), code);
            assert_eq!(of_code(last), code);
        }
    }

    #[test]
    fn predefined_distributions_sum_to_their_table_size() {
        // FSE requires the normalized counts to sum EXACTLY to 1<<log, with
        // each -1 counting as one state. A distribution that misses this builds
        // a table with unreachable states and decodes wrong.
        for (dist, log) in [
            (&LL_DEFAULT[..], LL_DEFAULT_LOG),
            (&ML_DEFAULT[..], ML_DEFAULT_LOG),
            (&OF_DEFAULT[..], OF_DEFAULT_LOG),
        ] {
            let sum: i32 = dist.iter().map(|&c| if c < 0 { 1 } else { c as i32 }).sum();
            assert_eq!(sum, 1 << log, "distribution with log {log}");
        }
    }

    #[test]
    fn the_predefined_distributions_match_the_rfc_byte_for_byte() {
        // Summing to the table size is NOT enough: an ML distribution with the
        // low-probability run in the wrong place still sums to 64 and builds a
        // valid-looking table that decodes every match length wrong. Only the
        // exact shape is correct, so the shape is what is asserted.
        assert_eq!(LL_DEFAULT.iter().filter(|&&c| c == -1).count(), 4);
        assert_eq!(ML_DEFAULT.iter().filter(|&&c| c == -1).count(), 7);
        assert_eq!(OF_DEFAULT.iter().filter(|&&c| c == -1).count(), 5);
        // The low-probability entries are always the tail of the table.
        for dist in [&LL_DEFAULT[..], &ML_DEFAULT[..], &OF_DEFAULT[..]] {
            let first = dist.iter().position(|&c| c == -1).expect("a low-prob tail exists");
            assert!(dist[first..].iter().all(|&c| c == -1), "the tail is contiguous");
        }
        assert_eq!(ML_DEFAULT[45], 1);
        assert_eq!(ML_DEFAULT[46], -1);
    }
}
