// Pinned against Linux's kernel siphash self-test vectors — the same key, the
// same 64 vectors, the same `in[i] = i` / `siphash(in, i)` loop. These vectors
// are the SipHash reference implementation's, so a pass
// proves interoperability with Linux and with SipHash itself, not merely
// self-consistency.

use super::*;

/// Linux `test_key_siphash`.
const KEY: Key = Key { k0: 0x0706_0504_0302_0100, k1: 0x0f0e_0d0c_0b0a_0908 };

/// Linux `test_vectors_siphash[64]`.
const VECTORS: [u64; 64] = [
    0x726f_db47_dd0e_0e31, 0x74f8_39c5_93dc_67fd, 0x0d6c_8009_d9a9_4f5a,
    0x8567_6696_d7fb_7e2d, 0xcf27_94e0_2771_87b7, 0x1876_5564_cd99_a68d,
    0xcbc9_466e_58fe_e3ce, 0xab02_00f5_8b01_d137, 0x93f5_f579_9a93_2462,
    0x9e00_82df_0ba9_e4b0, 0x7a5d_bbc5_94dd_b9f3, 0xf4b3_2f46_226b_ada7,
    0x751e_8fbc_860e_e5fb, 0x14ea_5627_c084_3d90, 0xf723_ca90_8e7a_f2ee,
    0xa129_ca61_49be_45e5, 0x3f2a_cc7f_57c2_9bdb, 0x699a_e9f5_2cbe_4794,
    0x4bc1_b3f0_968d_d39c, 0xbb6d_c91d_a779_61bd, 0xbed6_5cf2_1aa2_ee98,
    0xd0f2_cbb0_2e3b_67c7, 0x9353_6795_e3a3_3e88, 0xa80c_038c_cd5c_cec8,
    0xb8ad_50c6_f649_af94, 0xbce1_92de_8a85_b8ea, 0x17d8_35b8_5bbb_15f3,
    0x2f2e_6163_076b_cfad, 0xde4d_aaac_a71d_c9a5, 0xa6a2_5066_8795_6571,
    0xad87_a353_5c49_ef28, 0x32d8_92fa_d841_c342, 0x7127_512f_72f2_7cce,
    0xa7f3_2346_f959_78e3, 0x12e0_b01a_bb05_1238, 0x15e0_34d4_0fa1_97ae,
    0x314d_ffbe_0815_a3b4, 0x0279_90f0_2962_3981, 0xcadc_d4e5_9ef4_0c4d,
    0x9abf_d876_6a33_735c, 0x0e3e_a96b_5304_a7d0, 0xad0c_42d6_fc58_5992,
    0x1873_06c8_9bc2_15a9, 0xd4a6_0abc_f379_2b95, 0xf935_451d_e4f2_1df2,
    0xa953_8f04_1975_5787, 0xdb9a_cddf_f56c_a510, 0xd06c_98cd_5c09_75eb,
    0xe612_a3cb_9ecb_a951, 0xc766_e62c_fcad_af96, 0xee64_435a_9752_fe72,
    0xa192_d576_b245_165a, 0x0a87_87bf_8ecb_74b2, 0x81b3_e73d_20b4_9b6f,
    0x7fa8_220b_a3b2_ecea, 0x2457_31c1_3ca4_2499, 0xb78d_bfaf_3a8d_83bd,
    0xea1a_d565_322a_1a0b, 0x60e6_1c23_a379_5013, 0x6606_d7e4_4628_2b93,
    0x6ca4_ecb1_5c5f_91e1, 0x9f62_6da1_5c96_25f3, 0xe51b_3860_8ef2_5f57,
    0x958a_324c_eb06_4572,
];

#[test]
fn byte_input_matches_every_linux_vector() {
    let mut input = [0u8; VECTORS.len()];
    for i in 0..VECTORS.len() {
        input[i] = i as u8;
        assert_eq!(siphash(&input[..i], &KEY), VECTORS[i], "vector {i}");
    }
}

#[test]
fn word_fast_paths_agree_with_the_vectors_they_index() {
    // Linux checks each fixed-arity form against the byte vector of the same
    // length; a packing bug in `pair()` shows up here and nowhere else.
    assert_eq!(siphash_1u64(0x0706_0504_0302_0100, &KEY), VECTORS[8]);
    assert_eq!(siphash_2u64(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908, &KEY), VECTORS[16]);
    assert_eq!(siphash_3u64(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908,
                            0x1716_1514_1312_1110, &KEY), VECTORS[24]);
    assert_eq!(siphash_4u64(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908,
                            0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918, &KEY), VECTORS[32]);
    assert_eq!(siphash_1u32(0x0302_0100, &KEY), VECTORS[4]);
    assert_eq!(siphash_2u32(0x0302_0100, 0x0706_0504, &KEY), VECTORS[8]);
    assert_eq!(siphash_3u32(0x0302_0100, 0x0706_0504, 0x0b0a_0908, &KEY), VECTORS[12]);
    assert_eq!(siphash_4u32(0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c, &KEY),
               VECTORS[16]);
}

#[test]
fn output_depends_on_every_key_bit_half() {
    // The whole security argument is "unpredictable without the key". If a
    // half of the key were dropped on the floor (a plausible porting slip in
    // PREAMBLE), the hash would still look random but be forgeable from a
    // 64-bit search. Both halves must matter.
    let base = siphash_3u32(1, 2, 3, &KEY);
    let flip0 = Key { k0: KEY.k0 ^ 1, k1: KEY.k1 };
    let flip1 = Key { k0: KEY.k0, k1: KEY.k1 ^ 1 };
    assert_ne!(base, siphash_3u32(1, 2, 3, &flip0), "k0 is not mixed in");
    assert_ne!(base, siphash_3u32(1, 2, 3, &flip1), "k1 is not mixed in");
}

#[test]
fn length_is_bound_into_the_hash() {
    // Linux stages `len << 56` in `b`, so a zero byte appended must change the
    // output. Without it, siphash("a") == siphash("a\0") and the padding is
    // forgeable.
    assert_ne!(siphash(&[1u8], &KEY), siphash(&[1u8, 0], &KEY));
    assert_ne!(siphash(&[], &KEY), siphash(&[0u8], &KEY));
}

#[test]
fn key_from_bytes_reads_little_endian_like_linux() {
    let raw: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    assert_eq!(Key::from_bytes(&raw), KEY);
}
