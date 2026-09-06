use super::*;

#[test]
fn continuation_matches_cross_assembler_instructions() {
    let bytes = encode(0x4e540000000000da);
    let words: std::vec::Vec<u32> = bytes.chunks_exact(4).map(|v| u32::from_le_bytes(v.try_into().unwrap())).collect();
    assert_eq!(words, [0xd10043ff,0xf90003e0,0x910003e0,0xd2800101,0xd2800002,
        0xd2801b48,0xf2a00008,0xf2c00008,0xf2e9ca88,0xd4000001,0xd4200000]);
}

#[test]
fn selector_materialization_preserves_every_halfword() {
    for selector in [0, 0x4e540000000000da, 0x123456789abcdef0, u64::MAX] {
        let bytes = encode(selector);
        let mut decoded = 0;
        for i in 0..4 {
            let at = 20 + i * 4;
            let instruction = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            assert_eq!(instruction & 31, 8);
            decoded |= (((instruction >> 5) & 0xffff) as u64) << (16 * i);
        }
        assert_eq!(decoded, selector);
    }
}
