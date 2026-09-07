//! CRC-32 contracts: the published check value, the empty run, the residue's
//! continuation property, and the byte order the reflected form implies.

use super::checksum::accumulate;

#[test]
fn the_published_check_value_reproduces() {
    assert_eq!(accumulate(0, b"123456789"), 0xcbf4_3926);
}

#[test]
fn an_empty_run_returns_the_residue_unchanged() {
    for residue in [0, 1, 0xcbf4_3926, 0xffff_ffff] {
        assert_eq!(accumulate(residue, b""), residue);
    }
}

#[test]
fn a_split_run_continues_one_checksum() {
    let whole = accumulate(0, b"123456789");
    let split = accumulate(accumulate(0, b"1234"), b"56789");
    assert_eq!(whole, split);
    let thirds = accumulate(accumulate(accumulate(0, b"123"), b"456"), b"789");
    assert_eq!(whole, thirds);
}

#[test]
fn single_bytes_match_the_reflected_table() {
    assert_eq!(accumulate(0, &[0x00]), 0xd202_ef8d);
    assert_eq!(accumulate(0, &[0xff]), 0xff00_0000);
    assert_eq!(accumulate(0, b"a"), 0xe8b7_be43);
}

#[test]
fn byte_order_changes_the_answer() {
    assert_ne!(accumulate(0, b"ab"), accumulate(0, b"ba"));
}

#[test]
fn a_thousand_zero_bytes_match_the_published_vector() {
    assert_eq!(accumulate(0, &[0u8; 1000]), 0x060b_1780);
}
