use super::*;

const BLOCKS: [SackBlock; 1] = [SackBlock { left: 10, right: 20 }];
const FOUR_BLOCKS: [SackBlock; 4] = [
    SackBlock { left: 10, right: 20 },
    SackBlock { left: 30, right: 40 },
    SackBlock { left: 50, right: 60 },
    SackBlock { left: 70, right: 80 },
];

#[test]
fn timestamp_and_sack_share_one_established_option_encoder() {
    let bytes = append(Some((1, 2)), &BLOCKS, b"body");
    assert_eq!(&bytes[..22], &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2,
        5, 10, 0, 0, 0, 10, 0, 0, 0, 20]);
    assert_eq!(&bytes[22..24], &[1, 1]);
    assert_eq!(&bytes[24..], b"body");
}

#[test]
fn sack_without_timestamp_keeps_its_leading_padding() {
    assert_eq!(append(None, &BLOCKS, &[]),
        [1, 1, 5, 10, 0, 0, 0, 10, 0, 0, 0, 20].to_vec());
}

#[test]
fn timestamp_reserves_header_space_by_limiting_sack_blocks() {
    let options = SegmentOptions { timestamp: Some((1, 2)), sacks: &FOUR_BLOCKS };
    let bytes = append(options.timestamp, options.sacks, &[]);

    assert_eq!(options.encoded_len(), 40);
    assert_eq!(bytes.len(), 40);
    assert_eq!(bytes[13], 26);
    assert_eq!(&bytes[38..], &[1, 1]);
}
