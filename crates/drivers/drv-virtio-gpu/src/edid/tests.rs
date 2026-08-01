use super::*;
use crate::wire::{
    VIRTIO_GPU_CMD_GET_EDID, VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID, VIRTIO_GPU_RESP_OK_NODATA,
};

const OTHER_SCANOUT: u32 = 3;
const SENTINEL: u8 = 0xa5;

fn ok_response(size: u32, fill: u8) -> [u8; RESP_EDID_LEN] {
    let mut resp = [0u8; RESP_EDID_LEN];
    write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_EDID);
    write_u32_le(&mut resp, RESP_EDID_SIZE_OFF, size);
    for b in &mut resp[RESP_EDID_DATA_OFF..] { *b = fill; }
    resp
}

/// A response whose blob field carries a well-formed EDID base block.
fn response_with_block(block: &[u8]) -> [u8; RESP_EDID_LEN] {
    let mut resp = ok_response(block.len() as u32, 0);
    resp[RESP_EDID_DATA_OFF..RESP_EDID_DATA_OFF + block.len()].copy_from_slice(block);
    resp
}

fn valid_block() -> [u8; drm::edid::BLOCK_LEN] {
    let mut b = [0u8; drm::edid::BLOCK_LEN];
    b[..drm::edid::HEADER.len()].copy_from_slice(&drm::edid::HEADER);
    b[drm::edid::BLOCK_LEN - 1] = drm::edid::computed_checksum(&b);
    b
}

#[test]
fn the_request_is_a_header_plus_scanout_and_padding() {
    assert_eq!(GET_EDID_REQ_LEN, 32);
    assert_eq!((GET_EDID_SCANOUT_OFF, GET_EDID_PADDING_OFF), (24, 28));
    let mut buf = [SENTINEL; GET_EDID_REQ_LEN + 8];
    let n = encode_get_edid(&mut buf, OTHER_SCANOUT);
    assert_eq!(n, GET_EDID_REQ_LEN);
    assert_eq!(read_u32_le(&buf, 0), VIRTIO_GPU_CMD_GET_EDID);
    assert_eq!(read_u32_le(&buf, GET_EDID_SCANOUT_OFF), OTHER_SCANOUT);
    assert_eq!(read_u32_le(&buf, GET_EDID_PADDING_OFF), 0);
    // Bytes past the request are the caller's, never written.
    assert!(buf[GET_EDID_REQ_LEN..].iter().all(|b| *b == SENTINEL));
}

#[test]
fn a_short_request_buffer_encodes_nothing() {
    let mut buf = [SENTINEL; GET_EDID_REQ_LEN - 1];
    assert_eq!(encode_get_edid(&mut buf, PRIMARY_SCANOUT), 0);
    assert!(buf.iter().all(|b| *b == SENTINEL));
}

#[test]
fn the_response_is_a_header_size_padding_and_a_fixed_blob_field() {
    assert_eq!((RESP_EDID_SIZE_OFF, RESP_EDID_PADDING_OFF, RESP_EDID_DATA_OFF), (24, 28, 32));
    assert_eq!(EDID_MAX_BYTES, 1024);
    assert_eq!(RESP_EDID_LEN, 1056);
}

#[test]
fn only_the_bytes_the_device_filled_are_returned() {
    let resp = ok_response(128, 0x5a);
    let bytes = parse_edid_bytes(&resp).expect("an OK EDID response");
    assert_eq!(bytes.len(), 128);
    assert!(bytes.iter().all(|b| *b == 0x5a));
}

#[test]
fn a_size_past_the_field_is_clamped_rather_than_trusted() {
    let resp = ok_response(u32::MAX, 0x11);
    assert_eq!(parse_edid_bytes(&resp).unwrap().len(), EDID_MAX_BYTES);
}

#[test]
fn a_zero_size_response_yields_no_bytes() {
    let resp = ok_response(0, 0x11);
    assert!(parse_edid_bytes(&resp).unwrap().is_empty());
}

#[test]
fn a_non_edid_response_type_is_rejected() {
    for ty in [VIRTIO_GPU_RESP_OK_NODATA, VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID] {
        let mut resp = ok_response(128, 0);
        write_u32_le(&mut resp, 0, ty);
        assert_eq!(parse_edid_bytes(&resp), Err(Error::BadResp(ty)));
    }
}

#[test]
fn a_truncated_response_is_rejected() {
    let resp = ok_response(128, 0);
    assert_eq!(parse_edid_bytes(&resp[..RESP_EDID_LEN - 1]), Err(Error::Inval));
}

#[test]
fn the_command_is_issued_only_when_the_feature_was_negotiated() {
    assert!(should_fetch(1u64 << VIRTIO_GPU_F_EDID));
    assert!(!should_fetch(0));
    // Every other negotiated bit leaves the command unsent.
    assert!(!should_fetch(!(1u64 << VIRTIO_GPU_F_EDID)));
}

#[test]
fn a_well_formed_block_is_accepted_and_kept_at_its_reported_length() {
    let block = valid_block();
    let resp = response_with_block(&block);
    let bytes = parse_edid_bytes(&resp).unwrap();
    let kept = accept_edid(bytes).expect("a valid base block is kept");
    assert_eq!(kept.len(), drm::edid::BLOCK_LEN);
    assert_eq!(&kept[..], &block[..]);
}

#[test]
fn a_blob_that_is_not_an_edid_block_is_discarded() {
    // A device that reports a size but fills the field with nothing usable.
    let resp = ok_response(drm::edid::BLOCK_LEN as u32, 0x5a);
    assert!(accept_edid(parse_edid_bytes(&resp).unwrap()).is_none());

    // A block whose checksum does not agree.
    let mut block = valid_block();
    block[drm::edid::BLOCK_LEN - 1] ^= 0xff;
    assert!(accept_edid(parse_edid_bytes(&response_with_block(&block)).unwrap()).is_none());

    // A device reporting fewer bytes than a base block holds.
    let short = ok_response(8, 0);
    assert!(accept_edid(parse_edid_bytes(&short).unwrap()).is_none());
}
