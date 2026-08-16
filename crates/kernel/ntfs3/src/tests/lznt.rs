use super::*;
use crate::uapi::LZNT_CHUNK_SIZE;

#[test]
fn compressible_data_round_trips() {
    let data: alloc::vec::Vec<u8> = core::iter::repeat(b"abcdefgh").take(200).flatten()
        .copied().collect();
    let packed = compress(&data);
    assert!(packed.len() < data.len(), "highly repetitive data must compress");
    assert_eq!(decompress(&packed, data.len()).unwrap(), data);
}

#[test]
fn a_run_of_one_byte_round_trips() {
    // A match that overlaps what it is producing, which is how a run is
    // encoded: copying by block instead of byte at a time gets it wrong.
    let data = alloc::vec![0x5A; 3000];
    let packed = compress(&data);
    assert_eq!(decompress(&packed, data.len()).unwrap(), data);
}

#[test]
fn incompressible_data_round_trips_stored() {
    // A chunk that does not compress is stored whole; compressing regardless
    // writes a unit larger than the data.
    let data: alloc::vec::Vec<u8> = (0..2000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let packed = compress(&data);
    assert_eq!(decompress(&packed, data.len()).unwrap(), data);
}

#[test]
fn data_spanning_several_chunks_round_trips() {
    let data: alloc::vec::Vec<u8> = (0..LZNT_CHUNK_SIZE * 3 + 100)
        .map(|i| ((i / 7) % 251) as u8).collect();
    let packed = compress(&data);
    assert_eq!(decompress(&packed, data.len()).unwrap(), data);
}

#[test]
fn a_stream_shorter_than_the_buffer_leaves_zeros() {
    let data = alloc::vec![b'x'; 100];
    let packed = compress(&data);
    let out = decompress(&packed, 500).unwrap();
    assert_eq!(&out[..100], &data[..]);
    assert!(out[100..].iter().all(|b| *b == 0));
}

#[test]
fn a_header_of_zero_ends_the_stream() {
    let data = alloc::vec![b'y'; 64];
    let mut packed = compress(&data);
    packed.extend_from_slice(&[0, 0]);
    let out = decompress(&packed, 200).unwrap();
    assert_eq!(&out[..64], &data[..]);
    assert!(out[64..].iter().all(|b| *b == 0));
}

#[test]
fn a_chunk_reaching_past_the_bytes_is_refused() {
    // A header claiming more than there is.
    let packed = [0xFF, 0xB0, 0x00, 0x01];
    assert_eq!(decompress(&packed, 4096), Err(LzntError::Truncated));
}

#[test]
fn a_back_reference_before_the_chunk_is_refused() {
    // Flags byte with the first bit set, then a pair whose offset reaches
    // before anything has been produced.
    let mut packed = alloc::vec::Vec::new();
    let body = [0x01u8, 0xFF, 0xFF];
    let header = 0x8000u16 | (body.len() as u16 - 1);
    packed.extend_from_slice(&header.to_le_bytes());
    packed.extend_from_slice(&body);
    assert_eq!(decompress(&packed, 4096), Err(LzntError::BadReference));
}

#[test]
fn a_stream_of_nothing_decompresses_to_zeros() {
    assert_eq!(decompress(&[], 32).unwrap(), alloc::vec![0u8; 32]);
}

#[test]
fn the_window_widens_as_a_chunk_fills() {
    // Two identical matches at different points in one chunk pack into
    // different pairs, because the offset field's width moves; a fixed split
    // decodes every pair after the first sixteen bytes wrongly.
    let mut data = alloc::vec::Vec::new();
    data.extend_from_slice(b"abcdefghij");
    data.extend_from_slice(b"abcdefghij");
    data.extend_from_slice(&alloc::vec![b'z'; 500]);
    data.extend_from_slice(b"abcdefghij");
    let packed = compress(&data);
    assert_eq!(decompress(&packed, data.len()).unwrap(), data);
}
