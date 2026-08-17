// The frame shape a filesystem's streaming compressor produces, decoded here.
//
// The unit tests and `conformance.rs` both exercise frames that DECLARE their
// content size, because that is the shape this crate's encoder writes and the
// shape the reference's one-shot compressor writes. A streaming producer writes
// a different header: no content size at all, and a WINDOW DESCRIPTOR in its
// place. A decoder that reads the frame content size field unconditionally, or
// that refuses a frame whose size it cannot know in advance, passes every
// existing test in this crate and then mis-reads every cluster on a real
// volume.
//
// f2fs compresses a cluster with the streaming interface and a window fixed at
// the cluster size, ending the stream in the same call. So its clusters are
// exactly: multi-segment header, window descriptor of `page << log_cluster`,
// no content size, one or more blocks, last-block flag, no checksum. Those are
// the frames below.

use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};
use structured_zstd::io_nostd::Write;

/// The window a cluster of `1 << log_cluster` pages asks for.
const PAGE: usize = 4096;
/// The format's cluster-size log runs from 2 to 8 blocks.
const LOG_CLUSTER_MIN: u32 = 2;
const LOG_CLUSTER_MAX: u32 = 8;

/// Compress `src` the way a streaming producer does: content size unknown at
/// header time, stream ended in the same pass.
fn stream_compress(src: &[u8]) -> Vec<u8> {
    let mut enc = StreamingEncoder::new(Vec::new(), CompressionLevel::Default);
    enc.set_content_size_flag(false).expect("the flag is settable before any write");
    enc.write_all(src).expect("the drain is a Vec");
    enc.finish().expect("ending the stream flushes the last block")
}

/// A cluster's worth of plausible file content, deterministic per size.
fn cluster_content(len: usize, seed: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed | 1;
    while v.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // Mostly repetitive so the encoder emits real sequences rather than
        // falling back to raw blocks, with enough variation to force literals.
        if x % 11 == 0 { v.push((x >> 16) as u8); } else { v.extend_from_slice(b"cluster content "); }
    }
    v.truncate(len);
    v
}

#[test]
fn a_streaming_frame_states_no_content_size_and_still_decodes() {
    // The precondition IS the test: if the producer stamped a content size the
    // frame would not be the shape under examination and the check below would
    // be vacuous.
    let src = cluster_content(4 * PAGE, 7);
    let frame = stream_compress(&src);
    let fhd = frame[4];
    const FHD_SINGLE_SEGMENT: u8 = 1 << 5;
    const FHD_FCS_SHIFT: u8 = 6;
    assert_eq!(fhd & FHD_SINGLE_SEGMENT, 0, "a streaming frame is multi-segment");
    assert_eq!(fhd >> FHD_FCS_SHIFT, 0, "a streaming frame declares no content size");

    assert_eq!(zstd::decompress(&frame).expect("streaming frame decodes"), src);
}

#[test]
fn every_cluster_width_the_format_admits_round_trips_through_the_reference() {
    for log in LOG_CLUSTER_MIN..=LOG_CLUSTER_MAX {
        let len = PAGE << log;
        let src = cluster_content(len, log);
        let frame = stream_compress(&src);
        let got = zstd::decompress(&frame).unwrap_or_else(|e| panic!("log {log}: {e:?}"));
        assert_eq!(got, src, "cluster log {log}");

        // The caller-owned-buffer entry point is the one a filesystem uses; a
        // whole cluster must come out of it, not a short read.
        let mut dst = vec![0u8; len];
        assert_eq!(zstd::decompress_into(&frame, &mut dst).unwrap(), len, "cluster log {log}");
        assert_eq!(dst, src, "cluster log {log}");
    }
}

#[test]
fn a_cluster_that_does_not_compress_still_round_trips() {
    // Incompressible content makes the producer emit raw blocks under the same
    // streaming header; the decoder must not assume a compressed block.
    let noise: Vec<u8> = (0..(4u32 * PAGE as u32))
        .map(|i| (i.wrapping_mul(2_654_435_761).rotate_left(11) >> 24) as u8)
        .collect();
    let frame = stream_compress(&noise);
    assert_eq!(zstd::decompress(&frame).unwrap(), noise);
}

#[test]
fn a_uniform_cluster_round_trips() {
    for byte in [0u8, 0xFF] {
        let src = vec![byte; 8 * PAGE];
        assert_eq!(zstd::decompress(&stream_compress(&src)).unwrap(), src);
    }
}

#[test]
fn our_own_frames_stay_inside_a_clusters_budget_when_the_data_compresses() {
    // A filesystem gives the codec one block less than the cluster, minus its
    // own header. Output that does not fit is not an error there — the cluster
    // is stored plain — but a codec that cannot beat that budget on plainly
    // repetitive data would make the feature useless.
    const F2FS_HEADER: usize = 8;
    for log in LOG_CLUSTER_MIN..=LOG_CLUSTER_MAX {
        let len = PAGE << log;
        let budget = len - PAGE - F2FS_HEADER;
        let src: Vec<u8> = core::iter::repeat(b"the same sixteen".as_slice())
            .flatten().copied().take(len).collect();
        let out = zstd::compress(&src, zstd::Level::Default).expect("repetitive data compresses");
        assert!(out.len() <= budget, "cluster log {log}: {} > {budget}", out.len());
        // And it is a frame the reference reads, not merely one we read.
        let mut dec = structured_zstd::decoding::FrameDecoder::new();
        let mut back = vec![0u8; len];
        let n = dec.decode_all(&out, &mut back).expect("reference decodes our cluster");
        assert_eq!(n, len);
        assert_eq!(back, src, "cluster log {log}");
    }
}
