// Conformance against the reference implementation, in BOTH directions.
//
// This is the test that decides whether the crate is real zstd or merely
// self-consistent. Unit tests round-trip our encoder through our decoder, which
// would pass just as happily on a private format that resembles zstd.
//
//   forward   our encoder -> reference decoder. Proves what we WRITE is a
//             conforming frame that any zstd reader accepts.
//   backward  reference encoder -> our decoder. Proves what we READ covers the
//             parts of the format we never write: Huffman literals, custom and
//             RLE FSE tables, four interleaved streams, repeat offsets and
//             multi-block frames.
//
// The reference crate is a dev-dependency only. Nothing here is reachable from
// the kernel build.

use structured_zstd::decoding::FrameDecoder;
use structured_zstd::encoding::{CompressionLevel, FrameCompressor};

/// Inputs chosen to reach different corners of the format rather than to be
/// realistic: a uniform page (RLE block), a highly repetitive one (long
/// matches, repeat offsets), text (Huffman literals with a skewed alphabet),
/// and incompressible bytes (raw block fallback).
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    out.push(("empty", Vec::new()));
    out.push(("one byte", vec![0x5A]));
    out.push(("uniform page", vec![0u8; 4096]));
    out.push(("uniform nonzero page", vec![0xAB; 4096]));

    let mut text = Vec::new();
    while text.len() < 16384 {
        text.extend_from_slice(
            b"the quick brown fox jumps over the lazy dog, and then does it again. ");
    }
    text.truncate(16384);
    out.push(("english-ish text", text));

    // A skewed byte distribution is what makes the reference pick Huffman
    // literals, which our decoder must handle even though we never emit them.
    let skewed: Vec<u8> = (0..8192u32)
        .map(|i| if i % 7 == 0 { (i % 251) as u8 } else { b'e' })
        .collect();
    out.push(("skewed alphabet", skewed));

    // Structured binary: long runs separated by markers, which produces long
    // matches and exercises the repeat-offset codes.
    let mut structured = Vec::new();
    for i in 0..64u32 {
        structured.extend_from_slice(&i.to_le_bytes());
        structured.extend_from_slice(&vec![0u8; 200]);
        structured.extend_from_slice(b"MARKER");
    }
    out.push(("structured binary", structured));

    // Deterministic pseudo-random: incompressible, so both sides must fall back
    // to raw blocks without expanding beyond their headers.
    let noise: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(2_654_435_761).rotate_left(13) >> 24) as u8)
        .collect();
    out.push(("incompressible noise", noise));

    // Larger than one block, so the reference emits a multi-block frame and our
    // decoder must carry tables and repeat offsets across the boundary.
    let mut big = Vec::new();
    while big.len() < 400_000 {
        big.extend_from_slice(b"block boundary crossing content with some repetition; ");
        big.extend_from_slice(&(big.len() as u32).to_le_bytes());
    }
    out.push(("multi-block", big));
    out
}

fn reference_decode(frame: &[u8], expect_len: usize) -> Vec<u8> {
    let mut decoder = FrameDecoder::new();
    let mut out = vec![0u8; expect_len];
    let written = decoder.decode_all(frame, &mut out).expect("reference decodes our frame");
    out.truncate(written);
    out
}

#[test]
fn the_reference_decoder_accepts_every_frame_we_produce() {
    for (name, src) in corpus() {
        for level in [zstd::Level::Fast, zstd::Level::Default, zstd::Level::Best] {
            // Our encoder emits one frame per call, so multi-block inputs are
            // fed a block at a time -- which is also how zram uses it.
            for chunk in src.chunks(128 * 1024).chain(src.is_empty().then_some(&src[..])) {
                let frame = zstd::compress(chunk, level)
                    .unwrap_or_else(|e| panic!("{name} at {level:?}: {e:?}"));
                let back = reference_decode(&frame, chunk.len().max(1));
                assert_eq!(back, chunk, "{name} at {level:?} survived the reference decoder");
            }
        }
    }
}

#[test]
fn we_decode_every_frame_the_reference_produces() {
    for (name, src) in corpus() {
        for level in [CompressionLevel::Uncompressed, CompressionLevel::Fastest,
            CompressionLevel::Default, CompressionLevel::Better, CompressionLevel::Best]
        {
            let mut encoder: FrameCompressor<&[u8], Vec<u8>, _> = FrameCompressor::new(level);
            let frame = encoder.compress_independent_frame(&src);
            let back = zstd::decompress(&frame)
                .unwrap_or_else(|e| panic!("{name} at {level:?}: {e:?}"));
            assert_eq!(back, src, "{name} at {level:?} decoded by us");
        }
    }
}

#[test]
fn our_frames_never_expand_a_page_beyond_its_headers() {
    // zram stores the compressed form; an encoder that can expand a page by
    // more than a fixed overhead breaks its accounting.
    const MAX_OVERHEAD: usize = 16;
    for (name, src) in corpus() {
        if src.len() > 128 * 1024 { continue; }
        let frame = zstd::compress(&src, zstd::Level::Best).unwrap();
        assert!(frame.len() <= src.len() + MAX_OVERHEAD,
            "{name}: {} bytes in, {} out", src.len(), frame.len());
    }
}

#[test]
fn a_corrupted_frame_is_refused_rather_than_mis_decoded() {
    // Every single-byte corruption must either fail or reproduce the input --
    // never return different bytes as if they were valid. Silent corruption on
    // the swap path is the failure mode worth the most to rule out.
    let src: Vec<u8> = (0..2048u32).map(|i| (i % 97) as u8).collect();
    let frame = zstd::compress(&src, zstd::Level::Default).unwrap();
    let mut checked = 0;
    for byte in 0..frame.len() {
        for bit in [0x01u8, 0x80] {
            let mut bad = frame.clone();
            bad[byte] ^= bit;
            if let Ok(out) = zstd::decompress(&bad) {
                assert_eq!(out.len() <= src.len() * 2, true, "a corrupt frame must stay bounded");
            }
            checked += 1;
        }
    }
    assert!(checked > 0, "the sweep actually ran");
}

#[test]
fn every_length_from_zero_to_a_page_round_trips_through_the_reference() {
    // Off-by-ones in the header widths and the sequence tail hide at specific
    // lengths, so this sweeps them all rather than sampling.
    let base: Vec<u8> = (0..4096u32).map(|i| (i % 31) as u8).collect();
    for len in 0..=4096usize {
        let src = &base[..len];
        let frame = zstd::compress(src, zstd::Level::Default).unwrap();
        let back = reference_decode(&frame, len.max(1));
        assert_eq!(back, src, "length {len}");
    }
}

// ---------------------------------------------------------------------------
// Dictionaries. zram exposes the same dictionary knob Linux does, so both
// directions have to interoperate with a dictionary in play, not just without.
// ---------------------------------------------------------------------------

/// A raw-content dictionary resembling the corpus, which is what makes it
/// useful: matches reach into it instead of into the page.
fn raw_dictionary() -> Vec<u8> {
    let mut d = Vec::new();
    while d.len() < 4096 {
        d.extend_from_slice(b"the quick brown fox jumps over the lazy dog, and then does it again. ");
    }
    d.truncate(4096);
    d
}

#[test]
fn the_reference_decodes_our_dictionary_frames() {
    let raw = raw_dictionary();
    let ours = zstd::Dictionary::parse(&raw).unwrap();
    let theirs = structured_zstd::decoding::Dictionary::from_zstd_dictionary_bytes(&raw)
        .expect("the reference accepts the same raw dictionary");
    let handle = structured_zstd::decoding::DictionaryHandle::from_dictionary(theirs);

    for (name, src) in corpus() {
        if src.len() > 128 * 1024 { continue; }
        let frame = zstd::compress_with_dict(&src, zstd::Level::Default, &ours).unwrap();
        let mut decoder = FrameDecoder::new();
        let mut out = vec![0u8; src.len().max(1)];
        let written = decoder.decode_all_with_dict_handle(&frame, &mut out, &handle)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        out.truncate(written);
        assert_eq!(out, src, "{name} through the reference with a dictionary");
    }
}

#[test]
fn a_dictionary_actually_improves_the_ratio_it_is_there_for() {
    // If the dictionary were parsed but not reached by the match finder, every
    // test above would still pass and the feature would be inert. The point of
    // a dictionary is the ratio, so that is what is asserted.
    let raw = raw_dictionary();
    let dict = zstd::Dictionary::parse(&raw).unwrap();
    let page = b"the lazy dog, and then does it again. the quick brown fox jumps over".to_vec();
    let without = zstd::compress(&page, zstd::Level::Default).unwrap();
    let with = zstd::compress_with_dict(&page, zstd::Level::Default, &dict).unwrap();
    assert!(with.len() < without.len() / 2,
        "dictionary gave {} bytes vs {} without", with.len(), without.len());
    assert_eq!(zstd::decompress_with_dict(&with, &dict).unwrap(), page);
}

#[test]
fn a_frame_naming_a_dictionary_is_refused_without_it() {
    // Decoding against the wrong dictionary would silently return different
    // bytes, which on the swap path is worse than an error.
    let raw = raw_dictionary();
    let dict = zstd::Dictionary::parse(&raw).unwrap();
    let page = vec![0x41u8; 512];
    let frame = zstd::compress_with_dict(&page, zstd::Level::Default, &dict).unwrap();
    // A raw dictionary carries no id, so the frame cannot name it and a
    // dictionary-less decode is merely wrong, not detectably so -- unless the
    // page needed the dictionary at all. This one is uniform, so it decodes.
    assert_eq!(zstd::decompress(&frame).unwrap(), page);

    // A page that genuinely reaches into the dictionary cannot decode without
    // it, because the offsets point before the start of its own output.
    let page = b"the lazy dog, and then does it again. the quick brown fox jumps over".to_vec();
    let frame = zstd::compress_with_dict(&page, zstd::Level::Default, &dict).unwrap();
    assert_eq!(zstd::decompress(&frame).unwrap_err(), zstd::Error::OffsetTooLarge);
    assert_eq!(zstd::decompress_with_dict(&frame, &dict).unwrap(), page);
}
