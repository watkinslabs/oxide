//! Which files get compressed, with which codec, at which level.

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_ZSTD};
use crate::compress::policy::{
    context, flag_word, log_size_valid, matches_extension, wants_compression,
};
use crate::compress::Algorithm;

#[test]
fn only_a_codec_with_a_high_compression_mode_takes_a_level() {
    for a in [Algorithm::Lzo, Algorithm::LzoRle, Algorithm::Lz4] {
        assert!(a.level_valid(0), "{a:?}");
        for lvl in 1..=22u8 { assert!(!a.level_valid(lvl), "{a:?} level {lvl}"); }
    }
    assert!(!Algorithm::Zstd.level_valid(0));
    assert!(Algorithm::Zstd.level_valid(1) && Algorithm::Zstd.level_valid(22));
    assert!(!Algorithm::Zstd.level_valid(23));
}

#[test]
fn the_level_rides_in_the_top_byte_and_the_checksum_bit_in_the_bottom() {
    assert_eq!(flag_word(Algorithm::Lz4, false, 0), 0);
    assert_eq!(flag_word(Algorithm::Lz4, true, 0), 1);
    // A codec with no levels stores none, however loudly it was asked for.
    assert_eq!(flag_word(Algorithm::Lzo, true, 5), 1);
    assert_eq!(flag_word(Algorithm::Zstd, false, 5), 5 << 8);
    assert_eq!(flag_word(Algorithm::Zstd, true, 5), (5 << 8) | 1);
}

#[test]
fn the_stored_flag_word_reads_back_as_the_level_and_the_bit_it_was_built_from() {
    let w = flag_word(Algorithm::Zstd, true, 7);
    assert_eq!(crate::compress::algo::level(w), 7);
    assert!(crate::compress::algo::checksummed(w));
}

#[test]
fn only_the_widths_the_format_admits_are_accepted() {
    for log in 0u8..=1 { assert!(!log_size_valid(log), "log {log}"); }
    for log in 2u8..=8 { assert!(log_size_valid(log), "log {log}"); }
    for log in 9u8..=32 { assert!(!log_size_valid(log), "log {log}"); }
}

#[test]
fn settings_this_build_cannot_write_produce_no_context_at_all() {
    assert_eq!(context(COMPRESS_LZ4, 4, true, 0), Some((COMPRESS_LZ4, 4, 1)));
    assert_eq!(context(COMPRESS_LZO, 2, false, 0), Some((COMPRESS_LZO, 2, 0)));
    assert_eq!(context(COMPRESS_LZORLE, 8, true, 0), Some((COMPRESS_LZORLE, 8, 1)));
    // A codec this build cannot unpack, a level a codec has no meaning for,
    // and a width outside the format: each one is refused rather than stored.
    assert_eq!(context(COMPRESS_ZSTD, 4, false, 3), None);
    assert_eq!(context(COMPRESS_LZ4, 4, false, 3), None);
    assert_eq!(context(COMPRESS_LZ4, 1, false, 0), None);
    assert_eq!(context(9, 4, false, 0), None);
}

#[test]
fn an_extension_matches_the_last_dotted_component() {
    assert!(matches_extension(b"report.txt", b"txt"));
    assert!(matches_extension(b"a.b.txt", b"txt"));
    assert!(!matches_extension(b"report.text", b"txt"));
    assert!(!matches_extension(b"txt", b"txt"));
    assert!(!matches_extension(b".txt", b"txt"));
}

#[test]
fn an_extension_matches_through_a_temporary_one() {
    // A file being written out under a temporary name still gets the
    // treatment its real extension asks for.
    assert!(matches_extension(b"report.txt.part", b"txt"));
    assert!(matches_extension(b"a.txt.b.c", b"txt"));
    assert!(!matches_extension(b"report.txtx.part", b"txt"));
}

#[test]
fn the_match_ignores_case_because_the_list_is_written_by_people() {
    assert!(matches_extension(b"PHOTO.JPG", b"jpg"));
    assert!(matches_extension(b"photo.jpg", b"JPG"));
    assert!(matches_extension(b"photo.JpG", b"jPg"));
}

#[test]
fn the_wildcard_matches_every_name() {
    for name in [&b""[..], b"x", b"a.txt", b"...."] {
        assert!(matches_extension(name, b"*"), "{name:?}");
    }
}

#[test]
fn the_refusing_list_wins_over_the_allowing_one() {
    let allow: [&[u8]; 2] = [b"txt", b"log"];
    let refuse: [&[u8]; 1] = [b"log"];
    assert!(wants_compression(b"a.txt", &allow, &refuse));
    assert!(!wants_compression(b"a.log", &allow, &refuse));
    assert!(!wants_compression(b"a.bin", &allow, &refuse));
    // The wildcard on the allowing side still loses to a named refusal.
    let any: [&[u8]; 1] = [b"*"];
    assert!(!wants_compression(b"a.log", &any, &refuse));
    assert!(wants_compression(b"a.bin", &any, &refuse));
}
