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
    // Zstd's floor is below zero, so the level an unasked-for file carries is
    // inside its band; refusing it would reject an ordinary Zstd file.
    assert!(Algorithm::Zstd.level_valid(0));
    assert!(Algorithm::Zstd.level_valid(1) && Algorithm::Zstd.level_valid(22));
    for lvl in 23..=255u8 { assert!(!Algorithm::Zstd.level_valid(lvl), "level {lvl}"); }
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
    assert_eq!(context(COMPRESS_ZSTD, 4, false, 3), None, "no zstd encoder in this build");
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

// ---- what an inode's stored compression settings must satisfy -------------

use crate::flags::{F2FS_COMPR_FL, FEATURE_COMPRESSION, FEATURE_EXTRA_ATTR};
use crate::node::inode::{sanity, Inode};

/// An inode carrying settings, wide enough to hold every one of them.
/// # C: O(1)
fn compressed_inode(algorithm: u8, log: u8, flag: u16, compr_blocks: u64) -> Inode {
    Inode {
        mode: crate::mode::S_IFREG | 0o644,
        advise: 0,
        inline: crate::flags::EXTRA_ATTR,
        uid: 0,
        gid: 0,
        links: 1,
        size: 0,
        blocks: 8,
        atime: (0, 0),
        ctime: (0, 0),
        mtime: (0, 0),
        generation: 0,
        current_depth: 0,
        xattr_nid: 0,
        flags: F2FS_COMPR_FL,
        pino: 3,
        dir_level: 0,
        ext: (0, 0, 0),
        extra_isize: crate::uapi::TOTAL_EXTRA_ATTR_SIZE,
        inline_xattr_addrs: 0,
        projid: 0,
        inode_checksum: 0,
        crtime: None,
        compress_algorithm: algorithm,
        log_cluster_size: log,
        compress_flag: flag,
        compr_blocks,
    }
}

/// A volume that carries the compression feature, so an inode's compression
/// fields ARE compression fields.
const WITH: u32 = FEATURE_EXTRA_ATTR | FEATURE_COMPRESSION;
/// The same volume without it, where those same bytes are something else.
const WITHOUT: u32 = FEATURE_EXTRA_ATTR;

#[test]
fn a_compressed_inode_with_workable_settings_passes() {
    for algo in [COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_LZORLE] {
        for log in 2u8..=8 {
            assert_eq!(sanity(&compressed_inode(algo, log, 0, 4), 4, WITH), Ok(()), "{algo} {log}");
        }
    }
    // Zstd is a codec the format names and this build cannot unpack, but the
    // inode is still well formed: refusing it here would be a claim about the
    // volume rather than about this build.
    assert_eq!(sanity(&compressed_inode(COMPRESS_ZSTD, 4, 0, 4), 4, WITH), Ok(()));
    assert_eq!(sanity(&compressed_inode(COMPRESS_ZSTD, 4, 7 << 8, 4), 4, WITH), Ok(()));
}

#[test]
fn a_codec_number_the_format_does_not_name_is_refused() {
    for algo in 4u8..=255 {
        assert!(sanity(&compressed_inode(algo, 4, 0, 0), 4, WITH).is_err(), "codec {algo}");
    }
}

#[test]
fn a_cluster_width_outside_the_format_is_refused() {
    for log in [0u8, 1, 9, 16, 255] {
        assert!(sanity(&compressed_inode(COMPRESS_LZ4, log, 0, 0), 4, WITH).is_err(), "log {log}");
    }
}

#[test]
fn a_level_the_codec_has_no_meaning_for_is_refused() {
    // Nothing could rewrite the file the way it was written.
    for lvl in 1..=255u16 {
        assert!(
            sanity(&compressed_inode(COMPRESS_LZ4, 4, lvl << 8, 0), 4, WITH).is_err(),
            "level {lvl}"
        );
    }
    for lvl in 23..=255u16 {
        assert!(sanity(&compressed_inode(COMPRESS_ZSTD, 4, lvl << 8, 0), 4, WITH).is_err());
    }
}

#[test]
fn a_saving_larger_than_the_file_is_refused() {
    // The release that would hand those blocks back has none to hand back.
    assert_eq!(sanity(&compressed_inode(COMPRESS_LZ4, 4, 0, 8), 4, WITH), Ok(()));
    assert!(sanity(&compressed_inode(COMPRESS_LZ4, 4, 0, 9), 4, WITH).is_err());
    assert!(sanity(&compressed_inode(COMPRESS_LZ4, 4, 0, u64::MAX), 4, WITH).is_err());
}

#[test]
fn a_volume_without_the_feature_reads_those_bytes_as_something_else() {
    // Without the feature they are not compression settings at all, so
    // rejecting an inode over them would reject it over an unrelated field.
    for algo in [9u8, 200] {
        assert_eq!(sanity(&compressed_inode(algo, 0, 9 << 8, u64::MAX), 4, WITHOUT), Ok(()));
    }
}

#[test]
fn an_inode_without_the_flag_is_not_asked_about_its_settings() {
    let mut i = compressed_inode(9, 0, 9 << 8, u64::MAX);
    i.flags = 0;
    assert_eq!(sanity(&i, 4, WITH), Ok(()));
}
