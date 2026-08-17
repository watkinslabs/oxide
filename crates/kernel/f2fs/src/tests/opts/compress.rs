//! The compression options: their grammar, their limits, and the pair the
//! two extension lists have to form.

use syscall::errno::Errno;

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_ZSTD};
use crate::consistency::compress::check_compression;
use crate::flags::{FEATURE_COMPRESSION, FEATURE_EXTRA_ATTR};
use crate::opts::compress::{algorithm, check_lists, log_size, Compress, ExtList, COMPRESS_EXT_NUM,
                            ZSTD_DEFAULT_LEVEL};
use crate::opts::{parse, CompressMode, Options};

/// Parse a line over the build-wide defaults. # C: O(len)
fn p(line: &str) -> Result<Options, Errno> { parse(&Options::defaults(), line) }

// ---- the codec, and the level it may carry ------------------------------

#[test]
fn each_codec_the_format_names_is_spelled_and_only_that_spelling() {
    assert_eq!(algorithm("lzo"), Ok((COMPRESS_LZO, 0)));
    assert_eq!(algorithm("lz4"), Ok((COMPRESS_LZ4, 0)));
    assert_eq!(algorithm("lzo-rle"), Ok((COMPRESS_LZORLE, 0)));
    for bad in ["lzorle", "LZ4", "gzip", "", "lz", "zst"] {
        assert_eq!(algorithm(bad), Err(Errno::Einval), "{bad}");
    }
}

#[test]
fn zstd_named_without_a_level_takes_the_one_the_codec_means_by_default() {
    assert_eq!(algorithm("zstd"), Ok((COMPRESS_ZSTD, ZSTD_DEFAULT_LEVEL)));
    assert_ne!(ZSTD_DEFAULT_LEVEL, 0, "zero is a level zstd HAS, so it cannot mean 'none'");
}

#[test]
fn a_zstd_level_is_taken_across_the_whole_band_and_refused_outside_it() {
    for lvl in 0..=22u8 {
        assert_eq!(algorithm(&alloc::format!("zstd:{lvl}")), Ok((COMPRESS_ZSTD, lvl)), "{lvl}");
    }
    assert_eq!(algorithm("zstd:23"), Err(Errno::Einval));
    assert_eq!(algorithm("zstd:256"), Err(Errno::Einval));
    // A level the codec has and the FORMAT cannot store is a different
    // mistake from one nothing has.
    assert_eq!(algorithm("zstd:-1"), Err(Errno::Erange));
    // The colon is the whole grammar; without it the rest is not a level.
    assert_eq!(algorithm("zstd5"), Err(Errno::Einval));
    assert_eq!(algorithm("zstd:"), Err(Errno::Einval));
    assert_eq!(algorithm("zstd:x"), Err(Errno::Einval));
}

#[test]
fn a_codec_with_no_high_compression_mode_here_takes_no_level_at_all() {
    // Not even the level it would ignore: the two spellings must not mean the
    // same thing here and different things elsewhere.
    for bad in ["lz4:0", "lz4:1", "lz4:9", "lz4hc"] {
        assert_eq!(algorithm(bad), Err(Errno::Einval), "{bad}");
    }
}

#[test]
fn the_codec_and_its_level_reach_the_option_set_together() {
    let o = p("compress_algorithm=zstd:7").unwrap();
    assert_eq!((o.compress.algorithm, o.compress.level), (COMPRESS_ZSTD, 7));
    // A second naming replaces both, so a level does not survive its codec.
    let o = p("compress_algorithm=zstd:7,compress_algorithm=lzo").unwrap();
    assert_eq!((o.compress.algorithm, o.compress.level), (COMPRESS_LZO, 0));
}

// ---- the cluster width ---------------------------------------------------

#[test]
fn only_the_cluster_widths_the_format_admits_are_accepted() {
    for n in 2..=8u8 { assert_eq!(log_size(&alloc::format!("{n}")), Ok(n), "{n}"); }
    for bad in ["0", "1", "9", "32", "", "x", "-1"] {
        assert_eq!(log_size(bad), Err(Errno::Einval), "{bad}");
    }
    assert_eq!(p("compress_log_size=6").unwrap().compress.log_size, 6);
    assert_eq!(p("compress_log_size=9").map(|_| ()), Err(Errno::Einval));
}

// ---- the two lists -------------------------------------------------------

#[test]
fn an_extension_is_bounded_in_length_and_the_list_in_count() {
    let mut l = ExtList::empty();
    assert_eq!(l.push(b"1234567"), Ok(()));
    // One byte narrower than the slot: the stored form needs a terminator.
    assert_eq!(l.push(b"12345678"), Err(Errno::Einval));
    for i in 1..COMPRESS_EXT_NUM { l.push(alloc::format!("e{i}").as_bytes()).expect("fits"); }
    assert_eq!(l.len(), COMPRESS_EXT_NUM);
    assert_eq!(l.push(b"one"), Err(Errno::Einval));
}

#[test]
fn a_repeated_extension_is_kept_once_and_is_not_an_error() {
    // A remount restating the line it is running with must not fail.
    let o = p("compress_extension=txt,compress_extension=TXT,compress_extension=log").unwrap();
    assert_eq!(o.compress.extensions.len(), 2);
    assert!(o.compress.extensions.contains(b"txt"));
    assert!(o.compress.extensions.contains(b"LOG"));
}

#[test]
fn a_full_list_is_refused_before_the_duplicate_is_looked_for() {
    let mut line = alloc::string::String::new();
    for i in 0..COMPRESS_EXT_NUM { line.push_str(&alloc::format!("compress_extension=e{i},")); }
    assert!(p(&line).is_ok());
    line.push_str("compress_extension=e0");
    assert_eq!(p(&line).map(|_| ()), Err(Errno::Einval));
}

#[test]
fn the_two_lists_are_kept_apart() {
    let o = p("compress_extension=txt,nocompress_extension=log").unwrap();
    assert_eq!(o.compress.extensions.len(), 1);
    assert_eq!(o.compress.noextensions.len(), 1);
    assert!(o.compress.noextensions.contains(b"log"));
}

#[test]
fn the_same_extension_on_both_lists_is_refused() {
    let mut c = Compress::defaults();
    c.extensions.push(b"txt").unwrap();
    c.noextensions.push(b"TXT").unwrap();
    assert_eq!(check_lists(&c), Err(Errno::Einval));
}

#[test]
fn the_wildcard_is_refused_on_the_refusing_side_and_allowed_on_the_other() {
    let mut c = Compress::defaults();
    c.noextensions.push(b"*").unwrap();
    assert_eq!(check_lists(&c), Err(Errno::Einval));

    let mut c = Compress::defaults();
    c.extensions.push(b"*").unwrap();
    c.noextensions.push(b"log").unwrap();
    assert_eq!(check_lists(&c), Ok(()));
}

// ---- the checksum and the mode ------------------------------------------

#[test]
fn the_checksum_request_is_a_bare_word() {
    assert!(!Options::defaults().compress.chksum);
    assert!(p("compress_chksum").unwrap().compress.chksum);
    assert_eq!(p("compress_chksum=1").map(|_| ()), Err(Errno::Einval));
}

#[test]
fn which_side_compresses_is_named_and_defaults_to_the_mount() {
    assert_eq!(Options::defaults().compress.mode, CompressMode::Fs);
    assert_eq!(p("compress_mode=fs").unwrap().compress.mode, CompressMode::Fs);
    assert_eq!(p("compress_mode=user").unwrap().compress.mode, CompressMode::User);
    assert_eq!(p("compress_mode=maybe").map(|_| ()), Err(Errno::Einval));
    assert_eq!(p("compress_mode").map(|_| ()), Err(Errno::Einval));
}

// ---- against the volume --------------------------------------------------

#[test]
fn a_volume_that_cannot_record_compression_drops_the_whole_group() {
    let mut o = p("compress_algorithm=zstd:5,compress_log_size=6,compress_chksum,\
                   compress_mode=user,compress_extension=txt,nocompress_extension=bin")
        .unwrap();
    assert_ne!(o.compress, Compress::defaults());
    assert_eq!(check_compression(FEATURE_EXTRA_ATTR, &mut o), Ok(()));
    // Whole, not partly: anything left behind would be reported back through
    // the mount table for files that can never carry it.
    assert_eq!(o.compress, Compress::defaults());
}

#[test]
fn a_volume_that_can_record_it_keeps_the_group_and_checks_the_pair() {
    let mut o = p("compress_algorithm=zstd:5,compress_extension=txt").unwrap();
    assert_eq!(check_compression(FEATURE_COMPRESSION | FEATURE_EXTRA_ATTR, &mut o), Ok(()));
    assert_eq!((o.compress.algorithm, o.compress.level), (COMPRESS_ZSTD, 5));

    let mut bad = p("compress_extension=txt,nocompress_extension=txt").unwrap();
    assert_eq!(check_compression(FEATURE_COMPRESSION, &mut bad), Err(Errno::Einval));
}

#[test]
fn a_volume_that_cannot_record_compression_drops_the_read_cache_with_the_group() {
    // The cache is not part of the group and is not a setting a file carries,
    // but a volume with no compressed cluster on it has nothing for the cache
    // to hold — and leaving it on would report a cache that can never fill.
    let mut o = p("compress_cache").unwrap();
    assert!(o.compress_cache);
    assert_eq!(check_compression(FEATURE_EXTRA_ATTR, &mut o), Ok(()));
    assert!(!o.compress_cache);

    let mut kept = p("compress_cache").unwrap();
    assert_eq!(check_compression(FEATURE_COMPRESSION, &mut kept), Ok(()));
    assert!(kept.compress_cache, "a volume that can record it keeps it");
}

#[test]
fn the_read_cache_is_shown_only_where_it_is_on_and_reads_back() {
    let feature = FEATURE_COMPRESSION;
    let on = p("compress_cache").unwrap();
    let shown = crate::opts::show(&on, feature);
    assert!(shown.contains(",compress_cache"), "{shown}");
    assert!(crate::opts::parse(&Options::defaults(), &shown).unwrap().compress_cache);
    assert!(!crate::opts::show(&Options::defaults(), feature).contains("compress_cache"));
    // A volume that cannot record compression shows none of the group, so the
    // string a remount reads back never asks for a cache it would then refuse.
    assert!(!crate::opts::show(&on, FEATURE_EXTRA_ATTR).contains("compress_cache"));
}

#[test]
fn a_value_out_of_range_is_refused_even_where_it_could_not_be_recorded() {
    // The mistake is in the LINE, and the line is the same on every volume.
    assert_eq!(p("compress_log_size=9").map(|_| ()), Err(Errno::Einval));
    assert_eq!(p("compress_algorithm=gzip").map(|_| ()), Err(Errno::Einval));
}

// ---- back out through the mount table ------------------------------------

/// Render, for a volume that can record compression. # C: O(options)
fn shown(line: &str) -> alloc::string::String {
    let mut o = p(line).unwrap();
    let feature = FEATURE_COMPRESSION | FEATURE_EXTRA_ATTR;
    check_compression(feature, &mut o).unwrap();
    crate::opts::show(&o, feature)
}

#[test]
fn the_group_is_shown_only_where_the_volume_can_record_it() {
    let o = Options::defaults();
    assert!(!crate::opts::show(&o, FEATURE_EXTRA_ATTR).contains("compress"));
    assert!(crate::opts::show(&o, FEATURE_COMPRESSION).contains(",compress_algorithm=lz4"));
}

#[test]
fn what_is_shown_parses_back_to_what_was_shown() {
    for line in ["", "compress_algorithm=zstd:9", "compress_algorithm=lzo-rle",
                 "compress_log_size=8,compress_chksum,compress_mode=user",
                 "compress_extension=txt,compress_extension=log,nocompress_extension=bin"] {
        let s = shown(line);
        let back = parse(&Options::defaults(), &s).expect(&s);
        assert_eq!(back.compress, p(line).unwrap().compress, "{s}");
    }
}

#[test]
fn a_level_is_shown_on_the_codec_s_own_name() {
    assert!(shown("compress_algorithm=zstd:9").contains(",compress_algorithm=zstd:9"));
    // A codec with no level shows none, rather than a zero that would read
    // back as a level it does not have.
    assert!(shown("compress_algorithm=lz4").contains(",compress_algorithm=lz4,"));
    assert!(!shown("compress_algorithm=lz4").contains("lz4:"));
}
