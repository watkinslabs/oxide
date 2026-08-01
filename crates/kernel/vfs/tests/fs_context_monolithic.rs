//! `parse_monolithic_mount_data` — the `mount(2)` data blob reaching the SAME
//! admission verdict `fsconfig(2)` applies.
//!
//! Fails-before: `mount(2)` never built an `FsContext` at all. The raw
//! comma-separated string went straight to the filesystem constructor, so a
//! filesystem could report a key unsupported to an `fsconfig(2)` probe and
//! still swallow it on the real mount. Everything here drives the one
//! admission owner; nothing re-implements the per-key decision.

use std::sync::Arc;

use vfs::fs::fs_context::{FsContext, FsParameter, parse_monolithic_mount_data,
    vfs_clean_context, vfs_parse_fs_string};
use vfs::fs::{FsParamSpec, FsParamType};
use vfs::superblock::{FileSystemType, SuperBlock, SB_RDONLY, SB_SYNCHRONOUS};
use vfs::{KResult, VfsError};

/// A filesystem that publishes a table: keys outside it are refused.
struct Declared;
const DECLARED: &[FsParamSpec] = &[
    FsParamSpec::value("size", FsParamType::Size),
    FsParamSpec::value("mode", FsParamType::U32Oct),
    FsParamSpec::value("usrjquota", FsParamType::String),
    FsParamSpec::flag("noswap"),
];
impl FileSystemType for Declared {
    fn name(&self) -> &str { "declaredfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
    fn parameters(&self) -> Option<&'static [FsParamSpec]> { Some(DECLARED) }
}

/// A filesystem that publishes NO table: the unconverted backend, which keeps
/// its blob whole and cannot refuse anything.
struct Legacy;
impl FileSystemType for Legacy {
    fn name(&self) -> &str { "legacyfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

fn declared() -> FsContext { FsContext::for_mount(Arc::new(Declared), 0) }
fn legacy() -> FsContext { FsContext::for_mount(Arc::new(Legacy), 0) }

// ---- the split itself -------------------------------------------------------

#[test]
fn each_comma_separated_piece_becomes_one_parameter() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "size=64m,mode=0755,noswap").unwrap();
    assert_eq!(fc.params().len(), 3);
    assert_eq!(fc.params()[0], FsParameter::string("size", "64m"));
    assert_eq!(fc.params()[1], FsParameter::string("mode", "0755"));
    assert_eq!(fc.params()[2], FsParameter::flag("noswap"));
}

// An empty blob is what `mount(2)` passes when the caller named no options at
// all. It must not become a parameter, and must not be an error — every
// filesystem is mounted this way.
#[test]
fn an_empty_blob_yields_no_parameters_and_no_error() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "").unwrap();
    assert_eq!(fc.params().len(), 0);
}

// Empty pieces come from a trailing comma or a doubled separator, both of
// which real option-string builders emit. They are skipped, not refused.
#[test]
fn empty_pieces_are_skipped_not_refused() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, ",,noswap,,").unwrap();
    assert_eq!(fc.params(), &[FsParameter::flag("noswap")]);
}

// A piece whose `=` sits at offset 0 has no key at all. It is dropped whole —
// not reported as an unknown parameter, and above all not read as a value for
// whatever key came before it.
#[test]
fn a_piece_with_an_empty_key_is_dropped() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "=whatever,noswap").unwrap();
    assert_eq!(fc.params(), &[FsParameter::flag("noswap")]);
}

// Only the FIRST `=` splits: a value may contain `=`.
#[test]
fn only_the_first_equals_splits_a_piece() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "usrjquota=a=b=c").unwrap();
    assert_eq!(fc.params(), &[FsParameter::string("usrjquota", "a=b=c")]);
}

// A trailing `=` is an EMPTY VALUE, which is a different thing from a bare
// word — `usrjquota=` clears the journalled quota file, `usrjquota` alone is
// the wrong shape.
#[test]
fn a_trailing_equals_is_an_empty_value_not_a_bare_word() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "usrjquota=").unwrap();
    assert_eq!(fc.params(), &[FsParameter::string("usrjquota", "")]);

    let mut fc = declared();
    assert_eq!(parse_monolithic_mount_data(&mut fc, "usrjquota"), Err(VfsError::Einval));
}

// ---- the verdict ------------------------------------------------------------

// The whole point: a key the table does not describe fails the REAL mount
// path, not only the probe path.
#[test]
fn a_key_outside_the_table_fails_the_blob() {
    let mut fc = declared();
    assert_eq!(parse_monolithic_mount_data(&mut fc, "size=64m,nosuchoption=1"),
        Err(VfsError::Einval));
}

// Refusal stops at the offending piece: Linux breaks out of the loop, so the
// pieces after it are never parsed. What matters observably is that the whole
// mount fails, and that nothing later can undo the refusal.
#[test]
fn parsing_stops_at_the_first_refusal() {
    let mut fc = declared();
    assert_eq!(parse_monolithic_mount_data(&mut fc, "nosuchoption,size=64m"),
        Err(VfsError::Einval));
    assert_eq!(fc.params().len(), 0, "nothing after the refusal is admitted");
}

// A bare word where a value belongs must NOT fall through to `source`, or
// `mount -o size` would silently name a device.
#[test]
fn the_wrong_value_shape_never_becomes_a_source() {
    let mut fc = declared();
    assert_eq!(parse_monolithic_mount_data(&mut fc, "size"), Err(VfsError::Einval));
    assert!(fc.source().is_none());
}

// The superblock keywords are consumed before the table is consulted, so a
// filesystem that declares a table still honours `-o ro`.
#[test]
fn superblock_keywords_in_the_blob_still_reach_sb_flags() {
    let mut fc = declared();
    parse_monolithic_mount_data(&mut fc, "ro,sync,noswap").unwrap();
    assert!(fc.sb_flags() & SB_RDONLY != 0);
    assert!(fc.sb_flags() & SB_SYNCHRONOUS != 0);
    assert_eq!(fc.params(), &[FsParameter::flag("noswap")],
        "the keywords are consumed, not passed to the backend");
}

// ---- the unconverted backend ------------------------------------------------

// A filesystem with no table keeps its blob VERBATIM and refuses nothing. This
// is the behaviour every filesystem had before a table existed, and it is what
// makes adding a table an opt-in rather than a flag day.
#[test]
fn a_filesystem_without_a_table_keeps_its_blob_whole() {
    let mut fc = legacy();
    let blob = "mode=620,ptmxmode=000,gid=5,nosuchoption,=stray,";
    parse_monolithic_mount_data(&mut fc, blob).unwrap();
    assert_eq!(fc.classic_mount_options(), blob,
        "the constructor sees the exact string the caller passed");
    assert_eq!(fc.params().len(), 0, "nothing was split out of it");
    assert!(fc.source().is_none(), "nothing fell through to source");
}

// Order, duplicates and quoting survive only because the blob is not
// round-tripped through the parameter list.
#[test]
fn the_verbatim_blob_is_not_reordered_or_deduplicated() {
    let mut fc = legacy();
    parse_monolithic_mount_data(&mut fc, "mode=0700,mode=0755,context=\"a,b\"").unwrap();
    assert_eq!(fc.classic_mount_options(), "mode=0700,mode=0755,context=\"a,b\"");
}

// The blob describes how to build the tree; once built, a later reconfigure
// must not replay the original `mount(2)` options as if they were asked for
// again.
#[test]
fn a_cleaned_context_no_longer_replays_the_blob() {
    let mut fc = legacy();
    parse_monolithic_mount_data(&mut fc, "mode=0700").unwrap();
    assert_eq!(fc.classic_mount_options(), "mode=0700");
    vfs_clean_context(&mut fc);
    assert_eq!(fc.classic_mount_options(), "");
    assert!(fc.mount_target().is_none());
}

// `source` is parsed before the blob on the `mount(2)` path and must survive
// it on both backends.
#[test]
fn source_survives_the_blob_on_both_backends() {
    let mut fc = declared();
    vfs_parse_fs_string(&mut fc, "source", "/dev/vda1").unwrap();
    parse_monolithic_mount_data(&mut fc, "size=64m").unwrap();
    assert_eq!(fc.source(), Some("/dev/vda1"));

    let mut fc = legacy();
    vfs_parse_fs_string(&mut fc, "source", "/dev/vda1").unwrap();
    parse_monolithic_mount_data(&mut fc, "anything=at,all").unwrap();
    assert_eq!(fc.source(), Some("/dev/vda1"));
}
