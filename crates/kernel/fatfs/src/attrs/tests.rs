//! The mode an entry presents as.

use super::*;
use crate::dirent::{ATTR_ARCH, ATTR_DIR, ATTR_RO};

/// The two masks apply to their own kind and to nothing else.
#[test]
fn each_mask_applies_to_its_own_kind() {
    let mut o = Options::vfat();
    o.fmask = 0o133;
    o.dmask = 0o022;
    assert_eq!(make_mode(ATTR_ARCH, b"HELLO   TXT", &o), 0o644);
    assert_eq!(make_mode(ATTR_DIR, b"SUB        ", &o), 0o755);
}

/// A read-only FILE loses its write bits: reporting it writable fails the
/// write at the first byte rather than at the open.
#[test]
fn a_read_only_file_loses_its_write_bits() {
    let mut o = Options::vfat();
    o.fmask = 0o022;
    assert_eq!(make_mode(ATTR_ARCH | ATTR_RO, b"HELLO   TXT", &o), 0o555);
}

/// A read-only DIRECTORY keeps them unless the mount asked otherwise. The
/// attribute means something else on a directory, and honouring it by default
/// makes tools refuse to descend into one.
#[test]
fn a_read_only_directory_keeps_its_write_bits_unless_asked() {
    let mut o = Options::vfat();
    assert_eq!(make_mode(ATTR_DIR | ATTR_RO, b"SUB        ", &o), 0o777);
    o.rodir = true;
    assert_eq!(make_mode(ATTR_DIR | ATTR_RO, b"SUB        ", &o), 0o555);
    // The 8.3-only type asks for it by default, which is one of the three
    // ways the two types differ.
    assert_eq!(make_mode(ATTR_DIR | ATTR_RO, b"SUB        ", &Options::msdos()), 0o555);
}

/// `showexec` is the only sense in which this filesystem has an executable
/// file: three extensions keep the execute bits and everything else loses
/// them.
#[test]
fn showexec_grants_the_execute_bits_to_three_extensions_only() {
    let mut o = Options::vfat();
    o.showexec = true;
    for ext in [b"EXE", b"COM", b"BAT"] {
        let mut raw = *b"PROGRAM    ";
        raw[8..].copy_from_slice(ext);
        assert_eq!(make_mode(ATTR_ARCH, &raw, &o) & EXEC_BITS, EXEC_BITS,
                   "extension {ext:?}");
    }
    assert_eq!(make_mode(ATTR_ARCH, b"README  TXT", &o) & EXEC_BITS, 0);
    // A directory never loses them: one with no execute bit cannot be entered.
    assert_eq!(make_mode(ATTR_DIR, b"SUB        ", &o) & EXEC_BITS, EXEC_BITS);
}

/// Without the option every file keeps them, whatever it is called.
#[test]
fn without_showexec_the_extension_decides_nothing() {
    let o = Options::vfat();
    assert_eq!(make_mode(ATTR_ARCH, b"README  TXT", &o) & EXEC_BITS, EXEC_BITS);
}

/// Only the read-only bit can be written back: it is the one bit of a mode
/// this filesystem can store at all.
#[test]
fn only_the_read_only_bit_survives_a_mode_change() {
    assert_eq!(make_attrs(false, 0o444, ATTR_ARCH) & ATTR_RO, ATTR_RO);
    assert_eq!(make_attrs(false, 0o644, ATTR_ARCH | ATTR_RO) & ATTR_RO, 0);
    // A directory keeps its directory attribute across the change; a file
    // keeps the archive bit and does not acquire the directory one.
    assert_eq!(make_attrs(true, 0o755, ATTR_DIR) & ATTR_DIR, ATTR_DIR);
    assert_eq!(make_attrs(false, 0o644, ATTR_DIR | ATTR_ARCH) & ATTR_DIR, 0);
}

/// The extension test compares three bytes, not a prefix: `EXECUTE` is not
/// `EXE`, and a short slice is not an executable either.
#[test]
fn the_extension_test_is_exactly_three_bytes() {
    assert!(is_exec(b"EXE"));
    assert!(is_exec(b"BAT"));
    assert!(!is_exec(b"TXT"));
    assert!(!is_exec(b"EX"));
    assert!(!is_exec(b"exe"));
}
