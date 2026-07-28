//! The negative assertions: an `openat2` scoping bit that does NOT reach the
//! `O_CREAT` parent walk is a sandbox escape, so every one of them is checked
//! individually rather than as an aggregate.

use super::*;

#[test]
fn unknown_resolve_bit_rejected() {
    assert_eq!(validate_resolve(0x40), Err(Errno::Einval));
    assert_eq!(validate_resolve(1 << 63), Err(Errno::Einval));
    // Every valid bit at once, minus IN_ROOT — it is mutually exclusive with
    // BENEATH, so `RESOLVE_VALID` itself is legitimately EINVAL.
    assert_eq!(validate_resolve(RESOLVE_VALID & !RESOLVE_IN_ROOT), Ok(()));
    assert_eq!(validate_resolve(RESOLVE_VALID & !RESOLVE_BENEATH), Ok(()));
}

#[test]
fn beneath_and_in_root_mutually_exclusive() {
    assert_eq!(validate_resolve(RESOLVE_BENEATH | RESOLVE_IN_ROOT), Err(Errno::Einval));
    assert_eq!(validate_resolve(RESOLVE_BENEATH), Ok(()));
    assert_eq!(validate_resolve(RESOLVE_IN_ROOT), Ok(()));
}

#[test]
fn resolve_word_maps_bit_for_bit() {
    let f = lookup_flags_from_resolve(RESOLVE_NO_XDEV);
    assert!(f.no_xdev && !f.no_symlinks && !f.beneath_exdev && !f.in_root && !f.no_magiclinks && !f.cached);
    let f = lookup_flags_from_resolve(RESOLVE_NO_MAGICLINKS);
    assert!(f.no_magiclinks && !f.no_xdev);
    let f = lookup_flags_from_resolve(RESOLVE_NO_SYMLINKS);
    assert!(f.no_symlinks && !f.no_magiclinks);
    let f = lookup_flags_from_resolve(RESOLVE_BENEATH);
    assert!(f.beneath_exdev && !f.in_root);
    let f = lookup_flags_from_resolve(RESOLVE_IN_ROOT);
    assert!(f.in_root && !f.beneath_exdev);
    let f = lookup_flags_from_resolve(RESOLVE_CACHED);
    assert!(f.cached);
}

// The bug this module exists for. Each scoping bit is asserted to SURVIVE the
// transition to the parent phase; before the fix the create path built its
// parent flags from `LookupFlags::default()`, so every one of these was false.
#[test]
fn every_scoping_bit_survives_the_create_parent_walk() {
    for (name, resolve) in [
        ("RESOLVE_NO_XDEV", RESOLVE_NO_XDEV),
        ("RESOLVE_NO_MAGICLINKS", RESOLVE_NO_MAGICLINKS),
        ("RESOLVE_NO_SYMLINKS", RESOLVE_NO_SYMLINKS),
        ("RESOLVE_BENEATH", RESOLVE_BENEATH),
        ("RESOLVE_IN_ROOT", RESOLVE_IN_ROOT),
    ] {
        let extra = lookup_flags_from_resolve(resolve);
        let p = parent_lookup_flags(&extra);
        assert!(p.parent, "{name}: parent phase requested");
        let survived = match resolve {
            RESOLVE_NO_XDEV       => p.no_xdev,
            RESOLVE_NO_MAGICLINKS => p.no_magiclinks,
            RESOLVE_NO_SYMLINKS   => p.no_symlinks,
            RESOLVE_BENEATH       => p.beneath_exdev,
            RESOLVE_IN_ROOT       => p.in_root,
            _ => unreachable!(),
        };
        assert!(survived, "{name} was dropped on the O_CREAT parent walk (sandbox escape)");
    }
}

// The dirfd-rooted pair must route through `resolve_confined`, otherwise an
// absolute pathname is re-based on the PROCESS root and leaves the scope.
#[test]
fn scoping_pair_confines_the_walk_base() {
    assert!(lookup_flags_from_resolve(RESOLVE_BENEATH).confines_to_dirfd());
    assert!(lookup_flags_from_resolve(RESOLVE_IN_ROOT).confines_to_dirfd());
    assert!(parent_lookup_flags(&lookup_flags_from_resolve(RESOLVE_BENEATH)).confines_to_dirfd());
    assert!(parent_lookup_flags(&lookup_flags_from_resolve(RESOLVE_IN_ROOT)).confines_to_dirfd());
    // Non-scoping bits keep the ordinary process-root base.
    assert!(!lookup_flags_from_resolve(RESOLVE_NO_SYMLINKS).confines_to_dirfd());
    assert!(!lookup_flags_from_resolve(RESOLVE_NO_XDEV).confines_to_dirfd());
}

// Bits Linux scopes to the FINAL component must NOT leak into the parent walk,
// or `openat2(dirfd, "a/b", O_CREAT|O_NOFOLLOW)` would stop refusing to follow
// `a` — a false negative in the other direction.
#[test]
fn final_component_bits_do_not_leak_into_the_parent() {
    let mut extra = lookup_flags_from_resolve(RESOLVE_BENEATH);
    extra.no_follow_final = true;
    extra.directory = true;
    extra.empty = true;
    extra.cached = true;
    let p = parent_lookup_flags(&extra);
    assert!(!p.no_follow_final, "O_NOFOLLOW scopes the final component only");
    assert!(!p.directory, "LOOKUP_DIRECTORY scopes the final component only");
    assert!(!p.empty, "AT_EMPTY_PATH is meaningless for a parent walk");
    assert!(!p.cached, "RESOLVE_CACHED cannot coexist with O_CREAT (EAGAIN earlier)");
    assert!(p.beneath_exdev, "the scoping bit still survives");
}

// A plain `openat(2)` (no `open_how`) must be byte-identical to the historical
// `LookupFlags { parent: true, ..Default }` so nothing regresses.
#[test]
fn plain_openat_parent_flags_unchanged() {
    let p = parent_lookup_flags(&vfs::LookupFlags::default());
    assert!(p.parent);
    assert!(!resolve_active(&p), "no RESOLVE_* bit is invented for a plain openat");
}

#[test]
fn resolve_active_detects_each_bit() {
    assert!(!resolve_active(&vfs::LookupFlags::default()));
    for r in [RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
              RESOLVE_BENEATH, RESOLVE_IN_ROOT, RESOLVE_CACHED] {
        assert!(resolve_active(&lookup_flags_from_resolve(r)), "resolve bit {r:#x} not detected");
    }
}
