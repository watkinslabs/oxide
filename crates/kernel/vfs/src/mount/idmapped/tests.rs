// Durable provenance for the per-mount idmap admission ladder: which refusal a
// caller observes when several rungs would refuse at once.

use super::*;

/// A request that every rung accepts, so each test can spoil exactly one fact.
fn ok() -> IdmapFacts {
    IdmapFacts {
        requested: true,
        userns_is_sb_user_ns: false,
        replace: false,
        already_idmapped: false,
        fs_allow_idmap: true,
        sb_noidmap: false,
        controls_superblock: true,
        anon_ns: true,
    }
}

#[test]
fn a_request_with_no_idmap_change_is_admitted_whatever_else_is_false() {
    let f = IdmapFacts { requested: false, ..Default::default() };
    assert_eq!(can_idmap_mount(f), Ok(()));
    // Not merely "default is empty": every other fact is hostile here.
    let f = IdmapFacts { requested: false, userns_is_sb_user_ns: true, already_idmapped: true,
                         fs_allow_idmap: false, sb_noidmap: true, controls_superblock: false,
                         anon_ns: false, replace: false };
    assert_eq!(can_idmap_mount(f), Ok(()));
}

#[test]
fn a_fully_admissible_request_passes() {
    assert_eq!(can_idmap_mount(ok()), Ok(()));
    assert_eq!(can_idmap_mount(IdmapFacts { replace: true, ..ok() }), Ok(()));
}

#[test]
fn mapping_a_superblocks_own_user_namespace_is_einval() {
    let f = IdmapFacts { userns_is_sb_user_ns: true, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Einval));
}

#[test]
fn the_tautology_rung_outranks_every_other_refusal() {
    let f = IdmapFacts { userns_is_sb_user_ns: true, already_idmapped: true,
                         fs_allow_idmap: false, sb_noidmap: true,
                         controls_superblock: false, anon_ns: false, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Einval));
}

#[test]
fn overwriting_an_existing_map_without_the_replace_mode_is_eperm() {
    let f = IdmapFacts { already_idmapped: true, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Eperm));
}

#[test]
fn the_replace_mode_permits_overwriting_an_existing_map() {
    let f = IdmapFacts { already_idmapped: true, replace: true, ..ok() };
    assert_eq!(can_idmap_mount(f), Ok(()));
}

#[test]
fn the_already_idmapped_rung_outranks_the_filesystem_support_rungs() {
    // Both would refuse; EPERM must win, so a caller can tell "second install"
    // apart from "this filesystem cannot be idmapped".
    let f = IdmapFacts { already_idmapped: true, fs_allow_idmap: false, sb_noidmap: true, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Eperm));
    // With the replace mode the filesystem rung below it becomes visible.
    let f = IdmapFacts { replace: true, ..f };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Einval));
}

#[test]
fn an_unsupported_filesystem_is_einval() {
    assert_eq!(can_idmap_mount(IdmapFacts { fs_allow_idmap: false, ..ok() }),
               Err(VfsError::Einval));
    assert_eq!(can_idmap_mount(IdmapFacts { sb_noidmap: true, ..ok() }),
               Err(VfsError::Einval));
}

#[test]
fn the_filesystem_rungs_outrank_the_capability_rung() {
    let f = IdmapFacts { fs_allow_idmap: false, controls_superblock: false, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Einval));
    let f = IdmapFacts { sb_noidmap: true, controls_superblock: false, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Einval));
}

#[test]
fn not_controlling_the_superblock_is_eperm() {
    assert_eq!(can_idmap_mount(IdmapFacts { controls_superblock: false, ..ok() }),
               Err(VfsError::Eperm));
}

#[test]
fn the_capability_rung_outranks_the_visibility_rung() {
    let f = IdmapFacts { controls_superblock: false, anon_ns: false, ..ok() };
    assert_eq!(can_idmap_mount(f), Err(VfsError::Eperm));
}

#[test]
fn an_attached_mount_can_never_be_idmapped_even_in_the_replace_mode() {
    assert_eq!(can_idmap_mount(IdmapFacts { anon_ns: false, ..ok() }),
               Err(VfsError::Einval));
    // The replace mode relaxes only the already-idmapped rung; it does NOT
    // make a mount that is visible in a live namespace idmappable.
    assert_eq!(can_idmap_mount(IdmapFacts { anon_ns: false, replace: true, ..ok() }),
               Err(VfsError::Einval));
    assert_eq!(can_idmap_mount(IdmapFacts { anon_ns: false, replace: true,
                                            already_idmapped: true, ..ok() }),
               Err(VfsError::Einval));
}
