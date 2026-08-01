use crate::handle_policy::decode::*;
use crate::handle_policy::fid::{FID_LEN, FID_LEN_PARENT, HANDLE_TYPE_INO_GEN,
    HANDLE_TYPE_INO_GEN_PARENT};
use crate::handle_policy::flags::MAX_HANDLE_SZ;
use syscall::errno::Errno;

/// Everything denied: the baseline the ladder tests perturb one field at a time.
const DENIED: MayDecodeFh = MayDecodeFh {
    cap_dac_read_search: false,
    o_directory: false,
    sys_admin_over_sb_userns: false,
    anchor_is_mounted: false,
    sys_admin_over_mnt_ns: false,
    has_locked_children: false,
    dac_read_search_in_user_ns: false,
};

/// Header validation covers zero, oversize, negative type, and unknown
/// user-flag bits — all EINVAL, all before any fd or capability is looked at.
/// # C: O(1)
#[test]
fn header_check_rejects_malformed_handles() {
    assert_eq!(handle_header_check(FID_LEN, HANDLE_TYPE_INO_GEN), Ok(()));
    assert_eq!(handle_header_check(0, HANDLE_TYPE_INO_GEN), Err(Errno::Einval));
    assert_eq!(handle_header_check(MAX_HANDLE_SZ + 1, HANDLE_TYPE_INO_GEN), Err(Errno::Einval));
    assert_eq!(handle_header_check(FID_LEN, -1), Err(Errno::Einval));
    assert_eq!(handle_header_check(FID_LEN, i32::MIN), Err(Errno::Einval));
    assert_eq!(handle_header_check(FID_LEN, 0x4000_0000), Err(Errno::Einval),
        "a user-flag bit outside FILEID_VALID_USER_FLAGS");
}

/// Both documented user flags pass the header check on either FID type. 303
/// sets them for a connectable/directory handle, so rejecting them would make
/// this kernel unable to decode its own output. # C: O(1)
#[test]
fn valid_user_flags_pass_the_header_check() {
    for t in [HANDLE_TYPE_INO_GEN, HANDLE_TYPE_INO_GEN_PARENT] {
        for f in [FILEID_IS_CONNECTABLE, FILEID_IS_DIR, FILEID_VALID_USER_FLAGS] {
            assert_eq!(handle_header_check(FID_LEN, t | f), Ok(()), "type {t} flag {f:#x}");
        }
    }
    assert_eq!(FILEID_VALID_USER_FLAGS, FILEID_IS_CONNECTABLE | FILEID_IS_DIR);
}

/// The global capability short-circuits the whole ladder: no O_DIRECTORY
/// requirement and NO extra decode obligations. A `DecodeCtx` with
/// `check_perms` set here would make the privileged path re-verify ownership it
/// is entitled to override. # C: O(1)
#[test]
fn global_capability_passes_with_no_obligations() {
    let f = MayDecodeFh { cap_dac_read_search: true, ..DENIED };
    assert_eq!(may_decode_fh(f), Ok(DecodeCtx { check_perms: false, check_subtree: false, dir_only: false }));
    // …and it does not need O_DIRECTORY, unlike every relaxed leg.
    assert!(may_decode_fh(MayDecodeFh { cap_dac_read_search: true, o_directory: true, ..DENIED }).is_ok());
}

/// Without the global capability, a non-`O_DIRECTORY` open is EPERM — and that
/// check runs BEFORE either relaxed leg, so a caller who satisfies the mount
/// leg still cannot decode a non-directory handle. # C: O(1)
#[test]
fn relaxed_path_requires_o_directory_before_anything_else() {
    let mountable = MayDecodeFh {
        sys_admin_over_sb_userns: true, dac_read_search_in_user_ns: true, ..DENIED };
    assert_eq!(may_decode_fh(mountable), Err(Errno::Eperm), "no O_DIRECTORY");
    assert!(may_decode_fh(MayDecodeFh { o_directory: true, ..mountable }).is_ok());
}

/// "You may mount this filesystem" leg: obligations are ownership re-checks,
/// dir-only decode, but NOT subtree containment — a caller who could mount the
/// filesystem fresh could reach any part of it. # C: O(1)
#[test]
fn mount_capability_leg_checks_perms_but_not_subtree() {
    let f = MayDecodeFh { o_directory: true, sys_admin_over_sb_userns: true,
                          dac_read_search_in_user_ns: true, ..DENIED };
    assert_eq!(may_decode_fh(f),
        Ok(DecodeCtx { check_perms: true, check_subtree: false, dir_only: true }));
}

/// "You may bind-mount the anchor" leg additionally demands subtree
/// containment: the caller's reach is the subtree it could have bound, not the
/// whole filesystem. It needs the mount to be attached AND nothing locked
/// underneath, since a locked child would have hidden part of that subtree.
/// # C: O(1)
#[test]
fn bind_mount_leg_adds_subtree_containment() {
    let base = MayDecodeFh { o_directory: true, anchor_is_mounted: true,
                             sys_admin_over_mnt_ns: true, dac_read_search_in_user_ns: true, ..DENIED };
    assert_eq!(may_decode_fh(base),
        Ok(DecodeCtx { check_perms: true, check_subtree: true, dir_only: true }));
    assert_eq!(may_decode_fh(MayDecodeFh { has_locked_children: true, ..base }), Err(Errno::Eperm),
        "a locked child hides part of the subtree, so the bind argument fails");
    assert_eq!(may_decode_fh(MayDecodeFh { anchor_is_mounted: false, ..base }), Err(Errno::Eperm),
        "a detached mount cannot be bound");
    assert_eq!(may_decode_fh(MayDecodeFh { sys_admin_over_mnt_ns: false, ..base }), Err(Errno::Eperm));
}

/// The mount leg wins over the bind leg when both hold, and the stronger claim
/// yields the WEAKER obligation (no subtree bound). Order matters: evaluating
/// the bind leg first would needlessly confine a caller who may mount the
/// filesystem outright. # C: O(1)
#[test]
fn mount_leg_takes_precedence_over_bind_leg() {
    let both = MayDecodeFh { o_directory: true, sys_admin_over_sb_userns: true,
                             anchor_is_mounted: true, sys_admin_over_mnt_ns: true,
                             dac_read_search_in_user_ns: true, ..DENIED };
    assert_eq!(may_decode_fh(both).map(|c| c.check_subtree), Ok(false));
    // A locked child is irrelevant on the mount leg — it only defeats the bind
    // argument, and reaching it must not downgrade the stronger claim.
    assert_eq!(may_decode_fh(MayDecodeFh { has_locked_children: true, ..both }).map(|c| c.check_subtree),
        Ok(false));
}

/// The namespace-local DAC override is the LAST rung, checked after a leg has
/// already been selected. A caller who satisfies a leg but cannot override DAC
/// in its own user namespace is EPERM — it has no way to traverse the
/// directories the handle skipped. # C: O(1)
#[test]
fn namespace_dac_override_is_required_after_a_leg_is_selected() {
    for leg in [MayDecodeFh { o_directory: true, sys_admin_over_sb_userns: true, ..DENIED },
                MayDecodeFh { o_directory: true, anchor_is_mounted: true,
                              sys_admin_over_mnt_ns: true, ..DENIED }] {
        assert_eq!(may_decode_fh(leg), Err(Errno::Eperm), "leg selected, DAC override missing");
        assert!(may_decode_fh(MayDecodeFh { dac_read_search_in_user_ns: true, ..leg }).is_ok());
    }
}

/// An entirely unprivileged caller is EPERM whatever it passes. # C: O(1)
#[test]
fn unprivileged_caller_is_denied() {
    assert_eq!(may_decode_fh(DENIED), Err(Errno::Eperm));
    assert_eq!(may_decode_fh(MayDecodeFh { o_directory: true, ..DENIED }), Err(Errno::Eperm));
    assert_eq!(may_decode_fh(MayDecodeFh { o_directory: true, dac_read_search_in_user_ns: true,
                                           ..DENIED }), Err(Errno::Eperm),
        "the DAC override alone selects no leg");
}

/// O_DIRECTORY's value is the real one; a wrong constant would silently send
/// every relaxed decode down the EPERM arm. # C: O(1)
#[test]
fn o_directory_bit_value() { assert_eq!(O_DIRECTORY, 0o200000); }

/// Both FID types classify as ours; the pre-generation 8-byte handle does not,
/// so an old handle cannot be decoded against the new layout. # C: O(1)
#[test]
fn classification_matches_the_two_encoded_types() {
    assert!(header_is_our_fid(FID_LEN, HANDLE_TYPE_INO_GEN));
    assert!(header_is_our_fid(FID_LEN_PARENT, HANDLE_TYPE_INO_GEN_PARENT));
    assert!(!header_is_our_fid(8, HANDLE_TYPE_INO_GEN));
}
