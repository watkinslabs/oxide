// Hosted unit tests for the rename(2) family decision core. Every expectation
// below is read out of `/home/nd/oxide/linux-master/fs/namei.c`
// (`filename_renameat2`, `__start_renaming`, `lookup_one_qstr_excl`), not from
// a man page.

use super::*;

const NR: u32 = RENAME_NOREPLACE;
const EX: u32 = RENAME_EXCHANGE;
const WO: u32 = RENAME_WHITEOUT;

#[test] fn flags_unknown_bit_is_einval() {
    assert_eq!(check_flags(1 << 3), Err(Errno::Einval));
    assert_eq!(check_flags(u32::MAX), Err(Errno::Einval));
}

#[test] fn flags_exchange_conflicts_with_noreplace_and_whiteout() {
    assert_eq!(check_flags(NR | EX), Err(Errno::Einval));
    assert_eq!(check_flags(EX | WO), Err(Errno::Einval));
    assert_eq!(check_flags(NR | EX | WO), Err(Errno::Einval));
}

#[test] fn flags_noreplace_plus_whiteout_is_legal() {
    // `filename_renameat2` only rejects EXCHANGE combined with the other two.
    assert_eq!(check_flags(NR | WO), Ok(()));
    for f in [0, NR, EX, WO] { assert_eq!(check_flags(f), Ok(())); }
}

#[test] fn old_side_non_norm_is_ebusy_regardless_of_flags() {
    for k in [LastKind::Dot, LastKind::Dotdot, LastKind::Root] {
        assert_eq!(check_last_kinds(k, LastKind::Norm, 0), Err(Errno::Ebusy));
        assert_eq!(check_last_kinds(k, LastKind::Norm, NR), Err(Errno::Ebusy));
        assert_eq!(check_last_kinds(k, LastKind::Norm, EX), Err(Errno::Ebusy));
    }
}

#[test] fn new_side_non_norm_is_ebusy_but_eexist_under_noreplace() {
    // The `error = -EEXIST` assignment sits BETWEEN the two LAST_NORM tests.
    for k in [LastKind::Dot, LastKind::Dotdot, LastKind::Root] {
        assert_eq!(check_last_kinds(LastKind::Norm, k, 0), Err(Errno::Ebusy));
        assert_eq!(check_last_kinds(LastKind::Norm, k, EX), Err(Errno::Ebusy));
        assert_eq!(check_last_kinds(LastKind::Norm, k, NR), Err(Errno::Eexist));
    }
    assert_eq!(check_last_kinds(LastKind::Norm, LastKind::Norm, NR), Ok(()));
}

#[test] fn old_side_wins_over_new_side() {
    assert_eq!(check_last_kinds(LastKind::Dot, LastKind::Dotdot, NR), Err(Errno::Ebusy));
}

#[test] fn trap_source_ancestor_is_einval() {
    for f in [0, NR, EX, WO] {
        assert_eq!(check_trap(Trap::SourceIsAncestorOfTarget, f), Err(Errno::Einval));
    }
}

#[test] fn trap_target_ancestor_is_enotempty_except_exchange() {
    assert_eq!(check_trap(Trap::TargetIsAncestorOfSource, 0), Err(Errno::Enotempty));
    assert_eq!(check_trap(Trap::TargetIsAncestorOfSource, NR), Err(Errno::Enotempty));
    assert_eq!(check_trap(Trap::TargetIsAncestorOfSource, WO), Err(Errno::Enotempty));
    assert_eq!(check_trap(Trap::TargetIsAncestorOfSource, EX), Err(Errno::Einval));
}

#[test] fn trap_none_passes() {
    assert_eq!(check_trap(Trap::None, EX), Ok(()));
}

#[test] fn trailing_slash_detection() {
    assert!(has_trailing_slash("/tmp/foo/"));
    assert!(has_trailing_slash("foo//"));
    assert!(!has_trailing_slash("/tmp/foo"));
    assert!(!has_trailing_slash("foo"));
    // The bare root is LAST_ROOT and never reaches this test.
    assert!(!has_trailing_slash("/"));
}

#[test] fn trailing_slash_on_nondir_source_is_enotdir() {
    assert_eq!(check_trailing_slashes(false, false, true, false, 0), Err(Errno::Enotdir));
    // …and on the destination too, for a non-directory source.
    assert_eq!(check_trailing_slashes(false, false, false, true, 0), Err(Errno::Enotdir));
    // A directory source tolerates both.
    assert_eq!(check_trailing_slashes(true, false, true, true, 0), Ok(()));
}

#[test] fn exchange_ignores_destination_slash_for_nondir_source() {
    // The `!(flags & RENAME_EXCHANGE) && new_last…` clause is skipped, but the
    // EXCHANGE-specific test above it fires when the DESTINATION is not a dir.
    assert_eq!(check_trailing_slashes(false, true, false, true, EX), Ok(()));
    assert_eq!(check_trailing_slashes(false, false, false, true, EX), Err(Errno::Enotdir));
    assert_eq!(check_trailing_slashes(true, true, true, true, EX), Ok(()));
}

#[test] fn existence_missing_source_is_enoent_first() {
    assert_eq!(check_existence(false, true, NR), Err(Errno::Enoent));
    assert_eq!(check_existence(false, false, EX), Err(Errno::Enoent));
}

#[test] fn exchange_requires_both_to_exist() {
    assert_eq!(check_existence(true, false, EX), Err(Errno::Enoent));
    assert_eq!(check_existence(true, true, EX), Ok(()));
}

#[test] fn noreplace_occupied_destination_is_eexist() {
    assert_eq!(check_existence(true, true, NR), Err(Errno::Eexist));
    assert_eq!(check_existence(true, false, NR), Ok(()));
    // Plain rename happily replaces.
    assert_eq!(check_existence(true, true, 0), Ok(()));
}
