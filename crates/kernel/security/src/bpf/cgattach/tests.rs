// Hosted tests for the cgroup attach-list algebra. `P = u32` stands in
// for the program identity the kernel store binds (`cgstore::ProgRef`).

use super::*;

fn list(flags: u32, progs: &[(u32, u32)]) -> AttachList<u32> {
    AttachList {
        flags, revision: 0,
        progs: progs.iter().map(|&(p, f)| Entry { prog: p, id: p, flags: f }).collect(),
    }
}

fn req(prog: u32, flags: u32) -> AttachReq<u32> {
    AttachReq { prog, id: prog, replace: None, flags, id_or_fd: 0, revision: 0 }
}

fn progs_of(l: &AttachList<u32>) -> Vec<u32> { l.progs.iter().map(|e| e.prog).collect() }

#[test]
fn override_and_multi_together_is_einval() {
    let mut l = AttachList::<u32>::new();
    let r = req(1, af::ALLOW_OVERRIDE | af::ALLOW_MULTI);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn replace_without_multi_is_einval() {
    let mut l = AttachList::<u32>::new();
    let mut r = req(1, af::REPLACE);
    r.replace = Some(2);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn replace_flag_without_replace_prog_is_einval() {
    let mut l = AttachList::<u32>::new();
    let r = req(1, af::ALLOW_MULTI | af::REPLACE);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn replace_prog_without_replace_flag_is_einval() {
    let mut l = AttachList::<u32>::new();
    let mut r = req(1, af::ALLOW_MULTI);
    r.replace = Some(2);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn replace_combined_with_before_is_einval() {
    let mut l = AttachList::<u32>::new();
    let mut r = req(1, af::ALLOW_MULTI | af::REPLACE | af::BEFORE);
    r.replace = Some(2);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn stale_expected_revision_is_estale() {
    let mut l = list(af::ALLOW_MULTI, &[(7, 0)]);
    l.revision = 3;
    let mut r = req(1, af::ALLOW_MULTI);
    r.revision = 2;
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Estale));
}

#[test]
fn matching_expected_revision_attaches_and_bumps_it() {
    let mut l = list(af::ALLOW_MULTI, &[(7, 0)]);
    l.revision = 3;
    let mut r = req(1, af::ALLOW_MULTI);
    r.revision = 3;
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Ok(()));
    assert_eq!(l.revision, 4);
}

#[test]
fn ancestor_single_attach_without_override_vetoes_child_with_eperm() {
    let parent = list(0, &[(9, 0)]);
    let mut l = AttachList::<u32>::new();
    assert_eq!(attach(&mut l, &[&parent], req(1, 0), Anchor::None), Err(Errno::Eperm));
}

#[test]
fn ancestor_override_or_multi_permits_child_attach() {
    let over = list(af::ALLOW_OVERRIDE, &[(9, 0)]);
    let mut l = AttachList::<u32>::new();
    assert_eq!(attach(&mut l, &[&over], req(1, 0), Anchor::None), Ok(()));
    let multi = list(af::ALLOW_MULTI, &[(9, 0), (10, 0)]);
    let mut l2 = AttachList::<u32>::new();
    assert_eq!(attach(&mut l2, &[&multi], req(1, 0), Anchor::None), Ok(()));
}

#[test]
fn empty_ancestor_is_transparent_and_the_walk_continues() {
    let parent = AttachList::<u32>::new();
    let grand = list(0, &[(9, 0)]);
    let mut l = AttachList::<u32>::new();
    assert_eq!(attach(&mut l, &[&parent, &grand], req(1, 0), Anchor::None), Err(Errno::Eperm));
}

#[test]
fn mode_change_on_a_populated_list_is_eperm() {
    let mut l = list(af::ALLOW_MULTI, &[(7, 0)]);
    assert_eq!(attach(&mut l, &[], req(1, 0), Anchor::None), Err(Errno::Eperm));
    let mut l2 = list(0, &[(7, 0)]);
    assert_eq!(attach(&mut l2, &[], req(1, af::ALLOW_MULTI), Anchor::None), Err(Errno::Eperm));
}

#[test]
fn single_attach_replaces_in_place() {
    let mut l = list(0, &[(7, 0)]);
    assert_eq!(attach(&mut l, &[], req(1, 0), Anchor::None), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1]);
}

#[test]
fn multi_attach_appends_in_fifo_order() {
    let mut l = AttachList::<u32>::new();
    assert_eq!(attach(&mut l, &[], req(1, af::ALLOW_MULTI), Anchor::None), Ok(()));
    assert_eq!(attach(&mut l, &[], req(2, af::ALLOW_MULTI), Anchor::None), Ok(()));
    assert_eq!(attach(&mut l, &[], req(3, af::ALLOW_MULTI), Anchor::None), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 2, 3]);
}

#[test]
fn attaching_the_same_prog_twice_under_multi_is_einval() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    assert_eq!(attach(&mut l, &[], req(1, af::ALLOW_MULTI), Anchor::None), Err(Errno::Einval));
}

#[test]
fn replacing_an_absent_prog_is_enoent() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    let mut r = req(2, af::ALLOW_MULTI | af::REPLACE);
    r.replace = Some(9);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Enoent));
}

#[test]
fn replace_swaps_the_named_entry_and_keeps_its_position() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0), (3, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::REPLACE);
    r.replace = Some(2);
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 9, 3]);
}

#[test]
fn before_without_an_anchor_prepends() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0)]);
    assert_eq!(attach(&mut l, &[], req(9, af::ALLOW_MULTI | af::BEFORE), Anchor::None), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![9, 1, 2]);
}

#[test]
fn before_and_after_together_on_a_populated_list_is_einval() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    let f = af::ALLOW_MULTI | af::BEFORE | af::AFTER;
    assert_eq!(attach(&mut l, &[], req(9, f), Anchor::None), Err(Errno::Einval));
}

#[test]
fn an_anchor_demands_exactly_one_of_before_or_after() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0)]);
    let mut r = req(9, af::ALLOW_MULTI);
    r.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r, Anchor::Prog(2)), Err(Errno::Einval));
}

#[test]
fn anchored_insertion_lands_beside_the_anchor() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0), (3, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER);
    r.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r, Anchor::Prog(2)), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 2, 9, 3]);

    let mut r2 = req(8, af::ALLOW_MULTI | af::BEFORE);
    r2.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r2, Anchor::Prog(3)), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 2, 9, 8, 3]);
}

#[test]
fn an_anchor_by_id_resolves_the_same_way() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER | af::ID);
    r.id_or_fd = 1;
    assert_eq!(attach(&mut l, &[], r, Anchor::Id(1)), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 9, 2]);
}

#[test]
fn a_missing_anchor_is_enoent() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER);
    r.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r, Anchor::Prog(4)), Err(Errno::Enoent));
}

#[test]
fn an_anchor_must_agree_with_the_new_entry_on_preorder() {
    let mut l = list(af::ALLOW_MULTI, &[(1, af::PREORDER)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER);
    r.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r, Anchor::Prog(1)), Err(Errno::Einval));
}

#[test]
fn a_link_anchored_prog_attach_is_einval() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER | af::LINK);
    r.id_or_fd = 1;
    assert_eq!(attach(&mut l, &[], r, Anchor::None), Err(Errno::Einval));
}

#[test]
fn an_unresolvable_anchor_surfaces_after_the_hierarchy_vetoes() {
    // EPERM (mode change) beats the anchor's EBADF, matching the order
    // `__cgroup_bpf_attach()` runs its checks in.
    let mut l = list(0, &[(1, 0)]);
    let mut r = req(9, af::ALLOW_MULTI | af::AFTER);
    r.id_or_fd = 5;
    assert_eq!(attach(&mut l, &[], r, Anchor::Unresolved(Errno::Ebadf)), Err(Errno::Eperm));

    let mut l2 = list(af::ALLOW_MULTI, &[(1, 0)]);
    let mut r2 = req(9, af::ALLOW_MULTI | af::AFTER);
    r2.id_or_fd = 5;
    assert_eq!(attach(&mut l2, &[], r2, Anchor::Unresolved(Errno::Ebadf)), Err(Errno::Ebadf));
}

#[test]
fn a_full_list_is_e2big() {
    let entries: Vec<(u32, u32)> = (0..uapi::CGROUP_MAX_PROGS as u32).map(|i| (i + 1, 0)).collect();
    let mut l = list(af::ALLOW_MULTI, &entries);
    assert_eq!(attach(&mut l, &[], req(9999, af::ALLOW_MULTI), Anchor::None), Err(Errno::E2big));
}

#[test]
fn detach_from_an_empty_single_attach_list_is_enoent() {
    let mut l = AttachList::<u32>::new();
    assert_eq!(detach(&mut l, None, 0), Err(Errno::Enoent));
}

#[test]
fn single_attach_detach_ignores_the_named_prog() {
    let mut l = list(0, &[(7, 0)]);
    assert_eq!(detach(&mut l, None, 0), Ok(()));
    assert!(l.is_empty());
    assert_eq!(l.flags, 0);
}

#[test]
fn multi_detach_without_a_prog_is_einval() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0)]);
    assert_eq!(detach(&mut l, None, 0), Err(Errno::Einval));
}

#[test]
fn multi_detach_removes_only_the_named_prog() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0), (2, 0), (3, 0)]);
    assert_eq!(detach(&mut l, Some(&2), 0), Ok(()));
    assert_eq!(progs_of(&l), alloc::vec![1, 3]);
    assert_eq!(detach(&mut l, Some(&9), 0), Err(Errno::Enoent));
}

#[test]
fn detaching_the_last_prog_clears_the_mode() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    assert_eq!(detach(&mut l, Some(&1), 0), Ok(()));
    assert_eq!(l.flags, 0);
    assert_eq!(l.revision, 1);
}

#[test]
fn stale_revision_blocks_detach() {
    let mut l = list(af::ALLOW_MULTI, &[(1, 0)]);
    l.revision = 5;
    assert_eq!(detach(&mut l, Some(&1), 4), Err(Errno::Estale));
}

#[test]
fn effective_is_the_leaf_list_when_no_ancestor_allows_multi() {
    let leaf = list(0, &[(1, 0)]);
    let parent = list(0, &[(2, 0)]);
    assert_eq!(effective(&[&leaf, &parent]), alloc::vec![1]);
}

#[test]
fn effective_falls_through_an_empty_leaf_to_the_nearest_populated_ancestor() {
    let leaf = AttachList::<u32>::new();
    let parent = list(0, &[(2, 0)]);
    let grand = list(0, &[(3, 0)]);
    assert_eq!(effective(&[&leaf, &parent, &grand]), alloc::vec![2]);
}

#[test]
fn effective_concatenates_multi_levels_leaf_first() {
    let leaf = list(af::ALLOW_MULTI, &[(1, 0), (2, 0)]);
    let parent = list(af::ALLOW_MULTI, &[(3, 0)]);
    let grand = list(af::ALLOW_MULTI, &[(4, 0)]);
    assert_eq!(effective(&[&leaf, &parent, &grand]), alloc::vec![1, 2, 3, 4]);
}

#[test]
fn a_non_multi_ancestor_is_skipped_but_does_not_end_the_walk() {
    // `compute_effective_progs()` tests each level independently
    // (`cnt == 0 || flags & MULTI`), so a non-MULTI ancestor drops out
    // while a MULTI grandparent above it still contributes.
    let leaf = list(af::ALLOW_MULTI, &[(1, 0)]);
    let parent = list(0, &[(2, 0)]);
    let grand = list(af::ALLOW_MULTI, &[(3, 0)]);
    assert_eq!(effective(&[&leaf, &parent, &grand]), alloc::vec![1, 3]);
}

#[test]
fn preorder_entries_run_first_root_to_leaf() {
    let leaf = list(af::ALLOW_MULTI, &[(1, af::PREORDER), (2, 0)]);
    let parent = list(af::ALLOW_MULTI, &[(3, af::PREORDER), (4, 0)]);
    assert_eq!(effective(&[&leaf, &parent]), alloc::vec![3, 1, 2, 4]);
}

#[test]
fn preorder_entries_keep_list_order_within_a_level() {
    let leaf = list(af::ALLOW_MULTI, &[(1, af::PREORDER), (2, af::PREORDER), (3, 0)]);
    assert_eq!(effective(&[&leaf]), alloc::vec![1, 2, 3]);
}

#[test]
fn effective_of_an_empty_hierarchy_is_empty() {
    let leaf = AttachList::<u32>::new();
    assert!(effective(&[&leaf]).is_empty());
}
