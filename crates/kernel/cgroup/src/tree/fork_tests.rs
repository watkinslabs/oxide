use alloc::string::ToString;
use vfs::VfsError;

use super::{ROOT, Tree};

fn limited_tree(max: u64) -> (Tree, u64) {
    let mut tree = Tree::new();
    tree.mount_root();
    tree.write_subtree_control(ROOT, "+pids").unwrap();
    let cgid = tree.create(ROOT, "fork-target").unwrap().0;
    tree.write_file(cgid, "pids.max", &max.to_string()).unwrap();
    (tree, cgid)
}

#[test]
fn prepared_fork_pins_its_live_destination() {
    let (mut tree, cgid) = limited_tree(2);
    tree.prepare_fork(cgid).unwrap();
    assert_eq!(tree.remove(cgid), Err(VfsError::Ebusy));

    tree.commit_fork(cgid, 700, 699, false, 0);
    assert_eq!(tree.cgroup_of(700), cgid);
    tree.exit_task(700, 700);
    tree.remove(cgid).unwrap();
}

#[test]
fn pending_charge_excludes_a_second_fork_from_the_last_slot() {
    let (mut tree, cgid) = limited_tree(1);
    assert!(!tree.fork_would_exceed_pids(cgid));
    tree.prepare_fork(cgid).unwrap();
    assert!(tree.fork_would_exceed_pids(cgid),
        "the admitted but unpublished task owns the final slot");
    assert_eq!(tree.prepare_fork(cgid), Err(VfsError::Eagain));
    assert_eq!(tree.read_file(cgid, "pids.current").unwrap(), b"1\n");

    tree.cancel_fork(cgid);
    assert_eq!(tree.read_file(cgid, "pids.current").unwrap(), b"0\n");
    tree.prepare_fork(cgid).unwrap();
    tree.cancel_fork(cgid);
    tree.remove(cgid).unwrap();
}

#[test]
fn cancellation_releases_both_charge_and_pin() {
    let (mut tree, cgid) = limited_tree(1);
    tree.prepare_fork(cgid).unwrap();
    tree.cancel_fork(cgid);
    assert!(!tree.fork_would_exceed_pids(cgid));
    assert_eq!(tree.read_file(cgid, "pids.current").unwrap(), b"0\n");
    tree.remove(cgid).unwrap();
}

#[test]
fn prepared_fork_drop_restores_visible_count_and_removability() {
    let _ = crate::realize_tree();
    crate::write_file(ROOT, "cgroup.subtree_control", "+pids").unwrap();
    let name = "b3320-cgroup-prepared-drop";
    let cgid = crate::mkdir_child(ROOT, name, 0, 0).unwrap();
    crate::write_file(cgid, "pids.max", "1").unwrap();
    let prepared = crate::PreparedFork::prepare(
        Some(cgid), 710, false, &vfs::Cred::root()).unwrap();
    assert_eq!(crate::read_file(cgid, "pids.current").unwrap(), b"1\n");
    drop(prepared);
    assert_eq!(crate::read_file(cgid, "pids.current").unwrap(), b"0\n");
    crate::rmdir_child(ROOT, name).unwrap();
}

#[test]
fn common_ancestor_is_the_delegation_boundary_for_cross_branch_clone() {
    let mut tree = Tree::new();
    tree.mount_root();
    let boundary = tree.create(ROOT, "boundary").unwrap().0;
    let src = tree.create(boundary, "src").unwrap().0;
    let dst = tree.create(boundary, "dst").unwrap().0;
    assert_eq!(tree.fork_common_ancestor(src, dst), Ok(boundary));
    assert_eq!(tree.fork_common_ancestor(src, src), Ok(src));
}

#[test]
fn nsdelegate_requires_source_and_destination_visibility() {
    let mut tree = Tree::new();
    tree.mount_root();
    let visible = tree.create(ROOT, "visible").unwrap().0;
    let src = tree.create(visible, "src").unwrap().0;
    let dst = tree.create(ROOT, "hidden-dst").unwrap().0;
    assert_eq!(tree.validate_fork_destination(src, dst, false, Some("/visible")),
        Err(VfsError::Enoent));
    assert_eq!(tree.validate_fork_destination(src, dst, false, None), Ok(()),
        "positive control: the same topology is allowed without nsdelegate");
}

#[test]
fn destination_vet_rejects_internal_process_for_domain_controller() {
    let mut tree = Tree::new();
    tree.mount_root();
    tree.write_subtree_control(ROOT, "+memory").unwrap();
    let dst = tree.create(ROOT, "domain-parent").unwrap().0;
    tree.write_subtree_control(dst, "+memory").unwrap();
    assert_eq!(tree.validate_fork_destination(ROOT, dst, false, None),
        Err(VfsError::Ebusy));
    assert_eq!(tree.validate_fork_destination(ROOT, ROOT, false, None), Ok(()),
        "positive control: hierarchy root is exempt from no-internal-process");
}

#[test]
fn thread_clone_cannot_cross_the_domain_only_hierarchy() {
    let mut tree = Tree::new();
    tree.mount_root();
    let dst = tree.create(ROOT, "thread-dst").unwrap().0;
    assert_eq!(tree.validate_fork_destination(ROOT, dst, true, None),
        Err(VfsError::Eopnotsupp));
    assert_eq!(tree.validate_fork_destination(dst, dst, true, None), Ok(()));
}
