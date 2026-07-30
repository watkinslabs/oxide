use vfs::VfsError;

use super::{ROOT, Tree};

#[test]
fn offline_destination_cannot_acquire_membership() {
    let mut tree = Tree::new();
    tree.mount_root();
    assert_eq!(tree.add_proc(99, 10), Err(VfsError::Enodev));
    assert_eq!(tree.cgroup_of(10), ROOT);
}

#[test]
fn exited_leader_marker_survives_process_migration() {
    let mut tree = Tree::new();
    tree.mount_root();
    tree.write_subtree_control(ROOT, "+pids").unwrap();
    let (source, _) = tree.create(ROOT, "source").unwrap();
    let (destination, _) = tree.create(ROOT, "destination").unwrap();
    tree.add_proc(source, 20).unwrap();
    tree.add_thread(20, 21);
    assert_eq!(tree.subtree_proc_count(source), 2);

    assert_eq!(tree.exit_task(20, 20), None);
    assert_eq!(tree.subtree_proc_count(source), 1);
    tree.add_proc(destination, 20).unwrap();
    assert_eq!(tree.cgroup_of(21), destination);
    assert_eq!(tree.subtree_proc_count(destination), 1);

    assert_eq!(tree.exit_task(21, 20), Some(destination));
    assert_eq!(tree.subtree_proc_count(destination), 0);
    tree.remove(destination).unwrap();
}

#[test]
fn domain_thread_move_rejects_cross_domain_without_shadow_membership() {
    let mut tree = Tree::new();
    tree.mount_root();
    let (source, _) = tree.create(ROOT, "source").unwrap();
    let (destination, _) = tree.create(ROOT, "destination").unwrap();
    tree.add_proc(source, 30).unwrap();
    tree.add_thread(30, 31);

    assert_eq!(tree.move_thread(destination, 31), Err(VfsError::Eopnotsupp));
    assert_eq!(tree.cgroup_of(31), source);
    assert_eq!(tree.direct_procs(destination).unwrap(), alloc::vec![]);
    assert_eq!(tree.direct_threads(source).unwrap(), alloc::vec![30, 31]);
}
