use super::*;

const WEIGHT: u32 = 1024;

fn task(tid: u32) -> sched::Task {
    sched::Task::new(tid, "clone-cgroup-namespace",
        sched::SchedClass::Normal { weight: WEIGHT })
}

fn publish(parent: &sched::Task, child: &sched::Task, prepared: &cgroup::PreparedFork) {
    apply_new_namespaces(child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(), ns_bits_from_flags(CLONE_NEWCGROUP), false,
        NamespaceChange::CloneChild { share_vm: false, cgid: prepared.cgid() }).unwrap();
}

fn namespace_root(task: &sched::Task) -> alloc::string::String {
    let namespace = task.namespace_owner(NamespaceKind::Cgroup).unwrap();
    nscg::cgroup_ns::root_of(&namespace)
}

#[test]
fn clone_newcgroup_at_root_uses_prepared_root_before_membership_commit() {
    let _ = cgroup::realize_tree();
    let parent = task(98_220);
    let child = task(98_221);
    let prepared = cgroup::PreparedFork::prepare(None, parent.tid as u64, false,
        &vfs::Cred::root()).unwrap();
    assert_eq!(prepared.cgid(), cgroup::ROOT_CGROUP);

    publish(&parent, &child, &prepared);
    assert_eq!(namespace_root(&child), "/");
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgroup::ROOT_CGROUP,
        "namespace root is final before cgroup membership publication");

    prepared.commit(child.tid as u64);
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgroup::ROOT_CGROUP);
    assert_eq!(namespace_root(&child), "/");
    cgroup::on_exit(child.tid as u64, child.tid as u64);
}

#[test]
fn clone_newcgroup_inherits_prepared_nonroot_parent_before_commit() {
    let _ = cgroup::realize_tree();
    let name = "b3320-clone-newcgroup-inherited";
    let cgid = cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap();
    let parent = task(98_222);
    let child = task(98_223);
    cgroup::attach_tid_into(cgid, parent.tid as u64).unwrap();
    let prepared = cgroup::PreparedFork::prepare(None, parent.tid as u64, false,
        &vfs::Cred::root()).unwrap();
    assert_eq!(prepared.cgid(), cgid);

    publish(&parent, &child, &prepared);
    assert_eq!(namespace_root(&child), alloc::format!("/{name}"));
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgroup::ROOT_CGROUP,
        "the child is unpublished while its namespace root is final");

    prepared.commit(child.tid as u64);
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgid);
    assert_eq!(namespace_root(&child), alloc::format!("/{name}"));
    cgroup::on_exit(child.tid as u64, child.tid as u64);
    cgroup::on_exit(parent.tid as u64, parent.tid as u64);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn clone_newcgroup_into_cgroup_uses_prepared_destination_not_parent() {
    let _ = cgroup::realize_tree();
    let src_name = "b3320-clone-newcgroup-src";
    let dst_name = "b3320-clone-newcgroup-dst";
    let src = cgroup::mkdir_child(cgroup::ROOT_CGROUP, src_name, 0, 0).unwrap();
    let dst = cgroup::mkdir_child(cgroup::ROOT_CGROUP, dst_name, 0, 0).unwrap();
    let parent = task(98_224);
    let child = task(98_225);
    cgroup::attach_tid_into(src, parent.tid as u64).unwrap();
    let prepared = cgroup::PreparedFork::prepare(Some(dst), parent.tid as u64, false,
        &vfs::Cred::root()).unwrap();
    assert_eq!(prepared.cgid(), dst);

    publish(&parent, &child, &prepared);
    assert_eq!(namespace_root(&child), alloc::format!("/{dst_name}"));
    assert_ne!(namespace_root(&child), alloc::format!("/{src_name}"));
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgroup::ROOT_CGROUP,
        "CLONE_INTO_CGROUP membership commits after namespace construction");

    prepared.commit(child.tid as u64);
    assert_eq!(cgroup::cgroup_of(child.tid as u64), dst);
    assert_eq!(namespace_root(&child), alloc::format!("/{dst_name}"));
    cgroup::on_exit(child.tid as u64, child.tid as u64);
    cgroup::on_exit(parent.tid as u64, parent.tid as u64);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, src_name).unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, dst_name).unwrap();
}
