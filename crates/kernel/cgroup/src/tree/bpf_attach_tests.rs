use alloc::sync::Arc;

use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use super::{
    BpfAttachAnchor, BpfAttachError, BpfAttachMode, BpfAttachOrder, BpfAttachPosition,
    CgroupBpfAttachType, ROOT, Tree,
};

fn prog(ino: u64) -> InodeRef {
    InodeBuilder::new(
        ino, mk_mode(FileType::CharDev, 0o600), default_inode_ops(), default_file_ops(),
    ).build()
}

fn assert_programs(actual: &[InodeRef], expected: &[&InodeRef]) {
    assert_eq!(actual.len(), expected.len());
    for (got, want) in actual.iter().zip(expected) {
        assert!(Arc::ptr_eq(got, want));
    }
}

#[test]
fn types_have_independent_direct_lists_revisions_and_effective_arrays() {
    let mut tree = Tree::new();
    tree.mount_root();
    let ingress = prog(100);
    let egress = prog(101);
    tree.bpf_attach(
        ROOT, CgroupBpfAttachType::InetIngress, Arc::clone(&ingress),
        BpfAttachMode::Multi, BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        ROOT, CgroupBpfAttachType::InetEgress, Arc::clone(&egress),
        BpfAttachMode::Multi, BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();

    let ingress_query = tree.bpf_query(ROOT, CgroupBpfAttachType::InetIngress).unwrap();
    let egress_query = tree.bpf_query(ROOT, CgroupBpfAttachType::InetEgress).unwrap();
    assert_eq!(ingress_query.revision, 2);
    assert_eq!(egress_query.revision, 2);
    assert_programs(&ingress_query.direct, &[&ingress]);
    assert_programs(&egress_query.direct, &[&egress]);
    assert_programs(
        &tree.bpf_effective(ROOT, CgroupBpfAttachType::InetIngress).unwrap(),
        &[&ingress],
    );
}

#[test]
fn hierarchy_orders_ancestor_preorder_before_child_and_postorder_after_child() {
    let mut tree = Tree::new();
    tree.mount_root();
    let (child, _) = tree.create(ROOT, "child").unwrap();
    let root_pre = prog(110);
    let root_post = prog(111);
    let child_pre = prog(112);
    let child_post = prog(113);
    let attach_type = CgroupBpfAttachType::InetEgress;

    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&root_post), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&root_pre), BpfAttachMode::Multi,
        BpfAttachOrder::PREORDER, None, 0,
    ).unwrap();
    tree.bpf_attach(
        child, attach_type, Arc::clone(&child_post), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        child, attach_type, Arc::clone(&child_pre), BpfAttachMode::Multi,
        BpfAttachOrder::PREORDER, None, 0,
    ).unwrap();

    assert_programs(
        &tree.bpf_effective(child, attach_type).unwrap(),
        &[&root_pre, &child_pre, &child_post, &root_post],
    );
}

#[test]
fn direct_before_after_order_requires_an_anchor_in_the_same_ordering_region() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet4Connect;
    let first = prog(120);
    let second = prog(121);
    let middle = prog(122);
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&first), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&second), BpfAttachMode::Multi,
        BpfAttachOrder {
            position: BpfAttachPosition::After(BpfAttachAnchor::Legacy(&first)),
            preorder: false,
        },
        None, 0,
    ).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&middle), BpfAttachMode::Multi,
        BpfAttachOrder {
            position: BpfAttachPosition::Before(BpfAttachAnchor::Legacy(&second)),
            preorder: false,
        },
        None, 0,
    ).unwrap();
    assert_programs(
        &tree.bpf_query(ROOT, attach_type).unwrap().direct,
        &[&first, &middle, &second],
    );
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, prog(123), BpfAttachMode::Multi,
            BpfAttachOrder {
                position: BpfAttachPosition::Before(BpfAttachAnchor::Legacy(&first)),
                preorder: true,
            },
            None, 0,
        ),
        Err(BpfAttachError::Invalid),
    );
}

#[test]
fn pinned_runtime_observes_publications_and_survives_rmdir() {
    let mut tree = Tree::new();
    tree.mount_root();
    let (child, _) = tree.create(ROOT, "socket-owner").unwrap();
    let runtime = tree.bpf_runtime(child).unwrap();
    let attached = prog(130);
    let weak = Arc::downgrade(&attached);
    tree.bpf_attach(
        child, CgroupBpfAttachType::InetIngress, attached,
        BpfAttachMode::Multi, BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    assert_eq!(runtime.effective(CgroupBpfAttachType::InetIngress).len(), 1);

    tree.remove(child).unwrap();
    assert!(tree.bpf_effective(child, CgroupBpfAttachType::InetIngress).is_none());
    assert_eq!(runtime.effective(CgroupBpfAttachType::InetIngress).len(), 1);
    assert!(weak.upgrade().is_some());
    drop(runtime);
    assert!(weak.upgrade().is_none());
}

#[test]
fn task_runtime_is_pinned_with_membership_and_absent_tasks_fall_back_to_root() {
    let mut tree = Tree::new();
    let early_root = tree.bpf_root_runtime();
    assert!(!tree.is_mounted());
    assert!(tree.mount_root());
    assert!(Arc::ptr_eq(&early_root, &tree.bpf_root_runtime()));
    let (child, _) = tree.create(ROOT, "member").unwrap();
    tree.add_proc(child, 42).unwrap();
    assert_eq!(tree.bpf_runtime_for_task(42).cgid(), child);
    assert_eq!(tree.bpf_runtime_for_task(404).cgid(), ROOT);
}

#[test]
fn device_compatibility_wrappers_retain_b1553_semantics() {
    let mut tree = Tree::new();
    tree.mount_root();
    let (child, _) = tree.create(ROOT, "device").unwrap();
    let root_prog = prog(140);
    let child_prog = prog(141);
    tree.bpf_device_attach(
        ROOT, Arc::clone(&root_prog), BpfAttachMode::Override, None, 0,
    ).unwrap();
    tree.bpf_device_attach(
        child, Arc::clone(&child_prog), BpfAttachMode::Single, None, 0,
    ).unwrap();
    assert_programs(&tree.bpf_device_effective(child).unwrap(), &[&child_prog]);
    assert_eq!(tree.bpf_device_query(ROOT).unwrap().revision, 2);
    tree.bpf_device_detach(child, None, 0).unwrap();
    assert_programs(&tree.bpf_device_effective(child).unwrap(), &[&root_prog]);
}

#[test]
fn revision_duplicate_and_replace_guards_are_per_type() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet6Connect;
    let first = prog(150);
    let second = prog(151);
    let replacement = prog(152);
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, Arc::clone(&first), BpfAttachMode::Multi,
            BpfAttachOrder::DEFAULT, None, 2,
        ),
        Err(BpfAttachError::Stale),
    );
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&first), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, Arc::clone(&first), BpfAttachMode::Multi,
            BpfAttachOrder::DEFAULT, None, 0,
        ),
        Err(BpfAttachError::Duplicate),
    );
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&second), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 2,
    ).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&replacement), BpfAttachMode::Multi,
        BpfAttachOrder::PREORDER, Some(&first), 3,
    ).unwrap();
    assert_programs(
        &tree.bpf_query(ROOT, attach_type).unwrap().direct,
        &[&replacement, &second],
    );
    assert_programs(
        &tree.bpf_effective(ROOT, attach_type).unwrap(),
        &[&replacement, &second],
    );
    assert_eq!(
        tree.bpf_detach(ROOT, attach_type, Some(&second), 3),
        Err(BpfAttachError::Stale),
    );
    tree.bpf_detach(ROOT, attach_type, Some(&second), 4).unwrap();
    assert_eq!(tree.bpf_query(ROOT, attach_type).unwrap().revision, 5);
}

#[test]
fn non_overridable_ancestor_denies_descendants_and_override_yields() {
    let mut tree = Tree::new();
    tree.mount_root();
    let (child, _) = tree.create(ROOT, "child").unwrap();
    let attach_type = CgroupBpfAttachType::Inet4Bind;
    let root_prog = prog(160);
    let child_prog = prog(161);
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&root_prog), BpfAttachMode::Single,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    assert_eq!(
        tree.bpf_attach(
            child, attach_type, Arc::clone(&child_prog), BpfAttachMode::Multi,
            BpfAttachOrder::DEFAULT, None, 0,
        ),
        Err(BpfAttachError::Denied),
    );
    tree.bpf_detach(ROOT, attach_type, None, 0).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&root_prog), BpfAttachMode::Override,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        child, attach_type, Arc::clone(&child_prog), BpfAttachMode::Single,
        BpfAttachOrder::PREORDER, None, 0,
    ).unwrap();
    assert_programs(&tree.bpf_effective(child, attach_type).unwrap(), &[&child_prog]);
}

#[test]
fn legacy_and_link_owners_may_attach_the_same_program() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::InetIngress;
    let shared = prog(170);
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&shared), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 10, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    assert_programs(&tree.bpf_query(ROOT, attach_type).unwrap().direct, &[&shared, &shared]);
}

#[test]
fn distinct_links_may_attach_the_same_program() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::InetEgress;
    let shared = prog(171);
    tree.bpf_attach_link(
        ROOT, attach_type, 11, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 12, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    assert_programs(&tree.bpf_query(ROOT, attach_type).unwrap().direct, &[&shared, &shared]);
}

#[test]
fn legacy_detach_and_replace_never_select_link_owned_programs() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet4Bind;
    let shared = prog(172);
    let replacement = prog(173);
    tree.bpf_attach_link(
        ROOT, attach_type, 13, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    assert_eq!(
        tree.bpf_detach(ROOT, attach_type, Some(&shared), 0),
        Err(BpfAttachError::Missing),
    );
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, replacement, BpfAttachMode::Multi,
            BpfAttachOrder::DEFAULT, Some(&shared), 0,
        ),
        Err(BpfAttachError::Missing),
    );
    assert_programs(&tree.bpf_query(ROOT, attach_type).unwrap().direct, &[&shared]);
}

#[test]
fn link_close_selects_exact_link_not_same_program_or_legacy_owner() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet6Bind;
    let shared = prog(174);
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&shared), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 14, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 15, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    tree.bpf_detach_link(ROOT, attach_type, 15).unwrap();
    assert_programs(&tree.bpf_query(ROOT, attach_type).unwrap().direct, &[&shared, &shared]);
    tree.bpf_detach_link(ROOT, attach_type, 14).unwrap();
    assert_programs(&tree.bpf_query(ROOT, attach_type).unwrap().direct, &[&shared]);
}

#[test]
fn ordering_anchors_match_exact_owner_identity() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet4Connect;
    let shared = prog(175);
    let before = prog(176);
    tree.bpf_attach(
        ROOT, attach_type, Arc::clone(&shared), BpfAttachMode::Multi,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 16, Arc::clone(&shared), BpfAttachOrder::DEFAULT, 0,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 17, Arc::clone(&before),
        BpfAttachOrder {
            position: BpfAttachPosition::Before(BpfAttachAnchor::Link(16)),
            preorder: false,
        },
        0,
    ).unwrap();
    assert_programs(
        &tree.bpf_query(ROOT, attach_type).unwrap().direct,
        &[&shared, &before, &shared],
    );
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, prog(177), BpfAttachMode::Multi,
            BpfAttachOrder {
                position: BpfAttachPosition::After(BpfAttachAnchor::Legacy(&before)),
                preorder: false,
            },
            None, 0,
        ),
        Err(BpfAttachError::Missing),
    );
}

#[test]
fn unanchored_before_and_after_combination_is_empty_list_only() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Inet6Connect;
    tree.bpf_attach(
        ROOT, attach_type, prog(178), BpfAttachMode::Multi,
        BpfAttachOrder { position: BpfAttachPosition::Empty, preorder: false },
        None, 0,
    ).unwrap();
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, prog(179), BpfAttachMode::Multi,
            BpfAttachOrder { position: BpfAttachPosition::Empty, preorder: false },
            None, 0,
        ),
        Err(BpfAttachError::Invalid),
    );
}

#[test]
fn non_multi_resolves_relative_only_for_an_empty_direct_list() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::InetIngress;
    let absent = prog(182);
    let relative = BpfAttachOrder {
        position: BpfAttachPosition::Before(BpfAttachAnchor::Legacy(&absent)),
        preorder: false,
    };
    assert_eq!(
        tree.bpf_attach(
            ROOT, attach_type, prog(183), BpfAttachMode::Single,
            relative, None, 0,
        ),
        Err(BpfAttachError::Missing),
    );
    tree.bpf_attach(
        ROOT, attach_type, prog(184), BpfAttachMode::Single,
        BpfAttachOrder::DEFAULT, None, 0,
    ).unwrap();
    tree.bpf_attach(
        ROOT, attach_type, prog(185), BpfAttachMode::Single,
        relative, None, 0,
    ).expect("existing non-multi entry makes the relative anchor unused");
}

#[test]
fn link_attach_expected_revision_is_atomic() {
    let mut tree = Tree::new();
    tree.mount_root();
    let attach_type = CgroupBpfAttachType::Device;
    assert_eq!(
        tree.bpf_attach_link(
            ROOT, attach_type, 18, prog(180), BpfAttachOrder::DEFAULT, 2,
        ),
        Err(BpfAttachError::Stale),
    );
    tree.bpf_attach_link(
        ROOT, attach_type, 18, prog(180), BpfAttachOrder::DEFAULT, 1,
    ).unwrap();
    tree.bpf_attach_link(
        ROOT, attach_type, 19, prog(181), BpfAttachOrder::DEFAULT, 2,
    ).unwrap();
    assert_eq!(tree.bpf_query(ROOT, attach_type).unwrap().revision, 3);
}
