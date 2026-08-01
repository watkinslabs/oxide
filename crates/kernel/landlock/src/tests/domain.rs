// Enforcement over real hierarchies. These drive `Domain::check_fs` through the
// same walk the syscall hooks use, so a rule that is stored but consulted by
// nothing fails here.

use super::*;
use alloc::vec;

use crate::abi::RulesetAttr;
use crate::ruleset::Ruleset;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FileType, InodeBuilder, VfsPath};

fn dir_inode(ino: u64) -> vfs::InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}

fn child(parent: &Arc<Dentry>, name: &str, ino: u64) -> Arc<Dentry> {
    vfs::d_add(parent, name, dir_inode(ino))
}

fn path(mnt_id: u64, dentry: Arc<Dentry>) -> VfsPath {
    let inode = dentry.inode().expect("test dentry inode");
    VfsPath { mnt_id, dentry, inode, last_component: None }
}

fn ruleset(handled_fs: AccessMask) -> Arc<Ruleset> {
    Ruleset::new(&RulesetAttr { handled_fs, ..Default::default() })
}

fn enforce(parent: Option<&Arc<Domain>>, rs: &Ruleset) -> Arc<Domain> {
    Domain::merge(parent, rs).expect("layer budget")
}

#[test]
fn a_rule_covers_the_named_directory_and_everything_beneath_it() {
    let root = Dentry::new_root(dir_inode(1));
    let run  = child(&root, "run", 2);
    let udev = child(&run, "udev", 3);
    let data = child(&udev, "data", 4);

    let rs = ruleset(ACCESS_FS_READ_FILE);
    rs.add_fs(udev.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = enforce(None, &rs);

    assert!(dom.check_fs(&path(7, udev.clone()), ACCESS_FS_READ_FILE).is_ok());
    assert!(dom.check_fs(&path(7, data), ACCESS_FS_READ_FILE).is_ok());
    // A sibling above the rule is not covered by it.
    assert_eq!(dom.check_fs(&path(7, run), ACCESS_FS_READ_FILE), Err(Errno::Eacces));
}

#[test]
fn a_right_the_layer_does_not_handle_passes_through() {
    let root = Dentry::new_root(dir_inode(1));
    let d = child(&root, "d", 2);
    let rs = ruleset(ACCESS_FS_READ_FILE);
    rs.add_fs(d.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = enforce(None, &rs);
    // Writing is not filtered by this layer at all.
    assert!(dom.check_fs(&path(7, root.clone()), ACCESS_FS_WRITE_FILE).is_ok());
    assert_eq!(dom.check_fs(&path(7, root), ACCESS_FS_READ_FILE), Err(Errno::Eacces));
}

#[test]
fn a_rule_is_keyed_on_the_object_so_a_second_path_to_it_matches() {
    // Reaching the same directory through another mount id must not lose the
    // rule; rights are tied to the object, not to the route taken to it.
    let root = Dentry::new_root(dir_inode(1));
    let d = child(&root, "d", 2);
    let rs = ruleset(ACCESS_FS_READ_FILE);
    rs.add_fs(d.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = enforce(None, &rs);
    assert!(dom.check_fs(&path(7, d.clone()), ACCESS_FS_READ_FILE).is_ok());
    assert!(dom.check_fs(&path(9, d), ACCESS_FS_READ_FILE).is_ok());
}

#[test]
fn stacking_can_only_narrow_never_widen() {
    // The central stacking property: a second enforcement cannot restore a
    // right the first one withheld.
    let root = Dentry::new_root(dir_inode(1));
    let a = child(&root, "a", 2);
    let b = child(&root, "b", 3);

    let rs1 = ruleset(ACCESS_FS_READ_FILE);
    rs1.add_fs(a.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let d1 = enforce(None, &rs1);
    assert!(d1.check_fs(&path(7, a.clone()), ACCESS_FS_READ_FILE).is_ok());
    assert_eq!(d1.check_fs(&path(7, b.clone()), ACCESS_FS_READ_FILE), Err(Errno::Eacces));

    // A second ruleset that grants b as well.
    let rs2 = ruleset(ACCESS_FS_READ_FILE);
    rs2.add_fs(a.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    rs2.add_fs(b.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let d2 = enforce(Some(&d1), &rs2);
    assert_eq!(d2.num_layers(), 2);
    // b is still denied: the first layer never granted it.
    assert_eq!(d2.check_fs(&path(7, b), ACCESS_FS_READ_FILE), Err(Errno::Eacces));
    assert!(d2.check_fs(&path(7, a), ACCESS_FS_READ_FILE).is_ok());
}

#[test]
fn a_rule_added_after_enforcement_cannot_widen_the_enforced_domain() {
    // The security property that makes a snapshot necessary: the ruleset fd
    // stays writable, so if enforcement read through to it a sandboxed thread
    // could grant itself the access it was just denied.
    let root = Dentry::new_root(dir_inode(1));
    let a = child(&root, "a", 2);
    let b = child(&root, "b", 3);

    let rs = ruleset(ACCESS_FS_READ_FILE);
    rs.add_fs(a.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = enforce(None, &rs);
    assert_eq!(dom.check_fs(&path(7, b.clone()), ACCESS_FS_READ_FILE), Err(Errno::Eacces));

    rs.add_fs(b.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    assert_eq!(dom.check_fs(&path(7, b), ACCESS_FS_READ_FILE), Err(Errno::Eacces));
}

#[test]
fn the_layer_stack_is_capped() {
    let rs = ruleset(ACCESS_FS_READ_FILE);
    let mut dom = enforce(None, &rs);
    for _ in 1..MAX_NUM_LAYERS { dom = enforce(Some(&dom), &rs); }
    assert_eq!(dom.num_layers(), MAX_NUM_LAYERS);
    assert!(matches!(Domain::merge(Some(&dom), &rs), Err(Errno::E2big)));
}

#[test]
fn a_port_rule_gates_exactly_its_port() {
    let rs = Ruleset::new(&RulesetAttr {
        handled_net: ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP, ..Default::default() });
    rs.add_net(443, ACCESS_NET_CONNECT_TCP).unwrap();
    let dom = enforce(None, &rs);
    assert!(dom.check_net(443, ACCESS_NET_CONNECT_TCP).is_ok());
    assert_eq!(dom.check_net(80, ACCESS_NET_CONNECT_TCP), Err(Errno::Eacces));
    // Binding is handled but never granted on that port.
    assert_eq!(dom.check_net(443, ACCESS_NET_BIND_TCP), Err(Errno::Eacces));
    // A right this layer does not handle is not filtered at all.
    let rs2 = Ruleset::new(&RulesetAttr {
        handled_net: ACCESS_NET_CONNECT_TCP, ..Default::default() });
    rs2.add_net(443, ACCESS_NET_CONNECT_TCP).unwrap();
    let d2 = enforce(None, &rs2);
    assert!(d2.check_net(80, ACCESS_NET_BIND_TCP).is_ok());
}

#[test]
fn port_rules_also_stack_and_only_narrow() {
    let rs1 = Ruleset::new(&RulesetAttr { handled_net: ACCESS_NET_BIND_TCP, ..Default::default() });
    rs1.add_net(8080, ACCESS_NET_BIND_TCP).unwrap();
    let d1 = enforce(None, &rs1);
    let rs2 = Ruleset::new(&RulesetAttr { handled_net: ACCESS_NET_BIND_TCP, ..Default::default() });
    rs2.add_net(9090, ACCESS_NET_BIND_TCP).unwrap();
    let d2 = enforce(Some(&d1), &rs2);
    assert_eq!(d2.check_net(8080, ACCESS_NET_BIND_TCP), Err(Errno::Eacces));
    assert_eq!(d2.check_net(9090, ACCESS_NET_BIND_TCP), Err(Errno::Eacces));
}

#[test]
fn a_scope_isolates_everything_outside_the_domain_that_set_it() {
    let rs = Ruleset::new(&RulesetAttr { scoped: SCOPE_SIGNAL, ..Default::default() });
    let dom = enforce(None, &rs);
    assert!(dom.scopes(SCOPE_SIGNAL));
    assert!(!dom.scopes(SCOPE_ABSTRACT_UNIX_SOCKET));
    // An unsandboxed peer is outside.
    assert!(dom.scope_denies(SCOPE_SIGNAL, None));
    // The same domain is inside.
    assert!(!dom.scope_denies(SCOPE_SIGNAL, Some(&dom)));
    // An unrelated domain of equal depth is outside.
    let other = enforce(None, &rs);
    assert!(dom.scope_denies(SCOPE_SIGNAL, Some(&other)));
}

#[test]
fn a_nested_domain_stays_inside_the_scope_that_contains_it() {
    let rs = Ruleset::new(&RulesetAttr { scoped: SCOPE_SIGNAL, ..Default::default() });
    let outer = enforce(None, &rs);
    let inner = enforce(Some(&outer), &rs);
    // A thread that sandboxed itself further is still reachable from the outer
    // domain; the reverse is not true.
    assert!(!outer.scope_denies(SCOPE_SIGNAL, Some(&inner)));
    assert!(inner.scope_denies(SCOPE_SIGNAL, Some(&outer)));
}

#[test]
fn a_domain_with_no_scope_denies_nothing() {
    let rs = ruleset(ACCESS_FS_READ_FILE);
    let dom = enforce(None, &rs);
    assert!(!dom.scope_denies(SCOPE_SIGNAL, None));
    assert!(!dom.scope_denies(SCOPE_ABSTRACT_UNIX_SOCKET, None));
}

#[test]
fn union_of_filtered_rights_always_includes_reparenting() {
    let rs = ruleset(ACCESS_FS_READ_FILE);
    let dom = enforce(None, &rs);
    assert_eq!(dom.union_fs_mask(), ACCESS_FS_READ_FILE | ACCESS_FS_REFER);
    assert_eq!(dom.fs_masks(), vec![ACCESS_FS_READ_FILE | ACCESS_FS_REFER]);
}
