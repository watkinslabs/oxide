// A cgroup2 mount is rooted at the CALLER's cgroup-namespace root, not the
// hierarchy root. Rendering `/proc/<pid>/cgroup` relative to the namespace is
// not sufficient containment: a task that mounts the hierarchy walks inodes,
// so the mount's own root inode is where the namespace boundary is enforced.

use crate::state;

/// The namespace-root hook and the hierarchy are process-global, and cargo runs
/// tests on parallel threads, so every case here takes this gate for its whole
/// body — the same reason the rest of the tree serialises global-state tests.
static GATE: sync::Spinlock<(), sync::TaskList> = sync::Spinlock::new(());

static NS_ROOT: sync::Spinlock<alloc::string::String, sync::TaskList> =
    sync::Spinlock::new(alloc::string::String::new());

/// Install a namespace-root hook returning `path`, run `f`, restore. Caller
/// holds [`GATE`].
fn with_ns_root(path: &str, f: impl FnOnce()) {
    fn hook() -> Option<alloc::string::String> { Some(NS_ROOT.lock().clone()) }
    *NS_ROOT.lock() = alloc::string::String::from(path);
    state::set_cgroup_ns_root_hook(hook);
    f();
    *NS_ROOT.lock() = alloc::string::String::from("/");
}

#[test]
fn the_initial_namespace_mounts_the_hierarchy_root() {
    let _g = GATE.lock();
    with_ns_root("/", || {
    let _ = state::TREE.lock().mount_root();
    let (_fs, root) = crate::realize_tree();
    assert_eq!(crate::cgid_from_dir_inode(&root), Some(crate::tree::ROOT),
        "no cgroup namespace means the mount root is the hierarchy root");
    });
}

#[test]
fn a_namespaced_mount_is_rooted_at_the_namespace_cgroup() {
    let _g = GATE.lock();
    let _ = state::TREE.lock().mount_root();
    let child = { let mut t = state::TREE.lock(); t.create(crate::tree::ROOT, "ns-scope").expect("create").0 };
    with_ns_root("/ns-scope", || {
        let (_fs, root) = crate::realize_tree();
        assert_eq!(crate::cgid_from_dir_inode(&root), Some(child),
            "a task in a cgroup namespace must mount ITS root, not the hierarchy root");
    });
}

#[test]
fn a_namespace_root_that_no_longer_resolves_falls_back_to_the_hierarchy_root() {
    let _g = GATE.lock();
    let _ = state::TREE.lock().mount_root();
    with_ns_root("/removed-since", || {
        let (_fs, root) = crate::realize_tree();
        assert_eq!(crate::cgid_from_dir_inode(&root), Some(crate::tree::ROOT),
            "a dead namespace root must not fail the mount");
    });
}
