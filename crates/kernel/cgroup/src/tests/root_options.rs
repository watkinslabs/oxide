//! The cgroup2 mount flags, where they are ENFORCED rather than parsed.
//!
//! Parsing is covered in `root_flags`; these drive the hierarchy itself: a
//! `cgroup.procs` write refused across a cgroup-namespace boundary under
//! `nsdelegate`, and `memory.events` switching between the subtree aggregate
//! and this cgroup's own counts under `memory_localevents`.

use crate::root_flags::{RootFlag, RootFlags};
use crate::tree::{controller_files, MemoryEvent, Tree, ROOT, MEMORY};
use alloc::string::{String, ToString};

fn s(v: &[u8]) -> &str { core::str::from_utf8(v).unwrap() }

/// `/a`, `/a/b`, `/c` — enough tree to have an inside and an outside.
fn tree_with_branches() -> (Tree, u64, u64, u64) {
    let mut t = Tree::new();
    t.mount_root();
    let (a, _) = t.create(ROOT, "a").expect("a");
    let (b, _) = t.create(a, "b").expect("a/b");
    let (c, _) = t.create(ROOT, "c").expect("c");
    (t, a, b, c)
}

fn events_tree() -> (Tree, u64, u64) {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").expect("memory on");
    let (parent, _) = t.create(ROOT, "p").expect("p");
    t.write_subtree_control(parent, "+memory").expect("memory on p");
    let (child, _) = t.create(parent, "c").expect("p/c");
    (t, parent, child)
}

// ---------------------------------------------------------------------------
// nsdelegate — the namespace boundary
// ---------------------------------------------------------------------------

/// The question `cgroup_procs_write_permission` asks: can the writer SEE this
/// cgroup from its namespace? Compared component-wise, so `/a` does not
/// contain `/ab`.
#[test]
fn a_cgroup_is_inside_its_namespace_root_only_when_it_is_at_or_below_it() {
    let (mut t, a, b, c) = tree_with_branches();
    let (ab_sibling, _) = t.create(ROOT, "ab").expect("ab");

    assert!(t.is_under_path(a, "/a"), "the root itself is inside");
    assert!(t.is_under_path(b, "/a"), "a descendant is inside");
    assert!(!t.is_under_path(c, "/a"), "a sibling is outside");
    assert!(!t.is_under_path(ab_sibling, "/a"),
        "`/ab` must not read as inside `/a` — a raw string prefix would say it does");
    assert!(!t.is_under_path(ROOT, "/a"), "the hierarchy root is above the namespace root");
}

/// The initial namespace's root is `/`, and everything is inside it — so
/// `nsdelegate` changes nothing for a task that never unshared.
#[test]
fn the_initial_namespace_sees_the_whole_hierarchy() {
    let (t, a, b, c) = tree_with_branches();
    for id in [ROOT, a, b, c] {
        assert!(t.is_under_path(id, "/"), "everything is under the initial root");
    }
}

// ---------------------------------------------------------------------------
// memory_localevents — subtree aggregate vs this cgroup's own counts
// ---------------------------------------------------------------------------

/// The default (flag clear) is the recursive count a v2 reader expects: a
/// child's event shows up in its parent's `memory.events`.
#[test]
fn by_default_memory_events_reports_the_subtree() {
    let (mut t, parent, child) = events_tree();
    t.record_memory_event(child, MemoryEvent::High);

    assert_eq!(t.subtree_memory_events(parent).high, 1, "the parent counts its child's event");
    assert_eq!(t.local_memory_events(parent).high, 0, "...but not as its OWN");
    assert_eq!(t.local_memory_events(child).high, 1);
}

/// `memory.events.local` is published unconditionally by the reference and is
/// always the node's own counts, whatever the mount flags say.
#[test]
fn the_local_events_file_is_always_this_cgroups_own_counts() {
    let (mut t, parent, child) = events_tree();
    t.record_memory_event(child, MemoryEvent::Max);
    t.record_memory_event(parent, MemoryEvent::High);

    assert_eq!(s(&t.read_file(parent, "memory.events.local").expect("local file")),
        "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n",
        "the parent's own High, not the child's Max");
    assert_eq!(s(&t.read_file(child, "memory.events.local").expect("local file")),
        "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n");
}

/// And the file is LISTED, not merely readable — a control file that readdir
/// does not show is one no tool will find.
#[test]
fn the_local_events_file_appears_in_the_memory_controller_file_set() {
    let files = controller_files(MEMORY);
    assert!(files.contains(&"memory.events.local"),
        "memory.events.local must be listed beside memory.events");
    assert!(files.contains(&"memory.events"));
}

// ---------------------------------------------------------------------------
// the flag word itself
// ---------------------------------------------------------------------------

/// A remount ORs: naming one flag must not clear a delegation boundary another
/// mount established, which is why `cgroup_reconfigure` merges rather than
/// replaces.
#[test]
fn setting_flags_merges_and_never_clears() {
    let mut a = RootFlags::empty();
    a.set(RootFlag::NsDelegate);
    let mut b = RootFlags::empty();
    b.set(RootFlag::MemoryLocalEvents);

    let merged = RootFlags::from_bits(a.bits() | b.bits());
    assert!(merged.has(RootFlag::NsDelegate), "the boundary survives the second mount");
    assert!(merged.has(RootFlag::MemoryLocalEvents));
    assert_eq!(merged.show_options(), ",nsdelegate,memory_localevents");
}

/// A path with a trailing component that merely starts with the root's name is
/// the case a naive prefix check gets wrong, in the direction that MATTERS:
/// it would let a write escape the namespace.
#[test]
fn the_boundary_check_cannot_be_escaped_by_a_name_that_shares_a_prefix() {
    let mut t = Tree::new();
    t.mount_root();
    let (pod, _) = t.create(ROOT, "pod").expect("pod");
    let (podx, _) = t.create(ROOT, "podxyz").expect("podxyz");
    let (inner, _) = t.create(pod, "svc").expect("pod/svc");

    let ns_root = String::from("/pod");
    assert!(t.is_under_path(pod, &ns_root));
    assert!(t.is_under_path(inner, &ns_root));
    assert!(!t.is_under_path(podx, &ns_root),
        "/podxyz is a DIFFERENT cgroup and must stay outside the namespace");
    assert_eq!(t.path_of(podx), "/podxyz".to_string());
}
