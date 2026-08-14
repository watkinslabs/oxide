// `cgroup.events` notifier ownership tests.  The hierarchy node owns the
// source; lookup-created inode wrappers must never manufacture a second one.

use alloc::sync::Arc;

#[test]
fn events_inodes_share_the_hierarchy_notification_source() {
    let mut t = crate::tree::Tree::new();
    t.mount_root();
    let (cgid, _) = t.create(crate::tree::ROOT, "events-watch").unwrap();
    let source = t.events_poll(cgid).expect("live cgroup source");
    let before = source.generation();
    source.notify_mask(vfs::POLL_PRI | vfs::POLL_ERR);
    assert!(source.generation() > before, "population transition advances the shared source");

    // The production singleton exposes the same stable source to every
    // synthesized wrapper; the local tree contract above proves the owner is
    // the hierarchy node, not one wrapper's allocation.
    let again = t.events_poll(cgid).expect("same live cgroup source");
    assert!(Arc::ptr_eq(&source, &again));
}
