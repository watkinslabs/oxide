//! D40 (vfs-model/no-d_automount-no-fs-mount-callback) — the missing
//! piece was a name-keyed `register_filesystem`/`get_fs_type` registry
//! (Linux `fs/filesystems.c`). These prove `mount(2)`'s "resolve `-t
//! <type>` to a FileSystemType" can now be a registry lookup, not a
//! hard-coded `match fstype { … }`.
//!
//! SERIAL: the registry is a single global list — these tests register +
//! unregister disjoint names and run under one `#[test]` so there is no
//! cross-test interleave on the shared state.

use std::sync::Arc;

use vfs::fs::{get_fs_type, register_filesystem, registered_filesystems, unregister_filesystem};
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{KResult, VfsError};

struct FakeType { nm: &'static str }
impl FileSystemType for FakeType {
    fn name(&self) -> &str { self.nm }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

#[test]
fn registry_register_lookup_subtype_dup_unregister() {
    // Unique names so this test does not collide with any other registrant.
    let a: Arc<dyn FileSystemType> = Arc::new(FakeType { nm: "t250fooo" });
    let b: Arc<dyn FileSystemType> = Arc::new(FakeType { nm: "t250barr" });

    // Absent before registration.
    assert!(get_fs_type("t250fooo").is_none(), "unregistered type not resolvable");

    register_filesystem(a.clone()).expect("register a");
    register_filesystem(b.clone()).expect("register b");

    // get_fs_type resolves by name to the SAME Arc.
    let got = get_fs_type("t250fooo").expect("type a resolves");
    assert!(Arc::ptr_eq(&got, &a), "get_fs_type returns the registered instance");
    assert_eq!(get_fs_type("t250barr").map(|t| t.name() == "t250barr"), Some(true));

    // `name.subtype` resolves on the base name (Linux __get_fs_type split).
    let sub = get_fs_type("t250fooo.sshfs").expect("subtype resolves on base");
    assert!(Arc::ptr_eq(&sub, &a), "fuse-style name.subtype keys on base name");

    // Duplicate name is rejected with EBUSY (Linux -EBUSY).
    let dup: Arc<dyn FileSystemType> = Arc::new(FakeType { nm: "t250fooo" });
    assert_eq!(register_filesystem(dup), Err(VfsError::Ebusy), "dup name → EBUSY");

    // Registration order is preserved: a appears before b in the snapshot.
    let snap = registered_filesystems();
    let ia = snap.iter().position(|t| t.name() == "t250fooo").unwrap();
    let ib = snap.iter().position(|t| t.name() == "t250barr").unwrap();
    assert!(ia < ib, "registry preserves registration order (Linux list order)");

    // Unregister removes by name; missing name → EINVAL.
    unregister_filesystem("t250fooo").expect("unregister a");
    assert!(get_fs_type("t250fooo").is_none(), "gone after unregister");
    assert_eq!(unregister_filesystem("t250fooo"), Err(VfsError::Einval), "double-unregister → EINVAL");

    // Clean up the other entry so the global stays as we found it.
    unregister_filesystem("t250barr").expect("unregister b");
}
