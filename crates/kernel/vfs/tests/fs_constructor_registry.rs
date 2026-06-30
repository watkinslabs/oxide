//! D40: the constructor-bearing `file_system_type` registry that wires
//! `mount(2)`'s `-t <type>` dispatch (`fsmount_common::mount_fstype`) to a
//! name lookup instead of a hard-coded `match fstype`. Proves a type
//! registered via `register_fs` resolves through both `get_fs` (the production
//! dispatch lookup, yielding the mount constructor) and `get_fs_type` (the
//! shared `file_system_type` view), that its constructor produces the backend
//! object, and that an unknown name resolves to `None`.
//!
//! SERIAL: registers/unregisters one unique type name on a global list.

use std::sync::Arc;

use vfs::fs::{get_fs, get_fs_type, register_fs, unregister_fs, FileSystem, FsFlags, FsType, MountSpec};
use vfs::{InodeBuilder, InodeRef, FileType, default_file_ops, default_inode_ops, mk_mode};

const T_MAGIC: u64 = 0x7430_3431; // arbitrary, unique to this test

/// Minimal backend the test constructor hands the mount engine.
struct T040Fs;
impl FileSystem for T040Fs {
    fn name(&self) -> &str { "t040ctor" }
    fn magic(&self) -> u64 { T_MAGIC }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(1, mk_mode(FileType::Directory, 0),
            default_inode_ops(), default_file_ops()).build())
    }
}

#[test]
fn register_get_construct_and_unknown_is_none() {
    // Unknown before registration: both lookups miss.
    assert!(get_fs("t040ctor").is_none(), "unregistered: get_fs None");
    assert!(get_fs_type("t040ctor").is_none(), "unregistered: get_fs_type None");

    register_fs(FsType::new("t040ctor", T_MAGIC, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> vfs::fs::KResult<MountSpec> {
            let fs: Arc<dyn FileSystem> = Arc::new(T040Fs);
            Ok(MountSpec { fs, bind_root: None, strict: true })
        }))).expect("register t040ctor");

    // get_fs_type returns the registered type (the D40 test contract).
    let ty = get_fs_type("t040ctor").expect("get_fs_type resolves a registered type");
    assert_eq!(ty.name(), "t040ctor");
    // `name.subtype` resolves on the base name (Linux __get_fs_type split).
    assert!(get_fs_type("t040ctor.foo").is_some(), "subtype resolves on base name");

    // get_fs yields the constructor; running it builds the backend object.
    let cons = get_fs("t040ctor").expect("get_fs resolves the constructor entry");
    assert_eq!(cons.magic(), T_MAGIC);
    let spec = cons.construct("none", "/mnt", "").expect("constructor builds a MountSpec");
    assert_eq!(spec.fs.name(), "t040ctor");
    assert_eq!(spec.fs.magic(), T_MAGIC);
    assert!(spec.bind_root.is_none() && spec.strict);

    // Duplicate name → EBUSY.
    assert!(register_fs(FsType::new("t040ctor", T_MAGIC, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> vfs::fs::KResult<MountSpec> {
            Err(vfs::VfsError::Einval)
        }))).is_err(), "duplicate name rejected");

    // Unknown name still None.
    assert!(get_fs("t040nope").is_none(), "unknown type → None");
    assert!(get_fs_type("t040nope").is_none(), "unknown type → None");

    unregister_fs("t040ctor").expect("cleanup");
    assert!(get_fs("t040ctor").is_none(), "gone after unregister");
    assert!(get_fs_type("t040ctor").is_none(), "gone from get_fs_type too");
}
