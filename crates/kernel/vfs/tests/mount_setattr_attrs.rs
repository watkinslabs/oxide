//! [D51/D52] Per-mount MOUNT_ATTR_* application: `attach_sb_with_flags` stamps
//! the mapped MNT_* option bits on a realized graft (the `fsmount`+`move_mount`
//! D51 path), and `mnt_setattr_by_id`/`mnt_setattr_tree_by_id` apply a
//! `mount_setattr(2)` change to the crossed-into mount (D52). RDONLY has runtime
//! teeth (write → EROFS) and the writer guard; NOSUID/NODEV are runtime-inert
//! but reported through `flags()` (the same bits `statfs` ST_* reads by name).
//! Driven over the real global mount table, no QEMU. Serializes on `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{
    attach_sb_with_flags, mnt_setattr_by_id, mnt_setattr_tree_by_id, mount_attr_to_mnt,
    MNT_NODEV, MNT_NOSUID, MNT_RDONLY, MOUNT_ATTR_NOATIME, MOUNT_ATTR_RDONLY, MOUNT_ATTR__ATIME,
};
use vfs::superblock::{next_anon_dev, SuperBlock};
use vfs::{
    Cred, Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
    default_inode_ops, mk_mode,
};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

/// Writable regular `i_fop` — the only thing that can produce EROFS is the
/// mount-RO gate under test.
struct RwOps;
impl FileOps for RwOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}
fn rw_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(RwOps)).build()
}

/// A backend whose root is a writable regular inode.
struct RwFs { root_ino: u64 }
impl FileSystem for RwFs {
    fn name(&self) -> &str { "rwfs_attr" }
    fn root(&self) -> Option<InodeRef> { Some(rw_file(self.root_ino)) }
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(RwFs { root_ino: ino }) }

/// Build a realized SuperBlock over a writable backend (the `vfs_get_tree`
/// outcome `attach_sb*` grafts).
fn realized_sb(ino: u64) -> Arc<SuperBlock> {
    let f = fs(ino);
    let root = f.root();
    SuperBlock::for_backend(f, root, next_anon_dev(), String::from("rwfs_attr"))
}

/// A write-open `File` threaded with `mnt_id`, as the open syscall does.
fn wfile(mnt_id: u64) -> Arc<File> {
    let ino = rw_file(0xF11E);
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new_at(ino, d, OpenFlags::O_WRONLY, mnt_id, Cred::root())
}

// D51: a fsmount(2) MOUNT_ATTR_RDONLY request, mapped by `mount_attr_to_mnt` and
// grafted via `attach_sb_with_flags`, lands a read-only mount — a write through
// it is EROFS (the prior realized graft dropped the attr and stayed writable).
#[test]
fn attach_sb_with_flags_rdonly_is_erofs() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");

    let mnt_flags = mount_attr_to_mnt(MOUNT_ATTR_RDONLY);
    assert_eq!(mnt_flags & MNT_RDONLY, MNT_RDONLY, "MOUNT_ATTR_RDONLY → MNT_RDONLY");
    attach_sb_with_flags(Some(common::dentry("/ro")), realized_sb(0xAA), mnt_flags).expect("graft");

    let m = common::mount_at_path_exact("/ro").expect("mount present");
    assert!(m.is_readonly(), "graft stamped MNT_RDONLY before going live");
    let f = wfile(m.mnt_id);
    assert_eq!(f.write(b"data"), Err(VfsError::Erofs), "RDONLY mount → EROFS on write");
}

// D52: `mnt_setattr_by_id(set = NOSUID|NODEV)` flips exactly those option bits,
// readable via the typed gates and via `flags()` (the bits statfs ST_* reads by
// name) — RDONLY stays clear, so a write still succeeds (inert bits only).
#[test]
fn setattr_by_id_sets_nosuid_nodev_readback() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/m", fs(0xB0)).expect("m");
    let m = common::mount_at_path_exact("/m").expect("mount present");

    mnt_setattr_by_id(m.mnt_id, MNT_NOSUID | MNT_NODEV, 0).expect("setattr");
    let m = common::mount_at_path_exact("/m").expect("mount present");
    assert!(m.is_nosuid() && m.is_nodev(), "NOSUID|NODEV readback");
    assert_eq!(m.flags() & (MNT_NOSUID | MNT_NODEV), MNT_NOSUID | MNT_NODEV,
        "flags() carries the bits statfs ST_NOSUID/ST_NODEV read");
    assert!(!m.is_readonly(), "RDONLY untouched");
    // Inert bits: the mount is still writable.
    let f = wfile(m.mnt_id);
    assert!(f.write(b"data").is_ok(), "NOSUID/NODEV do not gate writes");
}

// D52: a `mount_setattr(2)` ro→rw clear honours `attr_clr` — setting then
// clearing MNT_RDONLY releases the mount so writes succeed again.
#[test]
fn setattr_attr_clr_clears_rdonly() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/c", fs(0xC0)).expect("c");
    let m = common::mount_at_path_exact("/c").expect("mount present");

    mnt_setattr_by_id(m.mnt_id, MNT_RDONLY, 0).expect("set ro");
    assert!(common::mount_at_path_exact("/c").unwrap().is_readonly(), "now RO");
    // attr_clr = RDONLY → ro→rw.
    mnt_setattr_by_id(m.mnt_id, 0, MNT_RDONLY).expect("clear ro");
    let m = common::mount_at_path_exact("/c").expect("mount present");
    assert!(!m.is_readonly(), "attr_clr released MNT_RDONLY");
    let f = wfile(m.mnt_id);
    assert!(f.write(b"data").is_ok(), "writable again after ro→rw clear");
}

// D52: turning RDONLY on while a writer is active is EBUSY (Linux
// `mnt_hold_writers`) — the same guard `apply_remount` enforces.
#[test]
fn setattr_rdonly_with_active_writer_is_ebusy() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/w", fs(0xD0)).expect("w");
    let m = common::mount_at_path_exact("/w").expect("mount present");

    vfs::mount::mnt_want_write(&m).expect("begin write");
    assert_eq!(mnt_setattr_by_id(m.mnt_id, MNT_RDONLY, 0), Err(VfsError::Ebusy),
        "RDONLY with active writer → EBUSY");
    assert!(!common::mount_at_path_exact("/w").unwrap().is_readonly(), "stayed RW on EBUSY");
    // Drop the writer; the RO flip then succeeds.
    vfs::mount::mnt_drop_write(&m);
    mnt_setattr_by_id(m.mnt_id, MNT_RDONLY, 0).expect("RO flip once writers drained");
    assert!(common::mount_at_path_exact("/w").unwrap().is_readonly());
}

// D52: `AT_RECURSIVE` (mnt_setattr_tree_by_id) applies the change across the
// whole subtree — a 3-mount chain all gain MNT_NOSUID from one call on the top.
#[test]
fn setattr_tree_sets_three_mount_subtree() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/t", fs(0xE0)).expect("t");
    common::register("/t/x", fs(0xE1)).expect("t/x");
    common::register("/t/x/y", fs(0xE2)).expect("t/x/y");
    let top = common::mount_at_path_exact("/t").expect("top");

    mnt_setattr_tree_by_id(top.mnt_id, MNT_NOSUID, 0).expect("recursive setattr");
    for p in ["/t", "/t/x", "/t/x/y"] {
        assert!(common::mount_at_path_exact(p).unwrap().is_nosuid(),
            "MNT_NOSUID applied recursively at {p}");
    }
}

// D52: the atime mapper resolves the MOUNT_ATTR__ATIME sub-field — NOATIME maps
// to MNT_NOATIME, the zero (relatime) value to MNT_RELATIME.
#[test]
fn mount_attr_to_mnt_atime_subfield() {
    let na = mount_attr_to_mnt(MOUNT_ATTR_NOATIME);
    assert_ne!(na & vfs::mount::MNT_ATIME_MASK & !vfs::mount::MNT_RELATIME, 0);
    assert!(na & vfs::mount::MNT_NOATIME != 0, "MOUNT_ATTR_NOATIME → MNT_NOATIME");
    // RELATIME is the zero sub-field value (the default).
    let re = mount_attr_to_mnt(0) & MOUNT_ATTR__ATIME;
    let _ = re; // sub-field math exercised; relatime resolves via the policy resolver
    assert!(mount_attr_to_mnt(0) & vfs::mount::MNT_RELATIME != 0, "0 atime → MNT_RELATIME");
}
