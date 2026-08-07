//! `fsmount(2)`'s namespace form: the mount is created as the root of a NAMED
//! mount namespace the caller gets a descriptor for, instead of an anonymous
//! one destined for the caller's own tree.
//!
//! The distinction is the whole point of the flag. An anonymous namespace is
//! not a namespace anyone can enter — it exists to hold a mount until
//! `move_mount(2)` takes it away, and closing the descriptor dissolves it. A
//! named one is a namespace a task can be placed into, so it must survive being
//! left alone, and its root must be something a path walk can start from.
//!
//! Driven against the real global mount engine through the hosted fixture; the
//! syscall shim itself is `#![cfg(target_os = "oxide-kernel")]` and cannot be.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct TFs { root: InodeRef }
impl FileSystem for TFs {
    fn name(&self) -> &str { "nsfs-test" }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}
struct TDirOps;
impl vfs::InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(tdir(0xB01)) }
}
fn tdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TDirOps), vfs::default_file_ops()).build()
}
fn tfile(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

fn realized_sb(root: InodeRef, dev: u64) -> Arc<vfs::SuperBlock> {
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: root.clone() });
    common::ensure_fs_type(&f);
    common::realize_sb(f, Some(root), dev, String::from("nsfs-test"))
}

#[test]
fn the_namespace_form_puts_the_mount_in_a_namespace_a_task_could_enter() {
    let _g = guard();
    let sb = realized_sb(tdir(0xA01), 0x9101);
    let (m, ns_held) = vfs::mount::create_ns_mount(sb, 0, 0, None).expect("named namespace mount");

    let ns = vfs::mntns::ns_by_id(m.namespace_id()).expect("the namespace is live");
    assert_eq!(ns.id(), ns_held.id(), "the caller is handed the namespace it must hold");
    assert!(!ns.is_anon(), "a descriptor is handed out for it, so it is not anonymous");
    assert_eq!(vfs::mntns::ns_root_id(ns.id()), Some(m.mnt_id),
        "the new mount is the namespace root");
    assert_eq!(ns.nr_mounts.load(std::sync::atomic::Ordering::Acquire), 1);
    assert_ne!(m.mnt_id, 0, "a real mount with a real id");
}

// The anonymous form's descriptor OWNS its mount: closing it unmoved takes the
// mount with it. The namespace form's does not — a namespace someone may still
// be placed into must not evaporate because the mount happens to be reachable
// through a dissolve path that runs unconditionally.
#[test]
fn dissolve_leaves_a_named_namespace_alone_and_reaps_an_anonymous_one() {
    let _g = guard();
    let (named, _hold) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA02), 0x9102), 0, 0, None)
        .expect("named");
    let anon = vfs::mount::create_anon_mount(realized_sb(tdir(0xA03), 0x9103), 0, 0, None)
        .expect("anon");

    assert!(!vfs::mount::anon_ns_root(&named), "not an anonymous root");
    assert!(vfs::mount::anon_ns_root(&anon), "an anonymous root");

    vfs::mount::dissolve_anon(&named);
    vfs::mount::dissolve_anon(&anon);

    assert_eq!(vfs::mntns::ns_root_id(named.namespace_id()), Some(named.mnt_id),
        "the named namespace still holds its mount");
    assert_ne!(vfs::mntns::ns_root_id(anon.namespace_id()), Some(anon.mnt_id),
        "the anonymous one gave its mount up");
}

// A named namespace is one a task can be placed into, so `/` inside it has to
// be resolvable. A superblock whose root is not a directory produces a
// namespace nothing can chdir into, and the refusal is ENOTDIR — the errno for
// "this is not a thing a path can walk through", not the EINVAL that would say
// the flag word was malformed.
#[test]
fn a_non_directory_root_is_enotdir_for_the_namespace_form() {
    let _g = guard();
    let sb = realized_sb(tfile(0xA04), 0x9104);
    assert_eq!(vfs::mount::create_ns_mount(sb, 0, 0, None).err(), Some(VfsError::Enotdir));
}

// The anonymous form has no such rule: its mount is going to be grafted
// somewhere by `move_mount(2)`, and a non-directory root is legal there (that
// is what a file bind mount is). Sharing one constructor must not have leaked
// the namespace form's requirement onto it.
#[test]
fn the_anonymous_form_still_accepts_a_non_directory_root() {
    let _g = guard();
    let sb = realized_sb(tfile(0xA05), 0x9105);
    let m = vfs::mount::create_anon_mount(sb, 0, 0, None).expect("anon over a file root");
    assert!(vfs::mount::anon_ns_root(&m));
}

// Whatever `MOUNT_ATTR_*` the caller asked for lands on the mount, in both
// forms — the flags are applied by the shared constructor, so a divergence here
// would mean one of the two silently dropped them.
#[test]
fn both_forms_carry_the_requested_mount_flags() {
    let _g = guard();
    let want = vfs::mount::mount_attr_to_mnt(0x1 /* MOUNT_ATTR_RDONLY */);
    let (named, _hold) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA06), 0x9106), want, 0, None)
        .expect("named");
    let anon = vfs::mount::create_anon_mount(realized_sb(tdir(0xA07), 0x9107), want, 0, None)
        .expect("anon");
    assert_ne!(want, 0, "the attribute maps to a real MNT_* bit");
    assert_eq!(named.flags() & want, want);
    assert_eq!(anon.flags() & want, want);
}

// The whole lifetime contract of the namespace form, and the one a naive
// implementation gets wrong in both directions.
//
// The mount arena retains the mount; the namespace's teardown is what empties
// the arena. So the mount must NOT retain its own namespace — that is a cycle
// nothing breaks, and the namespace (and its mount, and its superblock) would
// outlive every reference to it forever. The descriptor holds the namespace
// instead, which is why the constructor hands it back: drop it and both go.
#[test]
fn the_namespace_and_its_mount_die_with_the_last_reference_the_caller_holds() {
    let _g = guard();
    let (m, ns) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA08), 0x9108), 0, 0, None)
        .expect("named");
    let (id, mnt_id) = (ns.id(), m.mnt_id);
    assert!(vfs::mount::mount_by_id(mnt_id).is_some(), "published while held");

    // Only the caller's reference keeps it alive: the mount does not hold it.
    drop(m);
    assert!(vfs::mntns::ns_by_id(id).is_some(), "still held by the caller");
    drop(ns);

    assert!(vfs::mntns::ns_by_id(id).is_none(), "the namespace is gone");
    assert!(vfs::mount::mount_by_id(mnt_id).is_none(),
        "and its teardown reaped the mount — no leak, no cycle");
}
