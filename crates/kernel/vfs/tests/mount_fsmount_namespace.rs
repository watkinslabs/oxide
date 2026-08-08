//! The namespace form of `fsmount(2)` and `open_tree(2)`: the mount goes into a
//! NAMED mount namespace the caller gets a descriptor for, instead of an
//! anonymous one destined for the caller's own tree.
//!
//! Two things are being pinned here, and both are shape rather than errno.
//!
//! First, WHAT the namespace contains. Its root is not the caller's new tree —
//! it is a COPY of the caller's own namespace root, with the new tree mounted on
//! top of that copy. Both arrangements resolve `/` to the new filesystem, so the
//! difference only shows when the top comes off: with the copy underneath there
//! is still a root, and without it the namespace has nothing left at all.
//!
//! Second, WHICH propagation the copies carry. A caller whose current user
//! namespace is not the one owning its mount namespace is unprivileged with
//! respect to the mounter of everything it is copying, so the copies are slaves
//! and the tree is frozen.
//!
//! Driven against the real global mount engine through the hosted fixture; the
//! syscall shims are `#![cfg(target_os = "oxide-kernel")]` and cannot be.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{Mount, NsMountSource, Propagation, MNT_LOCKED, MNT_LOCK_ATIME};
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

/// A fresh caller mount namespace with a root filesystem in it — the state every
/// real `fsmount(2)` caller is in, and the thing the constructor copies. Owned by
/// the initial user namespace unless `child_user_ns`, which is the
/// `unshare(CLONE_NEWUSER|CLONE_NEWNS)` shape.
fn caller_ns_with_root(dev: u64, child_user_ns: bool) -> vfs::mntns::MntNamespaceRef {
    let owner: NamespaceRef = if child_user_ns {
        let init: NamespaceRef = namespace_identity::initial(NamespaceKind::User);
        namespace_identity::allocate(NamespaceKind::User, init.clone(), Some(init))
            .expect("child user namespace")
    } else {
        namespace_identity::initial(NamespaceKind::User)
    };
    let ns = vfs::mntns::allocate(owner).expect("caller mount namespace");
    common::set_current_namespace(ns.clone());
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: tdir(dev) });
    common::register("/", f).expect("root filesystem in the caller's namespace");
    ns
}

/// The namespace's root mount object.
fn ns_root(ns: u64) -> Arc<Mount> {
    let id = vfs::mntns::ns_root_id(ns).expect("the namespace has a root");
    vfs::mount::mount_by_id(id).expect("and it is a live mount")
}

fn nr_mounts(ns: &vfs::mntns::MntNamespaceRef) -> u64 { ns.nr_mounts.load(Ordering::Acquire) }

// ---------------------------------------------------------------------------
// 1. The shape: root copy underneath, new mount on top.
// ---------------------------------------------------------------------------

// The defect this pins: the new mount used to BE the namespace root. `/` resolved
// to the new filesystem either way, so nothing about a fresh namespace looked
// wrong — until someone took the top off and found a namespace with no root.
#[test]
fn the_namespace_is_rooted_on_a_copy_of_the_callers_root_with_the_mount_on_top() {
    let _g = guard();
    let caller = caller_ns_with_root(0xA00, false);
    let caller_root = ns_root(caller.id());

    let sb = realized_sb(tdir(0xA01), 0x9101);
    let (m, held) = vfs::mount::create_ns_mount(sb, 0, 0, None).expect("named namespace mount");

    let root = ns_root(held.id());
    assert_ne!(root.mnt_id, m.mnt_id, "the new mount is NOT the namespace root");
    assert!(root.is_root(), "the copy is: self-parent, no mountpoint");
    assert!(root.mountpoint().is_none());
    assert!(Arc::ptr_eq(&root.sb, &caller_root.sb),
        "and it is a copy of the CALLER's root — same superblock, new mount");
    assert_ne!(root.mnt_id, caller_root.mnt_id, "a copy, not the original");

    assert_eq!(m.parent_id.load(Ordering::Acquire), root.mnt_id,
        "the new tree is mounted ON the copy");
    assert_eq!(m.namespace_id(), held.id());
    assert_eq!(nr_mounts(&held), 2, "two mounts, both accounted for");
    assert!(!held.is_anon(), "a descriptor is handed out for it");
}

// The whole reason the copy is there. Take the top off and `/` still resolves —
// to what the caller's own root resolved to.
#[test]
fn unmounting_the_top_leaves_the_root_copy_underneath() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA10, false);
    let sb = realized_sb(tdir(0xA11), 0x9111);
    let (m, held) = vfs::mount::create_ns_mount(sb, 0, 0, None).expect("named namespace mount");
    let root = ns_root(held.id());
    let root_id = root.mnt_id;

    // Unmount from INSIDE the namespace, which is where a task holding the
    // descriptor would be when it does this.
    common::set_current_namespace(held.clone());
    let removed = vfs::mount::unregister_top(&root.mnt_root().expect("root dentry"), false);
    assert_eq!(removed, 1, "the top came off");

    assert!(vfs::mount::mount_by_id(m.mnt_id).is_none(), "the top is gone");
    assert_eq!(vfs::mntns::ns_root_id(held.id()), Some(root_id),
        "and the namespace still has a root to fall back to");
    assert!(vfs::mount::mount_by_id(root_id).is_some());
}

// A named namespace is one a task can be placed into, so `/` inside it has to be
// resolvable. A superblock whose root is not a directory produces a namespace
// nothing can chdir into, and the refusal is ENOTDIR — the errno for "this is
// not a thing a path can walk through", not the EINVAL that would say the flag
// word was malformed.
#[test]
fn a_non_directory_root_is_enotdir_for_the_namespace_form() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA20, false);
    let sb = realized_sb(tfile(0xA21), 0x9121);
    assert_eq!(vfs::mount::create_ns_mount(sb, 0, 0, None).err(), Some(VfsError::Enotdir));
}

// The anonymous form has no such rule: its mount is going to be grafted
// somewhere by `move_mount(2)`, and a non-directory root is legal there (that is
// what a file bind mount is). It also has no root copy and no namespace to hand
// back — it is a different construction, and sharing the entry point must not
// have leaked either requirement onto it.
#[test]
fn the_anonymous_form_is_still_its_own_root_over_a_non_directory() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA30, false);
    let sb = realized_sb(tfile(0xA31), 0x9131);
    let m = vfs::mount::create_anon_mount(sb, 0, 0, None).expect("anon over a file root");
    assert!(vfs::mount::anon_ns_root(&m), "the anonymous form's mount IS its namespace root");
    assert_eq!(vfs::mntns::ns_root_id(m.namespace_id()), Some(m.mnt_id));
}

// Whatever `MOUNT_ATTR_*` the caller asked for lands on the mount the caller
// asked for — the one on TOP, not the root copy underneath it, which carries the
// caller's own root's flags because that is what it is a copy of.
#[test]
fn the_requested_mount_flags_land_on_the_new_mount() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA40, false);
    let want = vfs::mount::mount_attr_to_mnt(vfs::mount::MOUNT_ATTR_RDONLY);
    assert_ne!(want, 0, "the attribute maps to a real MNT_* bit");
    let (named, held) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA41), 0x9141), want, 0, None)
        .expect("named");
    let anon = vfs::mount::create_anon_mount(realized_sb(tdir(0xA42), 0x9142), want, 0, None)
        .expect("anon");
    assert_eq!(named.flags() & want, want);
    assert_eq!(anon.flags() & want, want);
    assert_eq!(ns_root(held.id()).flags() & vfs::mount::MNT_RDONLY, 0,
        "the root copy is not the mount the caller configured — it kept the caller's own");
}

// ---------------------------------------------------------------------------
// 2. Propagation and freezing, chosen by the caller's user namespace.
// ---------------------------------------------------------------------------

// The transition the locked-attribute stamp alone does not make. A caller
// unprivileged with respect to the mounter gets SLAVES: propagation flows from
// the originals into the new namespace and nothing flows back out of it.
#[test]
fn a_cross_user_namespace_caller_gets_slave_copies_and_a_frozen_tree() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA50, true);
    let (m, held) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA51), 0x9151), 0, 0, None)
        .expect("named");
    let root = ns_root(held.id());

    assert_eq!(Propagation::from_u8(root.propagation.load(Ordering::Acquire)), Propagation::Slave,
        "the root copy receives from the caller's root and sends nothing back");
    assert_eq!(Propagation::from_u8(m.propagation.load(Ordering::Acquire)), Propagation::Slave,
        "and so does the mount on top of it");

    assert_ne!(m.internal_flags() & MNT_LOCKED, 0,
        "the top cannot be unmounted to reveal the copy it covers");
    assert_eq!(root.internal_flags() & MNT_LOCKED, 0,
        "the namespace's own root is the one node that may still come off");
    assert_ne!(m.internal_flags() & MNT_LOCK_ATIME, 0, "atime is frozen on every node");
    assert_ne!(root.internal_flags() & MNT_LOCK_ATIME, 0);
}

// Same user namespace: the caller is privileged over what it is copying, so
// nothing is frozen and the copies stand alone. Freezing here would make an
// ordinary privileged `fsmount(FSMOUNT_NAMESPACE)` produce a namespace its own
// creator cannot take apart.
#[test]
fn a_same_user_namespace_caller_gets_private_copies_and_no_freeze() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA60, false);
    let (m, held) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA61), 0x9161), 0, 0, None)
        .expect("named");
    let root = ns_root(held.id());

    assert_eq!(Propagation::from_u8(m.propagation.load(Ordering::Acquire)), Propagation::Private);
    assert_eq!(Propagation::from_u8(root.propagation.load(Ordering::Acquire)), Propagation::Private);
    assert_eq!(m.internal_flags() & (MNT_LOCKED | MNT_LOCK_ATIME), 0);
    assert_eq!(root.internal_flags() & (MNT_LOCKED | MNT_LOCK_ATIME), 0);
}

// ---------------------------------------------------------------------------
// 3. `open_tree(OPEN_TREE_NAMESPACE)` — the same constructor, a different top.
// ---------------------------------------------------------------------------

/// Mount a filesystem at `p` in the current namespace and return it.
fn mount_at(p: &str, dev: u64) -> Arc<Mount> {
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: tdir(dev) });
    common::register(p, f).expect("submount");
    common::mount_at_path_exact(p).expect("mount exists")
}

// The sibling flag. Its tree is a COPY of an existing mount rather than a fresh
// one over a superblock, and everything else about the namespace is identical —
// which is the point of there being one constructor.
#[test]
fn the_open_tree_form_puts_a_copy_of_an_existing_tree_on_the_same_root_copy() {
    let _g = guard();
    let caller = caller_ns_with_root(0xA70, false);
    let src = mount_at("/sub", 0xA71);
    let base = src.mnt_root().expect("the source has a root");

    let (top, held) = vfs::mount::create_new_namespace(NsMountSource::Tree {
        src: Arc::clone(&src), base, recursive: false,
    }).expect("open_tree namespace form");

    let root = ns_root(held.id());
    assert_ne!(top.mnt_id, root.mnt_id, "the copy is not the namespace root");
    assert_eq!(top.parent_id.load(Ordering::Acquire), root.mnt_id, "it is mounted ON the root copy");
    assert!(Arc::ptr_eq(&top.sb, &src.sb), "a copy shares the source superblock");
    assert_ne!(top.mnt_id, src.mnt_id, "and is a distinct mount");
    assert_eq!(top.namespace_id(), held.id());
    assert_eq!(nr_mounts(&held), 2);
    // The source is untouched: it is still the caller's, still where it was.
    assert_eq!(src.namespace_id(), caller.id());
}

// `may_clone_mount_tree` is the shared admission ladder — the namespace form
// copies exactly what the detached form may copy, so an unbindable source is
// refused here for the same reason and with the same errno.
#[test]
fn an_unbindable_source_is_refused_by_the_open_tree_form() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA80, false);
    let src = mount_at("/sub", 0xA81);
    src.propagation.store(Propagation::Unbindable as u8, Ordering::Release);
    let base = src.mnt_root().expect("root");

    assert_eq!(vfs::mount::create_new_namespace(NsMountSource::Tree {
        src, base, recursive: false,
    }).err(), Some(VfsError::Einval));
}

// ---------------------------------------------------------------------------
// 4. Lifetime.
// ---------------------------------------------------------------------------

// The anonymous form's descriptor OWNS its mount: closing it unmoved takes the
// mount with it. The namespace form's does not — a namespace someone may still
// be placed into must not evaporate because the mount happens to be reachable
// through a dissolve path that runs unconditionally.
#[test]
fn dissolve_leaves_a_named_namespace_alone_and_reaps_an_anonymous_one() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xA90, false);
    let (named, _hold) = vfs::mount::create_ns_mount(realized_sb(tdir(0xA91), 0x9191), 0, 0, None)
        .expect("named");
    let anon = vfs::mount::create_anon_mount(realized_sb(tdir(0xA92), 0x9192), 0, 0, None)
        .expect("anon");

    assert!(!vfs::mount::anon_ns_root(&named), "not an anonymous root — it is not a root at all");
    assert!(vfs::mount::anon_ns_root(&anon), "an anonymous root");

    vfs::mount::dissolve_anon(&named);
    vfs::mount::dissolve_anon(&anon);

    assert!(vfs::mount::mount_by_id(named.mnt_id).is_some(),
        "the named namespace still holds its mount");
    assert_ne!(vfs::mntns::ns_root_id(anon.namespace_id()), Some(anon.mnt_id),
        "the anonymous one gave its mount up");
}

// The whole lifetime contract of the namespace form, and the one a naive
// implementation gets wrong in both directions.
//
// The mount arena retains the mounts; the namespace's teardown is what empties
// the arena. So no mount may retain its own namespace — that is a cycle nothing
// breaks, and the namespace (and its mounts, and their superblocks) would
// outlive every reference to it forever. The descriptor holds the namespace
// instead, which is why the constructor hands it back: drop it and the whole
// tree goes, root copy included.
#[test]
fn the_namespace_and_every_mount_in_it_die_with_the_caller_s_last_reference() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xAA0, false);
    let (m, ns) = vfs::mount::create_ns_mount(realized_sb(tdir(0xAA1), 0x91A1), 0, 0, None)
        .expect("named");
    let (id, top_id, root_id) = (ns.id(), m.mnt_id, ns_root(ns.id()).mnt_id);
    assert!(vfs::mount::mount_by_id(top_id).is_some(), "published while held");

    // Only the caller's reference keeps it alive: no mount holds it.
    drop(m);
    assert!(vfs::mntns::ns_by_id(id).is_some(), "still held by the caller");
    drop(ns);

    assert!(vfs::mntns::ns_by_id(id).is_none(), "the namespace is gone");
    assert!(vfs::mount::mount_by_id(top_id).is_none(), "and its teardown reaped the mount");
    assert!(vfs::mount::mount_by_id(root_id).is_none(), "root copy included — no leak, no cycle");
}
