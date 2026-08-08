//! Every mount namespace a task can be in HAS a root mount, from the moment it
//! exists until it dies. `create_new_namespace` depends on that totally — its
//! first act is to COPY the caller's namespace root — so the property is a
//! precondition of the namespace form of `fsmount(2)` and `open_tree(2)`, not a
//! detail of one of them.
//!
//! The reference states the invariant rather than testing it: the root is a
//! field set when the namespace is created, and the code that reads it does so
//! unconditionally with a warn-once that it is the expected synthetic mount.
//! Three separate mechanisms hold it up, and NONE of them had a check here:
//!
//!   * a namespace copied from another carries the copy of that one's root;
//!   * a namespace the constructor builds is given the root copy it just made,
//!     so its output satisfies its own input precondition and the form composes;
//!   * the root mount is self-parented, and `do_umount` refuses a mount with no
//!     parent — so once set, a namespace's root cannot be taken away.
//!
//! Break any one and `create_new_namespace` starts refusing calls the reference
//! accepts, with an errno the reference never returns. These pin all three.
//!
//! Driven against the real global mount engine through the hosted fixture; the
//! syscall shims are `#![cfg(target_os = "oxide-kernel")]` and cannot be.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use namespace_identity::NamespaceKind;
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{Mount, NsMountSource, Umount, UmountRefusal};
use vfs::{FileType, InodeRef, KResult};

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
    fn name(&self) -> &str { "nsroot-test" }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}
struct TDirOps;
impl vfs::InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(tdir(0xC01)) }
}
fn tdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TDirOps), vfs::default_file_ops()).build()
}

fn realized_sb(dev: u64, ino: u64) -> Arc<vfs::SuperBlock> {
    let root = tdir(ino);
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: root.clone() });
    common::ensure_fs_type(&f);
    common::realize_sb(f, Some(root), dev, String::from("nsroot-test"))
}

/// A fresh caller mount namespace with a root filesystem in it, made current.
fn caller_ns_with_root(dev: u64) -> vfs::mntns::MntNamespaceRef {
    let owner = namespace_identity::initial(NamespaceKind::User);
    let ns = vfs::mntns::allocate(owner).expect("caller mount namespace");
    common::set_current_namespace(ns.clone());
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: tdir(dev) });
    common::register("/", f).expect("root filesystem in the caller's namespace");
    ns
}

/// An EMPTY mount namespace, owned like the caller's but with nothing in it.
fn empty_ns() -> vfs::mntns::MntNamespaceRef {
    vfs::mntns::allocate(namespace_identity::initial(NamespaceKind::User))
        .expect("empty mount namespace")
}

fn ns_root(ns: u64) -> Arc<Mount> {
    let id = vfs::mntns::ns_root_id(ns).expect("the namespace has a root");
    vfs::mount::mount_by_id(id).expect("and it is a live mount")
}

/// Mount a filesystem at `p` in the current namespace and return it.
fn mount_at(p: &str, dev: u64) -> Arc<Mount> {
    let f: Arc<dyn FileSystem> = Arc::new(TFs { root: tdir(dev) });
    common::register(p, f).expect("submount");
    common::mount_at_path_exact(p).expect("mount exists")
}

// ---------------------------------------------------------------------------
// 1. A copied namespace carries a root.
// ---------------------------------------------------------------------------

// `unshare(CLONE_NEWNS)` is the ordinary way a task ends up in a namespace it
// did not start in, and the ONLY thing that gives that namespace a root is
// `copy_mnt_ns` recognising which of the mounts it copied was the source's.
// Infer the root from parent fields instead and a bind of `/` onto itself — two
// self-parented candidates — picks whichever the iteration order reaches first.
#[test]
fn a_copied_namespace_gets_the_copy_of_the_root_it_was_copied_from() {
    let _g = guard();
    let src = caller_ns_with_root(0xB00);
    let src_root = ns_root(src.id());
    let dst = empty_ns();
    assert_eq!(vfs::mntns::ns_root_id(dst.id()), None, "empty until copied into");

    vfs::mount::copy_mnt_ns(&src, &dst).expect("copy the namespace");

    let copied = ns_root(dst.id());
    assert_ne!(copied.mnt_id, src_root.mnt_id, "a copy, not the original");
    assert!(Arc::ptr_eq(&copied.sb, &src_root.sb), "and it is a copy of THAT root");
    assert_eq!(copied.namespace_id(), dst.id());
}

// The precondition is on the CALLER's namespace, so a task in a freshly copied
// one must be able to build a namespace of its own. This is the composition the
// invariant exists for.
#[test]
fn the_namespace_form_works_from_inside_a_copied_namespace() {
    let _g = guard();
    let src = caller_ns_with_root(0xB10);
    let dst = empty_ns();
    vfs::mount::copy_mnt_ns(&src, &dst).expect("copy the namespace");
    common::set_current_namespace(dst.clone());

    let (top, held) = vfs::mount::create_ns_mount(realized_sb(0x9201, 0xB11), 0, 0, None)
        .expect("the copied namespace is a legal caller");
    assert_eq!(top.parent_id.load(Ordering::Acquire), ns_root(held.id()).mnt_id);
    assert!(Arc::ptr_eq(&ns_root(held.id()).sb, &ns_root(dst.id()).sb),
        "the root copy is a copy of the CALLER's root, whichever namespace that is");
}

// ---------------------------------------------------------------------------
// 2. The constructor's own output satisfies its own precondition.
// ---------------------------------------------------------------------------

// A namespace descriptor is handed to userspace, which may `setns(2)` into it
// and call `fsmount(FSMOUNT_NAMESPACE)` again. Give the new namespace no root —
// or make the new mount BE the root — and the second call has nothing to copy.
#[test]
fn a_namespace_the_constructor_built_can_itself_build_another() {
    let _g = guard();
    let caller = caller_ns_with_root(0xB20);
    let (_first, held) = vfs::mount::create_ns_mount(realized_sb(0x9211, 0xB21), 0, 0, None)
        .expect("first namespace");

    common::set_current_namespace(held.clone());
    let (second, held2) = vfs::mount::create_ns_mount(realized_sb(0x9212, 0xB22), 0, 0, None)
        .expect("a namespace built by the constructor is a legal caller for it");

    let root2 = ns_root(held2.id());
    assert_ne!(root2.mnt_id, second.mnt_id);
    assert_eq!(second.parent_id.load(Ordering::Acquire), root2.mnt_id);
    // The root copy chain terminates at the original rootfs superblock: each
    // namespace copies its caller's root, and the first one's root was a copy of
    // the caller's.
    assert!(Arc::ptr_eq(&root2.sb, &ns_root(caller.id()).sb));
    assert_eq!(root2.namespace_id(), held2.id());
}

// ---------------------------------------------------------------------------
// 3. The root cannot be taken away.
// ---------------------------------------------------------------------------

// `do_umount`'s "not the absolute root" rung. The namespace root is
// self-parented, so this refusal is what makes the invariant hold for the whole
// life of the namespace rather than just at its creation — and it refuses
// `MNT_DETACH` too, because the rung sits AHEAD of the detach branch.
#[test]
fn the_namespace_root_has_no_parent_and_umount_refuses_it() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xB30);
    let (top, held) = vfs::mount::create_ns_mount(realized_sb(0x9221, 0xB31), 0, 0, None)
        .expect("named namespace mount");
    common::set_current_namespace(held.clone());
    let root = ns_root(held.id());

    // A task in this namespace has the TOP as its root, so the root copy is not
    // caught by the caller's-root rung — the parent rung is the one that fires.
    let caller_root = Some(top.mnt_id);
    let facts = vfs::mount::umount_facts(root.mnt_id, 0, caller_root, true)
        .expect("the root copy is a live mount");
    assert!(!facts.has_parent, "a namespace root is self-parented");
    assert!(!facts.is_caller_root);
    assert_eq!(vfs::mount::umount_check(0, &facts).outcome, Err(UmountRefusal::Einval));

    let detach = vfs::mount::umount_facts(root.mnt_id, vfs::mount::MNT_DETACH, caller_root, true)
        .expect("live");
    assert_eq!(vfs::mount::umount_check(vfs::mount::MNT_DETACH, &detach).outcome,
        Err(UmountRefusal::Einval), "the parent rung is ahead of the detach branch");

    // The mount ON the root copy is parented and unmounts normally — the rung
    // is about position, not about being inside a fresh namespace.
    let tf = vfs::mount::umount_facts(top.mnt_id, 0, None, true).expect("live");
    assert!(tf.has_parent);
    assert_eq!(vfs::mount::umount_check(0, &tf).outcome, Ok(Umount::ShrinkAndDetach));
}

// ---------------------------------------------------------------------------
// 4. The copied tree is accounted against the new namespace.
// ---------------------------------------------------------------------------

// `AT_RECURSIVE` copies the whole subtree, and every node of it — root copy
// included — is counted against the new namespace's mount total. Miss the
// nested nodes and the per-namespace mount cap stops bounding what one
// `open_tree(OPEN_TREE_NAMESPACE)` can create.
#[test]
fn the_recursive_namespace_form_counts_every_mount_it_copied() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xB40);
    let src = mount_at("/sub", 0xB41);
    let _deeper = mount_at("/sub/deeper", 0xB42);
    let base = src.mnt_root().expect("the source has a root");

    let (top, held) = vfs::mount::create_new_namespace(NsMountSource::Tree {
        src: Arc::clone(&src), base, recursive: true,
    }).expect("recursive namespace form");

    let root = ns_root(held.id());
    assert_eq!(top.parent_id.load(Ordering::Acquire), root.mnt_id);
    assert_eq!(held.nr_mounts.load(Ordering::Acquire), 3,
        "root copy + the subtree's two mounts");
    let ids: Vec<u64> = vfs::mount::mounts_in_ns_snapshot(held.id())
        .iter().map(|m| m.mnt_id).collect();
    assert_eq!(ids.len(), 3, "and all three are IN the namespace");
    assert!(ids.contains(&root.mnt_id) && ids.contains(&top.mnt_id));
}

// The non-recursive form takes the one mount and leaves the nested one behind,
// so the same tree yields a two-mount namespace.
#[test]
fn the_non_recursive_namespace_form_takes_only_the_named_mount() {
    let _g = guard();
    let _caller = caller_ns_with_root(0xB50);
    let src = mount_at("/sub", 0xB51);
    let _deeper = mount_at("/sub/deeper", 0xB52);
    let base = src.mnt_root().expect("root");

    let (_top, held) = vfs::mount::create_new_namespace(NsMountSource::Tree {
        src, base, recursive: false,
    }).expect("namespace form");
    assert_eq!(held.nr_mounts.load(Ordering::Acquire), 2, "root copy + the one mount");
}
