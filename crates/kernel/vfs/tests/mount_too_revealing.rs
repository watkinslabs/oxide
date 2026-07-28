//! B1478: `mount_too_revealing` — the constraint that stops an unprivileged
//! user-namespace holder from mounting a PRISTINE `proc`/`sysfs` instance next
//! to the masked one it was given.
//!
//! Before this fix the function did not exist. `mount_capable`
//! (`fs/super.c`, wired in the first half of this lane) correctly lets a
//! user-namespace holder mount `FS_USERNS_MOUNT` filesystems — procfs and sysfs
//! are exactly those two — with NO visibility constraint at all. So a container
//! whose `/proc/kcore`, `/proc/sys`, `/proc/sysrq-trigger` were covered by
//! locked mounts simply did `mount -t proc proc /mnt` and read the originals out
//! of the fresh instance. That is a straight information-disclosure escape, and
//! it is the whole reason Linux carries this check.
//!
//! Linux source mirrored: `fs/namespace.c` `mount_too_revealing` /
//! `mnt_already_visible` and their two callers `do_new_mount_fc` and
//! `do_fsmount`; `mnt_add_to_ns` for the `ns->mnt_visible_mounts` membership
//! rule; `include/linux/fs/super_types.h` for `SB_I_NOEXEC` / `SB_I_NODEV` /
//! `SB_I_RESTRICTED_VARIANT`; `fs/proc/root.c` `proc_fill_super` and
//! `fs/kernfs/mount.c` `kernfs_fill_super` for who stamps them.
//!
//! Own test binary → own copy of the vfs statics; `SERIAL`-guarded.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::fs::{FileSystem, FsFlags};
use vfs::inode::Inode;
use vfs::mount::{
    MNT_LOCKED, MNT_LOCK_ATIME, MNT_LOCK_READONLY, MNT_NOATIME, MNT_RDONLY, MNT_RELATIME,
};
use vfs::superblock::{SB_I_NODEV, SB_I_NOEXEC, SB_I_RESTRICTED_VARIANT, SB_I_USERNS_REQUIRED};
use vfs::{
    FileType, FileSystemType, InodeBuilder, InodeOps, InodeRef, KResult, SimpleSuperOps, SuperBlock,
    SuperOps, VfsError, default_file_ops, mk_mode,
};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

// --- The fixture filesystem: one PROCESS-GLOBAL `file_system_type` per name.
// Linux compares `sb_visible->s_type != sb->s_type` by POINTER, and the registry
// mints exactly one `file_system_type` per registered name. `common::realize_sb`
// mints a FRESH one per call, which would make every instance a different type,
// so this file owns its own shared-type constructor. ---

struct TFs { name: &'static str, ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { self.name }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.ino)) }
}
/// Directory factory, like `common`'s fixture root: every name resolves to a
/// fresh child directory, so a submount position under a mount of this fs
/// (`/vis/kcore` — the masked path) can be materialised.
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(make_tdir(NEXT_TDIR_INO.fetch_add(1, AtomicOrdering::Relaxed)))
    }
}
static NEXT_TDIR_INO: AtomicU64 = AtomicU64::new(0x9000);
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

/// The procfs stand-in: `FS_USERNS_MOUNT | FS_USERNS_MOUNT_RESTRICTED`, exactly
/// `fs/proc/root.c`'s `.fs_flags`. ONE `Arc` for the whole binary.
fn restricted_ty() -> Arc<dyn FileSystemType> {
    static TY: OnceLock<Arc<vfs::fs::FsType>> = OnceLock::new();
    TY.get_or_init(|| vfs::fs::FsType::new("revealfs", 0x9fa0,
        FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED,
        Box::new(|_, _, _, _| unreachable!("mounted explicitly")))).clone()
}

/// A type WITHOUT `FS_USERNS_MOUNT_RESTRICTED` — Linux's second early exit.
fn plain_ty() -> Arc<dyn FileSystemType> {
    static TY: OnceLock<Arc<vfs::fs::FsType>> = OnceLock::new();
    TY.get_or_init(|| vfs::fs::FsType::new("plainfs", 0x0102,
        FsFlags::FS_USERNS_MOUNT,
        Box::new(|_, _, _, _| unreachable!("mounted explicitly")))).clone()
}

/// A SECOND restricted type, to prove the `s_type` comparison actually discriminates.
fn other_restricted_ty() -> Arc<dyn FileSystemType> {
    static TY: OnceLock<Arc<vfs::fs::FsType>> = OnceLock::new();
    TY.get_or_init(|| vfs::fs::FsType::new("otherfs", 0x6265_6572,
        FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED,
        Box::new(|_, _, _, _| unreachable!("mounted explicitly")))).clone()
}

/// A superblock of `ty` with `s_iflags` stamped as `fill_super` would.
fn sb_of(ty: Arc<dyn FileSystemType>, ino: u64, s_iflags: u64, s_id: &str) -> Arc<SuperBlock> {
    let fs: Arc<dyn FileSystem> = Arc::new(TFs { name: "revealfs", ino });
    let s_op: Arc<dyn SuperOps> =
        Arc::new(SimpleSuperOps { magic: 0, block_size: 4096, options: String::new() });
    let sb = SuperBlock::from_ops(ty, s_op, fs.root(), 0, ino, 4096, String::from(s_id), Arc::new(()));
    sb.set_s_iflags(s_iflags);
    sb
}

/// The well-formed restricted superblock: both `required_iflags` stamped.
fn good_sb(ino: u64, s_id: &str) -> Arc<SuperBlock> {
    sb_of(restricted_ty(), ino, SB_I_USERNS_REQUIRED, s_id)
}

/// A FRESH mount namespace owned by the INITIAL user namespace, made current,
/// with its root mount grafted. One test binary shares ONE process-global
/// `MOUNTS`, so every test needs its own namespace.
fn fresh_ns(root_ino: u64) -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("source ns");
    common::set_current_namespace(namespace.clone());
    let rootfs: Arc<dyn FileSystem> = Arc::new(TFs { name: "rootfs", ino: root_ino });
    common::register("/", rootfs).expect("root mount");
    namespace
}

/// A mount namespace owned by a FRESH CHILD user namespace — the shape
/// `unshare(CLONE_NEWUSER|CLONE_NEWNS)` produces, and the only condition under
/// which Linux applies this check at all.
fn unprivileged_ns(root_ino: u64) -> vfs::mntns::MntNamespaceRef {
    let parent_user: NamespaceRef = namespace_identity::initial(NamespaceKind::User);
    let child_user = namespace_identity::allocate(NamespaceKind::User, parent_user.clone(),
        Some(parent_user)).expect("child user namespace");
    let namespace = vfs::mntns::allocate(child_user).expect("mount ns under the child user ns");
    common::set_current_namespace(namespace.clone());
    let rootfs: Arc<dyn FileSystem> = Arc::new(TFs { name: "rootfs", ino: root_ino });
    common::register("/", rootfs).expect("root mount");
    namespace
}

/// Graft `sb` at `p` in the current namespace with option mask `mnt_flags`,
/// returning the live mount.
fn graft(p: &str, sb: Arc<SuperBlock>, mnt_flags: u64) -> Arc<vfs::mount::Mount> {
    vfs::mount::attach_sb_with_flags_at(Some(common::dentry(p)), sb, mnt_flags, None).expect("graft");
    common::mount_at_path_exact(p).expect("mount exists")
}

// ---------------------------------------------------------------------------
// 1. The four early exits (Linux `mount_too_revealing`'s opening ladder).
// ---------------------------------------------------------------------------

#[test]
fn initial_user_namespace_is_never_constrained() {
    let _g = guard();
    fresh_ns(0x100);
    // `if (ns->user_ns == &init_user_ns) return false;` — no visible instance
    // exists here, yet the mount is admitted. Refusing would break every
    // ordinary `mount -t proc proc /proc` on the real system.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x101, "p"), MNT_RELATIME), Ok(0));
}

#[test]
fn a_type_without_userns_mount_restricted_is_never_constrained() {
    let _g = guard();
    unprivileged_ns(0x110);
    let sb = sb_of(plain_ty(), 0x111, 0, "plain");
    // `if (!(sb->s_type->fs_flags & FS_USERNS_MOUNT_RESTRICTED)) return false;`
    // — tmpfs et al. show only what their mounter put in them.
    assert_eq!(vfs::mount::mount_too_revealing(&sb, MNT_RELATIME), Ok(0));
}

#[test]
fn restricted_type_missing_required_iflags_is_refused() {
    let _g = guard();
    unprivileged_ns(0x120);
    // `if ((s_iflags & required_iflags) != required_iflags) { WARN_ONCE; return
    // true; }` — a filesystem that claims to be restricted but forgot to stamp
    // SB_I_NOEXEC|SB_I_NODEV is refused outright, even with a visible instance.
    graft("/vis", good_sb(0x121, "vis"), MNT_RELATIME);
    for partial in [0, SB_I_NOEXEC, SB_I_NODEV] {
        let sb = sb_of(restricted_ty(), 0x122, partial, "bad");
        assert_eq!(vfs::mount::mount_too_revealing(&sb, MNT_RELATIME), Err(VfsError::Eperm),
            "s_iflags={partial:#x} is missing part of required_iflags");
    }
}

#[test]
fn a_restricted_variant_needs_no_visible_instance() {
    let _g = guard();
    unprivileged_ns(0x130);
    // "Restricted variants don't need an already visible mount because they
    // don't expose the full filesystem view" — procfs `-o subset=pid`.
    let sb = sb_of(restricted_ty(), 0x131, SB_I_USERNS_REQUIRED | SB_I_RESTRICTED_VARIANT, "sub");
    assert_eq!(vfs::mount::mount_too_revealing(&sb, MNT_RELATIME), Ok(0));
}

// ---------------------------------------------------------------------------
// 2. The core rule: refuse without a fully-visible instance, admit with one.
// ---------------------------------------------------------------------------

#[test]
fn userns_mount_without_any_visible_instance_is_refused() {
    let _g = guard();
    unprivileged_ns(0x200);
    // THE ESCAPE. Nothing of this type is mounted in the namespace, so the new
    // instance would show strictly more than the namespace can already see.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x201, "fresh"), MNT_RELATIME),
        Err(VfsError::Eperm));
}

#[test]
fn userns_mount_with_a_fully_visible_instance_is_allowed() {
    let _g = guard();
    unprivileged_ns(0x210);
    graft("/vis", good_sb(0x211, "vis"), MNT_RELATIME);
    // The NON-refusal half: a "refuse everything" implementation cannot pass
    // this. `unshare -Urm --mount-proc` must keep working.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x212, "new"), MNT_RELATIME), Ok(0));
}

#[test]
fn a_visible_instance_of_a_different_type_does_not_vouch() {
    let _g = guard();
    unprivileged_ns(0x220);
    graft("/other", sb_of(other_restricted_ty(), 0x221, SB_I_USERNS_REQUIRED, "other"), MNT_RELATIME);
    // `if (sb_visible->s_type != sb->s_type) continue;` — a visible sysfs says
    // nothing about what a fresh procfs would reveal.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x222, "new"), MNT_RELATIME),
        Err(VfsError::Eperm));
    // ... and it still vouches for its OWN type.
    assert_eq!(vfs::mount::mount_too_revealing(
        &sb_of(other_restricted_ty(), 0x223, SB_I_USERNS_REQUIRED, "n2"), MNT_RELATIME), Ok(0));
}

#[test]
fn a_restricted_variant_cannot_vouch_for_a_full_instance() {
    let _g = guard();
    unprivileged_ns(0x230);
    graft("/sub", sb_of(restricted_ty(), 0x231,
        SB_I_USERNS_REQUIRED | SB_I_RESTRICTED_VARIANT, "sub"), MNT_RELATIME);
    // "Restricted variants are not compatible with anything, even other
    // restricted variants." A `subset=pid` procfs shows no `/proc/kcore`, so it
    // is no evidence that a FULL procfs would reveal nothing new.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x232, "full"), MNT_RELATIME),
        Err(VfsError::Eperm));
}

#[test]
fn a_bind_of_a_subdirectory_does_not_vouch() {
    let _g = guard();
    let ns = unprivileged_ns(0x240);
    let full = graft("/vis", good_sb(0x241, "vis"), MNT_RELATIME);
    // `mnt_add_to_ns`: a mount joins `mnt_visible_mounts` only when
    // `mnt->mnt.mnt_root == mnt->mnt.mnt_sb->s_root`. Bind clones SHARE the
    // source's superblock and dentries, so the discriminator is mnt_root vs
    // s_root — never the mountpoint dentry (`docs/16§6`, bind dentry-sharing).
    let sub = vfs::d_add(&full.mnt_root().expect("mnt_root"), "self", make_tdir(0x242));
    let root_id = vfs::mount::root_mount_id(ns.id()).expect("root mount");
    let tgt = common::dentry("/partial");
    vfs::mount::register_bind_clone_under(root_id, tgt.clone(), full.mnt_id, sub.clone())
        .expect("bind of a subdirectory");
    let bind = vfs::mount::mount_at_path_exact_under(root_id, &tgt).expect("the bind");
    assert!(!Arc::ptr_eq(&bind.mnt_root().unwrap(), &bind.sb().s_root().unwrap()),
        "the bind's mnt_root is the subdirectory, not the fs root");

    // Drop the WHOLE-fs mount; only the partial bind remains visible.
    let mp = full.mountpoint().expect("mountpoint");
    vfs::mount::unregister_top(&mp, false);
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x243, "new"), MNT_RELATIME),
        Err(VfsError::Eperm), "a bind of /vis/self reveals nothing about /vis/kcore");
}

// ---------------------------------------------------------------------------
// 3. The MNT_LOCK_* interaction: check AND propagate.
// ---------------------------------------------------------------------------

#[test]
fn a_locked_child_makes_the_visible_mount_not_fully_visible() {
    let _g = guard();
    unprivileged_ns(0x300);
    let vis = graft("/vis", good_sb(0x301, "vis"), MNT_RELATIME);
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x302, "n1"), MNT_RELATIME), Ok(0),
        "no locked child yet");

    // THE MASKED-PATH ESCAPE, precisely. A container gets /proc with
    // /proc/kcore covered by a locked mount (in practice a bind of /dev/null,
    // hence a DIFFERENT filesystem type); the visible instance is therefore NOT
    // fully visible, and a fresh instance would uncover it.
    let masked = graft("/vis/kcore", sb_of(plain_ty(), 0x303, 0, "mask"), MNT_RELATIME);
    assert_eq!(vfs::mount::parent_mnt_id(&masked), vis.mnt_id, "the mask is a child of /vis");
    masked.set_internal_flag(MNT_LOCKED);
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x304, "n2"), MNT_RELATIME),
        Err(VfsError::Eperm), "a locked child covering a non-empty dir vetoes the vouch");
}

#[test]
fn a_locked_readonly_visible_mount_forces_and_propagates_readonly() {
    let _g = guard();
    unprivileged_ns(0x310);
    let vis = graft("/vis", good_sb(0x311, "vis"), MNT_RELATIME | MNT_RDONLY);
    vis.set_internal_flag(MNT_LOCK_READONLY | MNT_LOCK_ATIME);

    // "Verify the mount flags are equal to or more permissive than the proposed
    // new mount": a writable fresh mount would launder away a lock the sandbox
    // creator imposed.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x312, "rw"), MNT_RELATIME),
        Err(VfsError::Eperm), "a read-write instance is refused against a locked-ro one");
    // "Preserve the locked attributes": the admitted mount INHERITS the lock.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x313, "ro"), MNT_RELATIME | MNT_RDONLY),
        Ok(MNT_LOCK_READONLY | MNT_LOCK_ATIME));
}

#[test]
fn readonly_hidden_in_the_superblock_still_locks() {
    let _g = guard();
    unprivileged_ns(0x320);
    let sb = good_sb(0x321, "vis");
    sb.set_s_flags(vfs::superblock::SB_RDONLY, 0);
    // "Don't miss readonly hidden in the superblock flags": `sb_rdonly(sb)`
    // implies MNT_LOCK_READONLY even though no MNT_LOCK_* bit is set on the
    // mount. Grafted WITHOUT MNT_RDONLY to prove the sb is what carries it.
    graft("/vis", sb, MNT_RELATIME);
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x322, "rw"), MNT_RELATIME),
        Err(VfsError::Eperm));
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x323, "ro"), MNT_RELATIME | MNT_RDONLY),
        Ok(MNT_LOCK_READONLY));
}

#[test]
fn a_locked_atime_policy_must_be_reproduced_exactly() {
    let _g = guard();
    unprivileged_ns(0x330);
    let vis = graft("/vis", good_sb(0x331, "vis"), MNT_RELATIME);
    vis.set_internal_flag(MNT_LOCK_ATIME);
    // `(mnt_flags & MNT_ATIME_MASK) != (new_flags & MNT_ATIME_MASK)` — the whole
    // atime field must match, not merely be no more permissive.
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x332, "noatime"), MNT_NOATIME),
        Err(VfsError::Eperm));
    assert_eq!(vfs::mount::mount_too_revealing(&good_sb(0x333, "same"), MNT_RELATIME),
        Ok(MNT_LOCK_ATIME));
}

// ---------------------------------------------------------------------------
// 4. The graft plumbing: the returned lock bits actually reach the new mount.
// ---------------------------------------------------------------------------

#[test]
fn the_preserved_lock_bits_are_installed_by_the_graft() {
    let _g = guard();
    unprivileged_ns(0x400);
    let vis = graft("/vis", good_sb(0x401, "vis"), MNT_RELATIME | MNT_RDONLY);
    vis.set_internal_flag(MNT_LOCK_READONLY | MNT_LOCK_ATIME);

    let sb = good_sb(0x402, "new");
    let mnt_flags = MNT_RELATIME | MNT_RDONLY;
    let lock = vfs::mount::mount_too_revealing(&sb, mnt_flags).expect("admitted");
    vfs::mount::attach_sb_locked_at(Some(common::dentry("/new")), sb, mnt_flags, lock, None)
        .expect("graft");
    let m = common::mount_at_path_exact("/new").expect("the new mount");
    // FAILS-BEFORE: `attach_sb_with_flags_at` had no internal-flag parameter at
    // all, so an inherited lock could not have been installed even if computed.
    assert_eq!(m.internal_flags() & (MNT_LOCK_READONLY | MNT_LOCK_ATIME),
        MNT_LOCK_READONLY | MNT_LOCK_ATIME, "the new mount inherited the locks");
    assert_eq!(vfs::mount::remount_flags_by_id(m.mnt_id, vfs::mount::MS_RELATIME),
        Err(VfsError::Eperm), "and they are enforced: it cannot be remounted read-write");
}

#[test]
fn lock_new_mount_bits_freezes_what_is_on_and_hides_the_mount() {
    let _g = guard();
    // `create_new_namespace`'s `lock_mnt_tree(new_ns_root)`, as the word
    // `fsmount(2)` hands to the graft: atime frozen unconditionally, each
    // protection frozen only when currently on, plus MNT_LOCKED (the copy's own
    // root IS `p != mnt` in Linux, because the synthetic ns root is `mnt`).
    assert_eq!(vfs::mount::lock_new_mount_bits(MNT_RELATIME),
        MNT_LOCK_ATIME | MNT_LOCKED);
    assert_eq!(vfs::mount::lock_new_mount_bits(MNT_RELATIME | MNT_RDONLY),
        MNT_LOCK_ATIME | MNT_LOCK_READONLY | MNT_LOCKED);
    assert_eq!(vfs::mount::lock_bits_for(MNT_RELATIME) & MNT_LOCKED, 0,
        "lock_bits_for is the option half only — MNT_LOCKED is positional");
}
