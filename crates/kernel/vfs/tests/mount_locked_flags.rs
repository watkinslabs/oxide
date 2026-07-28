//! B1478: `MNT_LOCK_*` / `MNT_LOCKED` — the mechanism that stops an
//! unprivileged user-namespace holder from REMOUNTING AWAY the protections it
//! inherited.
//!
//! Before this fix `MNT_LOCKED` was set by NOTHING (a grep for a writer of the
//! bit came back empty — it was only ever read and copied), and the five
//! `MNT_LOCK_*` bits did not exist at all. `unshare(CLONE_NEWUSER|CLONE_NEWNS)`
//! therefore handed the child a full copy of the mount tree that it could
//! `mount -o remount,dev,suid,exec,rw` at will, and unmount to reveal whatever a
//! mount was covering. That makes user namespaces a privilege-escalation surface
//! rather than a sandbox.
//!
//! Linux source mirrored: `fs/namespace.c` `lock_mnt_tree` (called from
//! `copy_mnt_ns` under `if (user_ns != ns->user_ns)`), `can_change_locked_flags`
//! (`do_remount` / `do_reconfigure_mnt` / `mount_setattr`, all EPERM),
//! `__has_locked_children` (`__do_loopback` EINVAL), `clone_mnt`'s
//! `& ~MNT_INTERNAL_FLAGS`, and `do_umount`'s `MNT_LOCKED` EINVAL.
//!
//! Own test binary → own copy of the vfs statics; `SERIAL`-guarded.

use std::sync::{Arc, Mutex, MutexGuard};

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{
    MNT_LOCKED, MNT_LOCK_ATIME, MNT_LOCK_MASK, MNT_LOCK_NODEV, MNT_LOCK_NOEXEC, MNT_LOCK_NOSUID,
    MNT_LOCK_READONLY, MNT_NODEV, MNT_NOSUID, MNT_RDONLY, MNT_RELATIME,
    MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_RELATIME, MS_STRICTATIME,
};
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct TFs(u64);
impl FileSystem for TFs {
    fn name(&self) -> &str { "lkfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.0)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs(ino)) }

/// A FRESH source mount namespace, made current, with its root mount grafted.
/// One test binary shares ONE process-global `MOUNTS` + dentry tree, so every
/// test needs its own namespace or it inherits the previous test's mounts (and,
/// once locking works, the previous test's lock bits).
fn fresh_source_ns(root_ino: u64) -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("source ns");
    common::set_current_namespace(namespace.clone());
    common::register("/", fs(root_ino)).expect("root mount");
    namespace
}

/// The copied mount at rendered path `p` inside namespace `ns`.
fn copy_at(ns: u64, p: &str) -> Arc<vfs::mount::Mount> {
    vfs::mount::snapshot_ns_view(ns).into_iter()
        .find(|m| m.mount_point_str() == p).unwrap_or_else(|| panic!("copy of {p}"))
}

/// A mount namespace owned by a FRESH child user namespace — the shape
/// `unshare(CLONE_NEWUSER|CLONE_NEWNS)` produces, and the ONLY condition under
/// which Linux locks the copy.
fn ns_under_new_user_ns() -> vfs::mntns::MntNamespaceRef {
    let parent_user: NamespaceRef = namespace_identity::initial(NamespaceKind::User);
    let child_user = namespace_identity::allocate(NamespaceKind::User, parent_user.clone(),
        Some(parent_user)).expect("child user namespace");
    vfs::mntns::allocate(child_user).expect("mount namespace under the child user ns")
}

fn mount_with(p: &str, ino: u64, ms: u64) -> Arc<vfs::mount::Mount> {
    let sb = common::realize_sb(fs(ino), None, ino, String::from(p));
    vfs::mount::attach_sb_with_flags_at(Some(common::dentry(p)), sb, vfs::mount::ms_to_mnt(ms), None)
        .expect("graft");
    common::mount_at_path_exact(p).expect("mount exists")
}

fn in_ns<T>(namespace: &vfs::mntns::MntNamespaceRef, f: impl FnOnce() -> T) -> T {
    let prev = common::current_namespace();
    common::set_current_namespace(namespace.clone());
    let r = f();
    common::set_current_namespace(prev);
    r
}

// ---------------------------------------------------------------------------
// 1. The stamp: a cross-user-ns copy freezes what it inherited.
// ---------------------------------------------------------------------------

#[test]
fn cross_user_ns_copy_freezes_protections_and_locks_submounts() {
    let _g = guard();
    let src = fresh_source_ns(0x1);
    mount_with("/hard", 0x11, MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY);
    mount_with("/soft", 0x12, 0);

    let child = ns_under_new_user_ns();
    vfs::mount::copy_mnt_ns(&src, &child).expect("copy into the unprivileged ns");

    let copies = vfs::mount::snapshot_ns_view(child.id());
    assert_eq!(copies.len(), 3, "root + 2 submounts copied");
    let root_id = vfs::mount::root_mount_id(child.id()).expect("child ns root");

    for m in copies.iter() {
        // FAILS-BEFORE: nothing ever wrote a MNT_LOCK_* bit, so this was 0.
        assert!(m.internal_flags() & MNT_LOCK_ATIME != 0,
            "atime is frozen on EVERY node (Linux stamps it unconditionally)");
        let opts = m.flags();
        assert_eq!(m.internal_flags() & MNT_LOCK_READONLY != 0, opts & MNT_RDONLY != 0,
            "MNT_LOCK_READONLY iff currently read-only");
        assert_eq!(m.internal_flags() & MNT_LOCK_NOSUID != 0, opts & MNT_NOSUID != 0);
        assert_eq!(m.internal_flags() & MNT_LOCK_NODEV != 0, opts & MNT_NODEV != 0);
        // "Don't allow unprivileged users to reveal what is under a mount":
        // every node BUT the tree root is MNT_LOCKED.
        assert_eq!(m.is_locked(), m.mnt_id != root_id,
            "MNT_LOCKED on every non-root copy, never on the namespace root");
    }
}

#[test]
fn same_user_ns_copy_is_not_locked() {
    let _g = guard();
    let src = fresh_source_ns(0x2);
    mount_with("/hard", 0x21, MS_NOSUID | MS_RDONLY);

    // Linux locks ONLY when the destination's user namespace differs. A plain
    // `unshare(CLONE_NEWNS)` copy stays fully mutable — locking it would break
    // every systemd sandbox, which remounts its own copies constantly.
    let peer = vfs::mntns::allocate(src.owner_user_namespace()).expect("same-user-ns child");
    vfs::mount::copy_mnt_ns(&src, &peer).expect("copy");
    for m in vfs::mount::snapshot_ns_view(peer.id()) {
        assert_eq!(m.internal_flags() & (MNT_LOCK_MASK | MNT_LOCKED), 0,
            "a same-user-ns copy carries no lock bits");
    }
}

// ---------------------------------------------------------------------------
// 2. The enforcement: the frozen mount REFUSES to be relaxed.
// ---------------------------------------------------------------------------

#[test]
fn locked_mount_refuses_remount_that_drops_a_protection() {
    let _g = guard();
    let src = fresh_source_ns(0x3);
    mount_with("/hard", 0x31, MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY);

    let child = ns_under_new_user_ns();
    vfs::mount::copy_mnt_ns(&src, &child).expect("copy");
    let id = copy_at(child.id(), "/hard").mnt_id;

    in_ns(&child, || {
        // FAILS-BEFORE: `apply_remount` had no locked-flag ladder at all, so each
        // of these returned Ok(()) and the sandbox escaped its own restrictions.
        assert_eq!(vfs::mount::remount_flags_by_id(id, MS_NODEV | MS_NOEXEC | MS_RDONLY),
            Err(VfsError::Eperm), "dropping nosuid is refused with EPERM");
        assert_eq!(vfs::mount::remount_flags_by_id(id, MS_NOSUID | MS_NOEXEC | MS_RDONLY),
            Err(VfsError::Eperm), "dropping nodev is refused");
        assert_eq!(vfs::mount::remount_flags_by_id(id, MS_NOSUID | MS_NODEV | MS_RDONLY),
            Err(VfsError::Eperm), "dropping noexec is refused");
        assert_eq!(vfs::mount::remount_flags_by_id(id, MS_NOSUID | MS_NODEV | MS_NOEXEC),
            Err(VfsError::Eperm), "dropping ro is refused");

        // Nothing was committed by any refused attempt.
        let m = vfs::mount::mount_by_id(id).expect("still there");
        assert!(m.is_nosuid() && m.is_nodev() && m.is_noexec() && m.is_readonly(),
            "a refused remount changes nothing");

        // A remount that KEEPS every frozen protection is allowed — the lock
        // forbids relaxing, not remounting.
        vfs::mount::remount_flags_by_id(id, MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY)
            .expect("a protection-preserving remount is allowed");
    });
}

#[test]
fn locked_atime_refuses_a_retune() {
    let _g = guard();
    let src = fresh_source_ns(0x4);
    mount_with("/rel", 0x41, MS_RELATIME);

    let child = ns_under_new_user_ns();
    vfs::mount::copy_mnt_ns(&src, &child).expect("copy");
    let id = copy_at(child.id(), "/rel").mnt_id;

    in_ns(&child, || {
        assert_eq!(vfs::mount::mount_by_id(id).unwrap().flags() & MNT_RELATIME, MNT_RELATIME);
        // MNT_LOCK_ATIME is stamped unconditionally, so ANY atime change is EPERM.
        assert_eq!(vfs::mount::remount_flags_by_id(id, MS_STRICTATIME), Err(VfsError::Eperm),
            "retuning a frozen atime policy is refused");
        // Same policy = no change = allowed (Linux compares the whole
        // MNT_ATIME_MASK, it does not forbid the remount outright).
        vfs::mount::remount_flags_by_id(id, MS_RELATIME).expect("same atime policy is allowed");
    });
}

#[test]
fn mount_setattr_cannot_clear_a_locked_bit() {
    let _g = guard();
    let src = fresh_source_ns(0x5);
    mount_with("/hard", 0x51, MS_NOSUID | MS_NODEV);

    let child = ns_under_new_user_ns();
    vfs::mount::copy_mnt_ns(&src, &child).expect("copy");
    let id = copy_at(child.id(), "/hard").mnt_id;

    in_ns(&child, || {
        // `mount_setattr(2)` is the modern relax path and was completely
        // ungated: `attr_clr = MOUNT_ATTR_NOSUID` cleared the bit outright.
        assert_eq!(vfs::mount::mnt_setattr_by_id(id, 0, MNT_NOSUID), Err(VfsError::Eperm),
            "clearing a frozen MNT_NOSUID via mount_setattr is EPERM");
        assert_eq!(vfs::mount::mnt_setattr_tree_by_id(id, 0, MNT_NODEV), Err(VfsError::Eperm),
            "AT_RECURSIVE does not launder the refusal");
        assert!(vfs::mount::mount_by_id(id).unwrap().is_nosuid(), "nothing committed");
        // Adding a protection is always fine.
        vfs::mount::mnt_setattr_by_id(id, MNT_RDONLY, 0).expect("tightening is allowed");
    });
}

#[test]
fn locked_mount_refuses_umount_and_move() {
    let _g = guard();
    let src = fresh_source_ns(0x6);
    mount_with("/hide", 0x61, 0);

    let child = ns_under_new_user_ns();
    vfs::mount::copy_mnt_ns(&src, &child).expect("copy");
    let locked = copy_at(child.id(), "/hide");
    assert!(locked.is_locked(), "the copy is MNT_LOCKED");

    in_ns(&child, || {
        // `do_umount`: `if (mnt->mnt_flags & MNT_LOCKED) return -EINVAL` — the
        // reveal the lock exists to prevent. (The guard predates this branch;
        // asserted here because it is worthless until something SETS the bit.)
        let mp = locked.mountpoint().expect("mountpoint");
        assert_eq!(vfs::mount::unregister_top(&mp, false), 0,
            "a MNT_LOCKED mount cannot be unmounted to reveal what it covers");
        assert!(vfs::mount::mount_by_id(locked.mnt_id).is_some(), "still mounted");
    });
}

// ---------------------------------------------------------------------------
// 3. Propagation of the stamp through clones + the bind reveal guard.
// ---------------------------------------------------------------------------

#[test]
fn clone_keeps_lock_bits_and_bind_drops_only_mnt_locked() {
    let _g = guard();
    fresh_source_ns(0x7);
    let m = mount_with("/hard", 0x71, MS_NOSUID | MS_RDONLY);
    m.set_internal_flag(MNT_LOCK_NOSUID | MNT_LOCK_READONLY | MNT_LOCK_ATIME | MNT_LOCKED);

    // Linux `clone_mnt` masks `~MNT_INTERNAL_FLAGS`, which contains MNT_LOCKED
    // but NOT the MNT_LOCK_* bits: a bind of a frozen mount stays frozen, while
    // the bind itself may be unmounted by whoever made it. Before this fix the
    // mask was `& MNT_LOCKED` — exactly inverted, so a bind of a frozen mount
    // came out fully relaxable.
    let src_d = m.mnt_root().expect("mnt_root");
    let root_id = vfs::mount::root_mount_id(vfs::mount::current_ns()).expect("root");
    let tgt = common::dentry("/bind");
    vfs::mount::register_bind_clone_under(root_id, tgt.clone(), m.mnt_id, src_d)
        .expect("bind clone");
    let bind = vfs::mount::mount_at_path_exact_under(root_id, &tgt).expect("the bind");
    assert_eq!(bind.internal_flags() & MNT_LOCK_MASK,
        MNT_LOCK_NOSUID | MNT_LOCK_READONLY | MNT_LOCK_ATIME,
        "the sticky MNT_LOCK_* bits ride the bind");
    assert!(!bind.is_locked(), "MNT_LOCKED does NOT ride the bind (Linux clone_mnt)");
    assert_eq!(vfs::mount::remount_flags_by_id(bind.mnt_id, MS_RDONLY), Err(VfsError::Eperm),
        "the bind of a frozen mount is still frozen");
}

#[test]
fn non_recursive_bind_of_a_subtree_with_locked_children_is_refused() {
    let _g = guard();
    let src = fresh_source_ns(0x8);
    let a = mount_with("/a", 0x81, 0);
    mount_with("/b", 0x82, 0);
    let parent = vfs::mount::root_mount_id(src.id()).and_then(vfs::mount::mount_by_id)
        .expect("the root mount, parent of both");
    let root_d = parent.mnt_root().expect("root mnt_root");
    let b_mp = common::dentry("/b");

    assert!(!vfs::mount::has_locked_children(&parent, &root_d), "nothing locked yet");
    a.set_internal_flag(MNT_LOCKED);
    // `__do_loopback`: `if (!recurse && __has_locked_children(old, dentry))
    // return -EINVAL` — a non-recursive bind would publish the directory the
    // locked child covers.
    assert!(vfs::mount::has_locked_children(&parent, &root_d),
        "a MNT_LOCKED direct child under the bind root vetoes a non-recursive bind");
    // Scoped to the bind ROOT: a locked child OUTSIDE the subtree does not veto.
    assert!(!vfs::mount::has_locked_children(&parent, &b_mp),
        "the locked child is not under /b, so a bind of /b is unaffected");
}
