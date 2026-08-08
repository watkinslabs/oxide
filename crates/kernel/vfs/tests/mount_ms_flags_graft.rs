//! B1478: the `mount(2)` `MS_*` option word must REACH the mount it creates.
//!
//! Before this fix `sys_mount` computed nothing from `flags` on the fresh-mount
//! path — `dispatch_mount` grafted with a hard-coded `mnt_flags = 0` — so
//! `mount -o ro,nosuid,nodev,noexec` produced a mount whose `mnt_flags` were
//! EMPTY. `/proc/mounts` still printed the options (it renders the request), but
//! every consumer of the per-mount bits read "unrestricted": `mnt_want_write`
//! allowed writes on a `ro` mount, `mnt_may_suid` honoured set-user-ID on a
//! `nosuid` mount, `may_open` opened device nodes on a `nodev` mount, and the
//! exec/mmap gates allowed execution on a `noexec` mount.
//!
//! Every assertion below is NEGATIVE — it checks that the restriction actually
//! REFUSES something. A happy-path "the bit is set" test is what let this ship.
//!
//! Contract mirrored: `path_mount` separates the per-mountpoint MS_* flags
//! from the fs-specific data string and defaults atime-on-remount to
//! preservation; `do_add_mount` stamps the resolved `mnt_flags` onto the new
//! mount; `__mnt_is_readonly` reads them back.
//!
//! Own test binary → own copy of the vfs statics; `SERIAL`-guarded.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{
    ms_to_mnt, ms_to_mnt_remount, AtimePolicy, MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC,
    MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_RDONLY, MNT_RELATIME, MNT_STRICTATIME,
    MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_RDONLY,
    MS_RELATIME, MS_STRICTATIME,
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
    fn name(&self) -> &str { "msfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.0)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

/// The graft `sys_mount`'s fresh-mount path performs: realize a superblock, then
/// `attach_sb_with_flags_at` with the MNT_* mask `ms_to_mnt` derived from the
/// caller's `MS_*` word — i.e. exactly `do_new_mount` → `do_add_mount`.
fn mount_with(p: &str, ino: u64, ms: u64) -> Arc<vfs::mount::Mount> {
    let fs: Arc<dyn FileSystem> = Arc::new(TFs(ino));
    let sb = common::realize_sb(fs, None, ino, String::from(p));
    vfs::mount::attach_sb_with_flags_at(Some(common::dentry(p)), sb, ms_to_mnt(ms), None)
        .expect("graft");
    common::mount_at_path_exact(p).expect("mount exists")
}

// ---------------------------------------------------------------------------
// 1. The map itself — `path_mount`'s block, statement for statement.
// ---------------------------------------------------------------------------

#[test]
fn ms_to_mnt_mirrors_path_mount() {
    // Protection bits map one-to-one.
    assert_eq!(ms_to_mnt(MS_RDONLY) & MNT_RDONLY, MNT_RDONLY);
    assert_eq!(ms_to_mnt(MS_NOSUID) & MNT_NOSUID, MNT_NOSUID);
    assert_eq!(ms_to_mnt(MS_NODEV)  & MNT_NODEV,  MNT_NODEV);
    assert_eq!(ms_to_mnt(MS_NOEXEC) & MNT_NOEXEC, MNT_NOEXEC);
    assert_eq!(ms_to_mnt(MS_NODIRATIME) & MNT_NODIRATIME, MNT_NODIRATIME);

    // MS_NOSYMFOLLOW (mount UAPI value 256) was not even DEFINED before, so
    // the request bit was silently dropped and the mount followed symlinks.
    assert_eq!(MS_NOSYMFOLLOW, 256);
    assert_eq!(ms_to_mnt(MS_NOSYMFOLLOW) & MNT_NOSYMFOLLOW, MNT_NOSYMFOLLOW);

    // "Default to relatime unless overriden".
    assert_eq!(ms_to_mnt(0) & MNT_RELATIME, MNT_RELATIME);
    assert_eq!(ms_to_mnt(MS_RELATIME) & MNT_RELATIME, MNT_RELATIME);
    assert_eq!(ms_to_mnt(MS_NOATIME) & MNT_RELATIME, 0, "MS_NOATIME suppresses the default");
    assert_eq!(ms_to_mnt(MS_NOATIME) & MNT_NOATIME, MNT_NOATIME);

    // `if (flags & MS_STRICTATIME) mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);`
    // runs AFTER the NOATIME set, so STRICTATIME wins over NOATIME. The old
    // `if NOATIME {..} else if STRICTATIME {..}` ladder got this backwards.
    let both = ms_to_mnt(MS_NOATIME | MS_STRICTATIME);
    assert_eq!(both & MNT_NOATIME, 0, "MS_STRICTATIME clears NOATIME");
    assert_eq!(both & MNT_RELATIME, 0, "MS_STRICTATIME clears RELATIME");
    assert_eq!(both & MNT_STRICTATIME, MNT_STRICTATIME);
}

#[test]
fn remount_preserves_atime_when_unrequested() {
    // "The default atime for remount is preservation": a remount naming NO atime
    // bit keeps the mount's current mode. Pre-fix `ms_to_mnt` unconditionally
    // stamped relatime, so `mount -o remount,ro` silently reset a noatime mount
    // to relatime (a real Linux divergence, and an atime-lock bypass).
    let cur = MNT_NOATIME;
    let kept = ms_to_mnt_remount(MS_RDONLY, cur);
    assert_eq!(kept & MNT_NOATIME, MNT_NOATIME, "unrequested atime preserved");
    assert_eq!(kept & MNT_RELATIME, 0, "relatime NOT re-stamped");
    assert_eq!(kept & MNT_RDONLY, MNT_RDONLY, "the requested change still applies");

    // An EXPLICIT atime request overrides the preservation.
    let asked = ms_to_mnt_remount(MS_RELATIME, cur);
    assert_eq!(asked & MNT_NOATIME, 0);
    assert_eq!(asked & MNT_RELATIME, MNT_RELATIME);
}

// ---------------------------------------------------------------------------
// 2. The map REACHES the mount, and the resulting mount REFUSES things.
// ---------------------------------------------------------------------------

#[test]
fn ro_mount_refuses_writes() {
    let _g = guard();
    common::register("/", Arc::new(TFs(0x1))).expect("root");

    let rw = mount_with("/rw", 0x10, 0);
    vfs::mount::mnt_want_write(&rw).expect("a plain mount accepts writers");
    vfs::mount::mnt_drop_write(&rw);

    // FAILS-BEFORE: the graft dropped `flags`, so this mount came up rw and
    // `mnt_want_write` returned Ok — every write to a `-o ro` mount succeeded.
    let ro = mount_with("/ro", 0x11, MS_RDONLY);
    assert!(ro.is_readonly(), "MS_RDONLY reached the mount");
    assert_eq!(vfs::mount::mnt_want_write(&ro), Err(VfsError::Erofs),
        "a read-only mount REFUSES a writer with EROFS");
    assert_eq!(ro.writers(), 0, "a refused mnt_want_write takes no writer ref");
}

#[test]
fn nosuid_mount_refuses_setuid_and_file_caps() {
    let _g = guard();
    common::register("/", Arc::new(TFs(0x2))).expect("root");

    assert!(mount_with("/suid", 0x20, 0).may_suid(), "a plain mount honours set-user-ID");

    // FAILS-BEFORE: `mnt_flags` was 0, so `mnt_may_suid` said true and
    // `exec_transition` honoured the set-user-ID bit AND the security.capability
    // xattr of a binary on a `-o nosuid` mount — a straight privilege escalation.
    let m = mount_with("/nosuid", 0x21, MS_NOSUID);
    assert!(m.is_nosuid());
    assert!(!m.may_suid(),
        "mnt_may_suid is false on a nosuid mount (gates setuid AND file caps)");
}

#[test]
fn noexec_and_nodev_reach_the_mount() {
    let _g = guard();
    common::register("/", Arc::new(TFs(0x3))).expect("root");

    let plain = mount_with("/plain", 0x30, 0);
    assert!(!plain.is_noexec() && !plain.is_nodev());

    // FAILS-BEFORE: both read false, so `fs_access_common`'s EACCES-on-X_OK gate,
    // the mmap PROT_EXEC gate and `may_open_dev`'s EACCES never fired.
    let m = mount_with("/hard", 0x31, MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RDONLY);
    assert!(m.is_noexec(), "MS_NOEXEC reached the mount");
    assert!(m.is_nodev(),  "MS_NODEV reached the mount");
    assert!(m.is_nosuid(), "MS_NOSUID reached the mount");
    assert!(m.is_readonly(), "MS_RDONLY reached the mount");
}

#[test]
fn atime_request_reaches_the_mount() {
    let _g = guard();
    common::register("/", Arc::new(TFs(0x4))).expect("root");
    assert_eq!(mount_with("/def", 0x40, 0).atime_policy(), AtimePolicy::Relatime);
    assert_eq!(mount_with("/na", 0x41, MS_NOATIME).atime_policy(), AtimePolicy::Noatime);
    assert_eq!(mount_with("/sa", 0x42, MS_STRICTATIME).atime_policy(), AtimePolicy::Strict);
}

#[test]
fn readonly_superblock_makes_every_mount_over_it_readonly() {
    let _g = guard();
    common::register("/", Arc::new(TFs(0x5))).expect("root");

    // Linux `__mnt_is_readonly` is `(mnt_flags & MNT_READONLY) || sb_rdonly(sb)`.
    // The second half was missing: `mnt_want_write` consulted only the per-mount
    // bit, so a mount over a read-only SUPERBLOCK (a RO backing device, an ext4
    // that aborted its journal) accepted writers.
    let m = mount_with("/sbro", 0x50, 0);
    assert!(!vfs::mount::mnt_is_readonly(&m));
    m.sb().set_s_flags(vfs::superblock::SB_RDONLY, 0);
    assert!(!m.is_readonly(), "the per-mount bit is still clear");
    assert!(vfs::mount::mnt_is_readonly(&m), "sb_rdonly alone makes the mount read-only");
    assert_eq!(vfs::mount::mnt_want_write(&m), Err(VfsError::Erofs),
        "a mount over a read-only superblock REFUSES a writer");
}
