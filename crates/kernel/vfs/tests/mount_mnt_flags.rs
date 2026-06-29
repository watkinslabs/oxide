//! B252 [D11 + mnt_flags model]: the kernel-internal `mnt_flags` bit set
//! (MNT_LOCKED/MNT_INTERNAL/MNT_DOOMED/MNT_MARKED/MNT_UMOUNT, Linux
//! include/linux/mount.h) lives in a DISJOINT word from the MS_*-valued option
//! mask, and the option mask has typed readback (RDONLY/NOSUID/NODEV/NOEXEC/
//! RELATIME) + an atime-policy resolver. Pre-fix only the raw `flags()` u64 and
//! the `Propagation` enum existed — no MNT_LOCKED/MNT_INTERNAL bits (grep
//! empty), no typed accessors. Exercises the real global mount engine via the
//! hosted dentry-identity fixture. Serializes on `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{
    AtimePolicy, MNT_DOOMED, MNT_INTERNAL, MNT_LOCKED, MNT_MARKED, MNT_NODEV, MNT_NOEXEC,
    MNT_NOSUID, MNT_RDONLY, MNT_RELATIME,
};
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xF1A6);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn mount_at(p: &str) -> Arc<vfs::mount::Mount> {
    common::mount_at_path_exact(p).expect("mount exists")
}

// Typed readback of the MS_*-valued OPTION mask: remount_flags sets bits, the
// typed accessors read them back, and the atime policy resolves per Linux
// precedence. Pre-fix there were no is_readonly/is_nosuid/... accessors.
#[test]
fn option_mask_typed_readback_and_atime_policy() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/m", fs(0xA)).expect("m");
    let d = common::dentry("/m");

    // Default: nothing set → relatime is the kernel default, all gates false.
    let m = mount_at("/m");
    assert!(!m.is_readonly() && !m.is_nosuid() && !m.is_nodev() && !m.is_noexec());
    assert_eq!(m.atime_policy(), AtimePolicy::Relatime, "default policy is relatime");

    // Set RDONLY|NOSUID|NODEV|NOEXEC and read back each typed gate.
    vfs::mount::remount_flags(&d, MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_NOEXEC)
        .expect("remount");
    let m = mount_at("/m");
    assert!(m.is_readonly(), "MNT_RDONLY readback");
    assert!(m.is_nosuid(), "MNT_NOSUID readback");
    assert!(m.is_nodev(), "MNT_NODEV readback");
    assert!(m.is_noexec(), "MNT_NOEXEC readback");
    assert_eq!(m.flags() & MNT_RDONLY, MNT_RDONLY);

    // Explicit RELATIME resolves to the Relatime policy.
    vfs::mount::remount_flags(&d, MNT_RELATIME).expect("remount relatime");
    assert_eq!(mount_at("/m").atime_policy(), AtimePolicy::Relatime);
    assert!(!mount_at("/m").is_readonly(), "remount cleared RDONLY");
}

// The internal `mnt_flags` word is DISJOINT from the option mask: setting
// MNT_LOCKED/MNT_INTERNAL leaves `flags()` untouched and vice-versa, and the
// per-bit set/clear is xchg-correct (returns the prior word).
#[test]
fn internal_flags_disjoint_from_option_mask() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/lk", fs(0xB)).expect("lk");
    let d = common::dentry("/lk");
    let m = mount_at("/lk");

    assert!(!m.is_locked() && !m.is_internal() && !m.is_doomed(), "clean start");
    assert_eq!(m.internal_flags(), 0);

    // Set an OPTION bit — the internal word stays zero (disjoint spaces).
    vfs::mount::remount_flags(&d, MNT_RDONLY).expect("remount");
    let m = mount_at("/lk");
    assert!(m.is_readonly());
    assert_eq!(m.internal_flags(), 0, "option mask does not bleed into mnt_flags");

    // Set internal bits — the option mask stays unchanged.
    let prior = m.set_internal_flag(MNT_LOCKED | MNT_INTERNAL);
    assert_eq!(prior, 0, "set returns the prior internal word");
    assert!(m.is_locked() && m.is_internal(), "internal bits readback");
    assert!(m.has_internal_flag(MNT_LOCKED | MNT_INTERNAL));
    assert!(m.is_readonly(), "option mask untouched by internal-flag set");
    assert_eq!(m.flags() & MNT_LOCKED as u64, 0, "MNT_LOCKED is not an option bit");

    // Clear one internal bit; the other survives; xchg returns the prior word.
    let prior = m.clear_internal_flag(MNT_LOCKED);
    assert!(prior & MNT_LOCKED != 0, "clear returns prior word with the bit set");
    assert!(!m.is_locked() && m.is_internal(), "only MNT_LOCKED cleared");
    let _ = MNT_DOOMED; // const exists (D11 requires the bit to be defined)
}

// MNT_LOCKED is preserved across a copy_mnt_ns clone (Linux clone_mnt) so a
// child userns cannot reveal a locked submount; transient internal marks are
// NOT copied.
#[test]
fn copy_mnt_ns_preserves_mnt_locked() {
    let _g = guard();
    let from = vfs::mount::current_ns();
    common::register("/", fs(0x1)).expect("root");
    common::register("/sub", fs(0xC)).expect("sub");
    let m = mount_at("/sub");
    m.set_internal_flag(MNT_LOCKED | MNT_MARKED);

    let to = 0xF1B7u64;
    vfs::mount::copy_mnt_ns(from, to);
    // Re-point the engine to the new ns and find the clone of /sub.
    vfs::mount::set_current_ns_provider(|| 0xF1B7);
    let clone = mount_at("/sub");
    assert!(clone.mnt_id != m.mnt_id, "clone is a distinct mount");
    assert!(clone.is_locked(), "MNT_LOCKED preserved on the ns clone");
    assert_eq!(clone.internal_flags() & MNT_MARKED, 0,
        "transient MNT_MARKED not carried to the clone");
    let _ = (from, to);
}
