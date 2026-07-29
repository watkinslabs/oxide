//! memfd seal word still works after the inode-D42 placement refactor (it must
//! not change behavior). The seal WORD no longer lives on the generic
//! `struct Inode`; it lives in the per-fs inode-info, reached through the
//! `vfs::SealCarrier` trait (Linux `SHMEM_I(inode)->seals`). A sealable memfd
//! attaches a carrier via `InodeBuilder::seal_carrier(...)`; `fcntl_seals()`
//! exposes the word for F_GET_SEALS/F_ADD_SEALS. A non-sealable inode attaches
//! no carrier → `fcntl_seals()` is `None` (the syscall layer maps that to
//! EINVAL). This pins the observable contract so the relocation stays
//! behavior-preserving.

use std::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use vfs::{
    ATTR_MODE, Cred, F_SEAL_EXEC, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE,
    FileType, IDENTITY, Iattr, InodeBuilder, InodeRef, SealCarrier,
    default_file_ops, default_inode_ops, mk_mode, notify_change,
};

/// Stand-in for the tmpfs/shmem inode-info (`TmpfsFileData`): owns the seal word
/// in the per-fs backend, exactly where the relocation puts it.
struct ShmemInfo { seals: AtomicU32 }
impl SealCarrier for ShmemInfo {
    fn seal_word(&self) -> &AtomicU32 { &self.seals }
}

#[test]
fn sealable_inode_round_trips_seals() {
    let info = Arc::new(ShmemInfo { seals: AtomicU32::new(0) });
    let ino: InodeRef = InodeBuilder::new(0x5EA1, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops())
        .seal_carrier(info.clone())
        .build();
    let s = ino.fcntl_seals().expect("sealable memfd exposes a seal word");
    assert_eq!(s.load(Ordering::Acquire), 0, "initial seal word is empty");
    // F_ADD_SEALS semantics: OR new bits in.
    s.fetch_or(F_SEAL_WRITE, Ordering::AcqRel);
    s.fetch_or(F_SEAL_SHRINK, Ordering::AcqRel);
    assert_eq!(s.load(Ordering::Acquire), F_SEAL_WRITE | F_SEAL_SHRINK,
        "added seals accumulate (F_GET_SEALS would report both)");
    // The word lives in the backend inode-info, not on `struct Inode`: the
    // carrier and the inode observe the SAME store.
    assert_eq!(info.seals.load(Ordering::Acquire), F_SEAL_WRITE | F_SEAL_SHRINK,
        "seal word is stored in the per-fs inode-info (SealCarrier), not on Inode");
}

#[test]
fn seal_seal_blocks_further_seals() {
    // F_SEAL_SEAL is the "no more sealing" latch the syscall layer enforces by
    // reading the word; once set, F_ADD_SEALS must reject (EPERM). Pin that the
    // word round-trips so the syscall gate sees it.
    let info = Arc::new(ShmemInfo { seals: AtomicU32::new(0) });
    let ino: InodeRef = InodeBuilder::new(0x5EA2, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops())
        .seal_carrier(info)
        .build();
    let s = ino.fcntl_seals().expect("sealable memfd exposes a seal word");
    s.fetch_or(F_SEAL_SEAL, Ordering::AcqRel);
    assert!(s.load(Ordering::Acquire) & F_SEAL_SEAL != 0,
        "F_SEAL_SEAL latched; syscall F_ADD_SEALS now returns EPERM");
}

#[test]
fn non_sealable_inode_has_no_seals() {
    let ino: InodeRef = InodeBuilder::new(0x0000, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    assert!(ino.fcntl_seals().is_none(),
        "a non-sealable inode has no seal word (syscall layer → EINVAL)");
    assert!(ino.as_seal_carrier().is_none(), "no carrier attached");
}

fn exec_sealed_inode(mode: u16) -> InodeRef {
    let info = Arc::new(ShmemInfo { seals: AtomicU32::new(F_SEAL_EXEC) });
    InodeBuilder::new(
        0x5EA3,
        mk_mode(FileType::Regular, mode),
        default_inode_ops(),
        default_file_ops(),
    )
    .seal_carrier(info)
    .build()
}

#[test]
fn exec_seal_rejects_adding_or_removing_execute_bits() {
    for (before, after) in [(0o600, 0o700), (0o755, 0o644)] {
        let inode = exec_sealed_inode(before);
        let mut ia = Iattr { valid: ATTR_MODE, mode: after, ..Iattr::default() };
        assert_eq!(
            notify_change(&IDENTITY, &inode, &mut ia, &Cred::root()),
            Err(vfs::VfsError::Eperm),
        );
        assert_eq!(inode.perm(), Some(before));
    }
}

#[test]
fn exec_seal_allows_changes_that_preserve_execute_bits() {
    let inode = exec_sealed_inode(0o755);
    let mut ia = Iattr { valid: ATTR_MODE, mode: 0o711, ..Iattr::default() };
    notify_change(&IDENTITY, &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.perm(), Some(0o711));
}
