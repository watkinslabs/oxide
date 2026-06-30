//! memfd seal word still works (inode-D42 placement refactor must not change
//! behavior). `InodeBuilder::seals(initial)` enables the seal word ONLY for a
//! sealable memfd; `fcntl_seals()` exposes it for F_GET_SEALS/F_ADD_SEALS. A
//! non-sealable inode returns `None` (the syscall layer maps that to EINVAL).
//!
//! NOTE: the Linux-faithful placement is `shmem_inode_info.seals` reached via a
//! `SHMEM_I()` (`i_private`) cast; that move is cross-lane (the tmpfs backend in
//! `fs/` owns `i_private`, and `vfs` cannot depend on `fs`). This test pins the
//! observable contract so the eventual relocation stays behavior-preserving.

use std::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::{FileType, InodeBuilder, InodeRef, default_inode_ops, default_file_ops, mk_mode};

const F_SEAL_WRITE: u32 = 0x0008;
const F_SEAL_SHRINK: u32 = 0x0002;

#[test]
fn sealable_inode_round_trips_seals() {
    let ino: InodeRef = InodeBuilder::new(0x5EA1, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).seals(0).build();
    let s = ino.fcntl_seals().expect("sealable memfd exposes a seal word");
    assert_eq!(s.load(Ordering::Acquire), 0, "initial seal word is empty");
    // F_ADD_SEALS semantics: OR new bits in.
    s.fetch_or(F_SEAL_WRITE, Ordering::AcqRel);
    s.fetch_or(F_SEAL_SHRINK, Ordering::AcqRel);
    assert_eq!(s.load(Ordering::Acquire), F_SEAL_WRITE | F_SEAL_SHRINK,
        "added seals accumulate (F_GET_SEALS would report both)");
}

#[test]
fn non_sealable_inode_has_no_seals() {
    let ino: InodeRef = InodeBuilder::new(0x0000, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    assert!(ino.fcntl_seals().is_none(),
        "a non-sealable inode has no seal word (syscall layer → EINVAL)");
}
