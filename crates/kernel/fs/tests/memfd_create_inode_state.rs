//! What `memfd_create(2)` actually HANDS BACK, not just what its flag ladder
//! computes. `memfd_flags::setup` was covered by unit tests; nothing asserted
//! that the derived seal word, inode mode, ownership, address_space and
//! rendered path reach a real tmpfs inode — the state `fcntl(F_GET_SEALS)`,
//! `fstat` and `readlink /proc/self/fd/N` report.
//!
//! The slot file is `#![cfg(target_os = "oxide-kernel")]`, so this test
//! composes the same objects the slot composes, from the same ungated policy
//! module, and asserts the result.

// The included production modules carry surface this test does not drive.
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::{CreateCtx, FileType, InodeRef};

#[path = "../../syscalls/src/memfd_flags.rs"]
mod memfd_flags;
// This fixture includes the production owner but exercises only its memfd table.
#[allow(unused_imports)]
#[path = "../../syscalls/src/anon_dname.rs"]
mod anon_dname;

use memfd_flags::{sanitize_flags, setup, MemfdSetup, MEMFD_NOEXEC_SCOPE_EXEC, MEMFD_PERM,
    MEMFD_PERM_NOEXEC, MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_EXEC, MFD_NAME_PREFIX,
    MFD_NOEXEC_SEAL, F_SEAL_EXEC, F_SEAL_SEAL};

const CREATOR_UID: u32 = 4242;
const CREATOR_GID: u32 = 91;

/// Exactly the object graph `sys_memfd_create` builds after `setup()`:
/// a sealable tmpfs inode carrying the derived seal word, permission bits and
/// creator ownership, behind a pseudo dentry with the memfd `d_dname`.
fn build_memfd(name: &str, flags: u32) -> (MemfdSetup, InodeRef, Arc<vfs::Dentry>) {
    let eff = sanitize_flags(flags, MEMFD_NOEXEC_SCOPE_EXEC).expect("flags accepted");
    let st = setup(eff);
    assert!(!st.hugetlb, "this fixture builds the shmem-backed memfd only");
    let inode = fs::tmpfs::tmpfs_sealable_file();
    inode.fcntl_seals().expect("every memfd carries the seal word")
        .store(st.seals, Ordering::Release);
    inode.set_perm(st.perm).expect("memfd inode mode");
    inode.set_owner(CREATOR_UID, CREATOR_GID).expect("memfd inode owner");
    let mut full = alloc::vec::Vec::from(MFD_NAME_PREFIX);
    full.extend_from_slice(name.as_bytes());
    let path = vfs::path_from_bytes(&full);
    let dentry = vfs::dcache::d_alloc_pseudo(&path, inode.clone(), &anon_dname::MEMFD_OPS);
    (st, inode, dentry)
}

// EVERY memfd carries the seal word, including one created without
// MFD_ALLOW_SEALING: such a file is not "unsealable", it is born holding
// F_SEAL_SEAL, so F_GET_SEALS reads 1 rather than failing.
#[test]
fn a_plain_memfd_reports_seal_seal_rather_than_no_seal_word() {
    let (st, inode, _d) = build_memfd("plain", 0);
    assert_eq!(st.seals, F_SEAL_SEAL);
    assert_eq!(inode.fcntl_seals().expect("seal word").load(Ordering::Acquire), F_SEAL_SEAL);
}

// MFD_ALLOW_SEALING is the flag that clears F_SEAL_SEAL; the file starts with
// no seals at all and F_ADD_SEALS can proceed.
#[test]
fn allow_sealing_starts_the_file_with_an_empty_seal_word() {
    let (st, inode, _d) = build_memfd("sealable", MFD_ALLOW_SEALING);
    assert_eq!(st.seals, 0);
    assert_eq!(inode.fcntl_seals().expect("seal word").load(Ordering::Acquire), 0);
}

// MFD_NOEXEC_SEAL enables sealing AND applies F_SEAL_EXEC immediately AND
// strips the execute bits — all three, on the real inode, without
// MFD_ALLOW_SEALING being passed.
#[test]
fn noexec_seal_reaches_the_inode_as_both_a_seal_and_a_mode_change() {
    let (st, inode, _d) = build_memfd("noexec", MFD_NOEXEC_SEAL);
    assert_eq!(st.seals, F_SEAL_EXEC);
    assert_eq!(inode.fcntl_seals().expect("seal word").load(Ordering::Acquire), F_SEAL_EXEC);
    assert_eq!(inode.perm().expect("memfd inode has mode bits"), MEMFD_PERM_NOEXEC);
    assert_eq!((inode.perm().expect("memfd inode has mode bits") & 0o111), 0, "no execute bit survives MFD_NOEXEC_SEAL");
}

// A memfd inode is born 0777, not the 0644 the underlying tmpfs constructor
// uses — the syscall overrides it. MFD_EXEC keeps the execute bits.
#[test]
fn a_memfd_inode_is_born_world_rwx() {
    for flags in [0, MFD_EXEC, MFD_ALLOW_SEALING, MFD_CLOEXEC] {
        let (_st, inode, _d) = build_memfd("mode", flags);
        assert_eq!(inode.perm().expect("memfd inode has mode bits"), MEMFD_PERM, "flags {flags:#x}");
        assert_eq!((inode.perm().expect("memfd inode has mode bits") & 0o111), 0o111, "flags {flags:#x}");
    }
}

// The file belongs to its creator's fsuid/fsgid, which is what fstat reports —
// not to root, and not to the tmpfs constructor's 0/0 default.
#[test]
fn a_memfd_belongs_to_its_creator() {
    let (_st, inode, _d) = build_memfd("owner", 0);
    assert_eq!(inode.uid(), Some(CREATOR_UID));
    assert_eq!(inode.gid(), Some(CREATOR_GID));
}

// A memfd is a regular file with an address_space, so it can be mmap'd,
// truncated and read; and it starts empty.
#[test]
fn a_memfd_is_an_empty_mappable_regular_file() {
    let (_st, inode, _d) = build_memfd("shape", MFD_ALLOW_SEALING);
    assert_eq!(inode.file_type(), FileType::Regular);
    assert_eq!(inode.size(), 0);
    assert!(inode.i_mapping().is_some(), "a memfd must be mappable");
}

// `readlink /proc/self/fd/N` renders `/memfd:<name> (deleted)`: the `memfd:`
// prefix is part of the name, and the file is reported as unlinked because it
// never had a directory entry.
#[test]
fn the_rendered_path_carries_the_prefix_and_the_deleted_marker() {
    let (_st, _inode, dentry) = build_memfd("cache", 0);
    assert_eq!(dentry.d_dname().expect("memfd dentry renders through d_dname"), "/memfd:cache (deleted)");
}

// An empty name is legal and renders as the bare prefix.
#[test]
fn an_empty_name_is_legal() {
    let (_st, _inode, dentry) = build_memfd("", 0);
    assert_eq!(dentry.d_dname().expect("memfd dentry renders through d_dname"), "/memfd: (deleted)");
}

// Two memfds are independent inodes with independent seal words — sealing one
// must not seal the other.
#[test]
fn two_memfds_do_not_share_state() {
    let (_a, ia, _da) = build_memfd("one", MFD_ALLOW_SEALING);
    let (_b, ib, _db) = build_memfd("two", MFD_ALLOW_SEALING);
    assert_ne!(ia.ino(), ib.ino());
    ia.fcntl_seals().expect("seal word").store(F_SEAL_EXEC, Ordering::Release);
    assert_eq!(ib.fcntl_seals().expect("seal word").load(Ordering::Acquire), 0);
}

// The tmpfs root's own files are NOT sealable: the seal word belongs to memfd
// inodes, so F_ADD_SEALS on an ordinary tmpfs file has no word to act on.
#[test]
fn an_ordinary_tmpfs_file_carries_no_seal_word() {
    let fs = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("memfd-audit"));
    let ino = fs.root_inode().create_child("plain", 0o644, &CreateCtx::root()).expect("create");
    assert!(ino.fcntl_seals().is_none());
}
