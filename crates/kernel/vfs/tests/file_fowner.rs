//! `f_owner` / `fown_struct` + `F_SETSIG`/`F_GETSIG` model on `File`
//! (file-D13). Pre-fix `File` carried only a bare `owner: AtomicI32` — no
//! captured owner credentials and no per-fd async-I/O signal, so SIGIO could
//! not be `kill_pid_info`-permission-checked against the requesting creds and
//! `F_SETSIG` had nowhere to land. These tests drive the real `File` accessors
//! and assert the Linux `f_setown`/`f_getown`/`f_setsig`/`send_sigio` shape.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Cred, Dentry, File, FileType, InodeRef, KResult, OpenFlags, VfsError};

/// Default `SIGIO` number (asm-generic, both arches) — the signal `fasync`
/// delivers when `F_SETSIG` was never called.
const SIGIO: i32 = 29;
/// A realtime signal a process might select via `F_SETSIG`.
const SIGRTMIN: i32 = 34;

struct Anon;
impl Inode for Anon {
    fn ino(&self) -> vfs::Ino { 7 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn file() -> Arc<File> {
    let ino: InodeRef = Arc::new(Anon);
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

/// A non-root cred used to prove the owner credentials are snapshotted.
fn user(uid: u32) -> Cred {
    let mut c = Cred::root();
    c.uid = uid;
    c
}

#[test]
fn fresh_file_has_no_owner_no_sig() {
    let f = file();
    assert_eq!(f.f_getown(), 0, "no F_SETOWN yet → target 0");
    assert_eq!(f.sig(), 0, "no F_SETSIG yet → 0 (default SIGIO)");
    assert_eq!(f.f_owner_creds(), (0, 0), "no owner creds captured yet");
}

#[test]
fn setown_records_target_and_creds() {
    let f = file();
    f.f_setown(4321, &user(1000));
    assert_eq!(f.f_getown(), 4321, "F_GETOWN returns the F_SETOWN target");
    assert_eq!(f.f_owner_creds(), (1000, 1000), "uid/euid snapshot from the setter's cred");
    // Negative target = process group, faithfully round-tripped.
    f.f_setown(-77, &user(1000));
    assert_eq!(f.f_getown(), -77, "negative target (-pgrp) preserved");
}

#[test]
fn setown_target_is_owner_field_used_by_syscall() {
    // The legacy `owner` field the fcntl shim writes/reads must stay in sync
    // with the model setter (single pid source of truth).
    let f = file();
    f.f_setown(99, &Cred::root());
    assert_eq!(f.owner.load(std::sync::atomic::Ordering::Acquire), 99);
}

#[test]
fn setsig_overrides_default_else_sigio() {
    let f = file();
    // Default: fasync delivers SIGIO when no F_SETSIG.
    assert_eq!(f.fasync_signal(SIGIO), SIGIO, "unset signum → default SIGIO");
    f.set_sig(SIGRTMIN);
    assert_eq!(f.sig(), SIGRTMIN, "F_GETSIG returns the F_SETSIG value");
    assert_eq!(f.fasync_signal(SIGIO), SIGRTMIN, "set signum overrides the default");
    // Reset to 0 restores the default (Linux F_SETSIG 0).
    f.set_sig(0);
    assert_eq!(f.fasync_signal(SIGIO), SIGIO, "F_SETSIG 0 restores default SIGIO");
}
