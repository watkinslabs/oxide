//! `File::set_fl` — the `fcntl(F_SETFL)` work fn (Linux `setfl`, `fs/fcntl.c`).
//! `F_SETFL` may change ONLY the status flags `O_APPEND`/`O_NONBLOCK`/
//! `O_DIRECT`/`O_NOATIME` on an already-open file description; the access mode
//! (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) and the creation-time flags
//! (`O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_CLOEXEC`/`O_DIRECTORY`) are fixed at open
//! and must be preserved no matter what the caller passes in `arg`.
//!
//! Pre-fix shape: the syscall shim recomputed the mask inline with a wrong
//! constant (`0o4_004_000 | 0o4000`) that DROPPED `O_APPEND` and added a stray
//! `__O_SYNC` bit, and the raw `File::set_flags` setter would clobber the
//! access mode outright. `set_fl` centralizes the correct `SETFL_MASK` in the
//! VFS so the access mode and creation flags survive and `O_APPEND` is settable.

use std::sync::Arc;

use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

/// `O_DIRECT` / `O_NOATIME` are settable status flags not declared in
/// `OpenFlags`; set them as raw bits exactly how the syscall layer forwards
/// the user's `arg` word.
const O_DIRECT:  u32 = 0o40000;
const O_NOATIME: u32 = 0o1000000;

/// Minimal regular inode; `set_fl` touches no I/O so the body is unused.
fn reg_inode() -> InodeRef {
    InodeBuilder::new(0x5F, mk_mode(FileType::Regular, 0), default_inode_ops(), default_file_ops()).build()
}

fn file(flags: u32) -> Arc<File> {
    let ino: InodeRef = reg_inode();
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, d, OpenFlags::from_bits_retain(flags))
}

/// Access mode is immutable: opening O_RDWR and asking F_SETFL for O_RDONLY
/// (access bits 0) leaves O_RDWR intact. Pre-fix `set_flags` would have stored
/// the bare arg and silently demoted the description to read-only.
#[test]
fn access_mode_preserved() {
    let f = file(OpenFlags::O_RDWR.bits());
    let out = f.set_fl(OpenFlags::from_bits_retain(OpenFlags::O_NONBLOCK.bits())); // access bits 0
    assert!(out.contains(OpenFlags::O_RDWR), "O_RDWR access mode must survive F_SETFL");
    assert!(out.contains(OpenFlags::O_NONBLOCK), "O_NONBLOCK must be set");
    assert_eq!(f.flags(), out, "flags() reflects the new f_flags");
}

/// Creation-time flags (O_CLOEXEC here, plus O_CREAT/O_TRUNC) are fixed at open
/// and ignored by F_SETFL: passing them in `arg` does NOT set them, and an
/// already-present one is preserved (it lies outside SETFL_MASK).
#[test]
fn creation_flags_ignored_and_preserved() {
    let f = file(OpenFlags::O_WRONLY.bits() | OpenFlags::O_CLOEXEC.bits());
    // arg requests O_CREAT|O_TRUNC|O_APPEND; only O_APPEND is in SETFL_MASK.
    let arg = OpenFlags::O_CREAT.bits() | OpenFlags::O_TRUNC.bits() | OpenFlags::O_APPEND.bits();
    let out = f.set_fl(OpenFlags::from_bits_retain(arg));
    assert!(out.contains(OpenFlags::O_APPEND), "O_APPEND is settable");
    assert!(!out.contains(OpenFlags::O_CREAT), "O_CREAT must not be settable via F_SETFL");
    assert!(!out.contains(OpenFlags::O_TRUNC), "O_TRUNC must not be settable via F_SETFL");
    assert!(out.contains(OpenFlags::O_CLOEXEC), "pre-existing O_CLOEXEC preserved (outside SETFL_MASK)");
    assert!(out.contains(OpenFlags::O_WRONLY), "access mode preserved");
}

/// O_APPEND is settable and clearable; the round-trip leaves the access mode
/// untouched. This is the bit the old shim mask dropped entirely.
#[test]
fn append_settable_and_clearable() {
    let f = file(OpenFlags::O_RDWR.bits() | OpenFlags::O_APPEND.bits());
    // Clear all status flags: arg = access mode only (0 here for status bits).
    let out = f.set_fl(OpenFlags::from_bits_retain(OpenFlags::O_RDWR.bits()));
    assert!(!out.contains(OpenFlags::O_APPEND), "O_APPEND cleared when arg omits it");
    // Set it back.
    let out = f.set_fl(OpenFlags::from_bits_retain(OpenFlags::O_APPEND.bits()));
    assert!(out.contains(OpenFlags::O_APPEND), "O_APPEND re-set");
    assert!(out.contains(OpenFlags::O_RDWR), "access mode never changed");
}

/// O_DIRECT and O_NOATIME (raw bits, not in OpenFlags) are inside SETFL_MASK and
/// must be both settable and preservable through subsequent F_SETFL calls.
#[test]
fn direct_and_noatime_settable() {
    let f = file(OpenFlags::O_RDONLY.bits());
    let out = f.set_fl(OpenFlags::from_bits_retain(O_DIRECT | O_NOATIME));
    assert_eq!(out.bits() & O_DIRECT, O_DIRECT, "O_DIRECT settable");
    assert_eq!(out.bits() & O_NOATIME, O_NOATIME, "O_NOATIME settable");
    // A later F_SETFL that only toggles O_NONBLOCK must NOT clear them? In Linux
    // SETFL overwrites the whole masked region, so omitting O_DIRECT clears it.
    let out = f.set_fl(OpenFlags::from_bits_retain(OpenFlags::O_NONBLOCK.bits()));
    assert_eq!(out.bits() & O_DIRECT, 0, "omitting O_DIRECT in arg clears it (whole-region overwrite)");
    assert!(out.contains(OpenFlags::O_NONBLOCK), "O_NONBLOCK set");
}
