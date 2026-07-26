//! fdtable: two-phase fd allocation — `get_unused_fd_flags` reserve,
//! `fd_install` publish, `put_unused_fd` rollback (Linux open path:
//! `fd = get_unused_fd_flags(flags); file = do_filp_open(...);
//!  if (IS_ERR(file)) put_unused_fd(fd); else fd_install(fd, file);`).
//!
//! Invariants under test:
//!   - a reserved fd's `open_fds` bit is set, so a concurrent allocation
//!     (the `CLONE_FILES`-shared-table case) never hands out the same fd
//!     while the open is still in flight;
//!   - `get(fd)` yields EBADF in the reserved-but-uninstalled window
//!     (`files[fd] == None`), and succeeds only after `fd_install`;
//!   - `O_CLOEXEC` is applied atomically at reserve time, not after (though
//!     `cloexec()` itself reports Ebadf for a still-reserved fd, same as
//!     `get()` — the bit is set but not query-visible until `fd_install`);
//!   - `put_unused_fd` rolls the reservation (and its cloexec bit) back
//!     so the fd is reusable, dropping no file.
//!
//! No global state — each test owns a fresh `FdTable`, no serial guard.

use std::sync::Arc;

use vfs::{InodeBuilder, default_file_ops, default_inode_ops, mk_mode};
use vfs::{Dentry, FdTable, File, FileType, InodeRef, OpenFlags, VfsError, FD_TABLE_MAX};

fn mk_inode() -> InodeRef {
    InodeBuilder::new(0x1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = mk_inode();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// Reserve, observe the EBADF window, install, observe the file.
#[test]
fn reserve_then_install_round_trip() {
    let t = FdTable::new();
    let fd = t.get_unused_fd_flags(OpenFlags::empty(), FD_TABLE_MAX).unwrap();
    assert_eq!(fd, 0, "first reservation takes the lowest fd");
    // Reserved-but-uninstalled: visible to the allocator, not as a file.
    assert_eq!(t.get(fd).err(), Some(VfsError::Ebadf),
        "a reserved fd has no file yet → EBADF");
    assert!(!t.live_fds().contains(&fd),
        "a reserved fd is not a live (procfs-visible) fd until installed");
    t.fd_install(fd, mk_file());
    assert!(t.get(fd).is_ok(), "after fd_install the file resolves");
    assert!(t.live_fds().contains(&fd), "installed fd is now live");
}

/// The reservation blocks a concurrent allocator from reusing the fd —
/// the whole point of the two-phase split (the open may sleep between
/// reserve and install).
#[test]
fn reservation_blocks_concurrent_alloc() {
    let t = FdTable::new();
    let reserved = t.get_unused_fd_flags(OpenFlags::empty(), FD_TABLE_MAX).unwrap();
    let other = t.alloc(mk_file()).unwrap();
    assert_ne!(reserved, other, "alloc must skip the in-flight reservation");
    assert_eq!(other, 1, "alloc lands at the next free fd above the reservation");
    t.fd_install(reserved, mk_file());
    assert!(t.get(reserved).is_ok());
    assert!(t.get(other).is_ok());
}

/// O_CLOEXEC is set at reserve time and survives the install — no
/// post-install set_cloexec, matching `get_unused_fd_flags(O_CLOEXEC)`.
#[test]
fn reserve_sets_cloexec_atomically() {
    let t = FdTable::new();
    let fd = t.get_unused_fd_flags(OpenFlags::O_CLOEXEC, FD_TABLE_MAX).unwrap();
    // `cloexec()` gates on `!is_reserved` (like `get`/`set_cloexec`) — a
    // reserved-but-unpublished fd isn't a valid open descriptor yet, so it
    // reports Ebadf, not the bit it was reserved with. The bit itself is
    // still set internally at reserve time (proven below: it survives
    // fd_install without a separate set_cloexec call).
    assert_eq!(t.cloexec(fd), Err(VfsError::Ebadf), "reserved-but-uninstalled fd is not query-visible");
    t.fd_install(fd, mk_file());
    assert!(t.cloexec(fd).unwrap(), "fd_install preserves the reserve-time cloexec bit");

    // Without the flag the bit stays clear (install first — cloexec() is
    // Ebadf for a still-reserved fd, same gate as above).
    let plain = t.get_unused_fd_flags(OpenFlags::empty(), FD_TABLE_MAX).unwrap();
    t.fd_install(plain, mk_file());
    assert!(!t.cloexec(plain).unwrap(), "no O_CLOEXEC → fd starts non-cloexec");
}

/// put_unused_fd rolls the reservation back: the fd and its cloexec bit
/// are free again, and a subsequent alloc reuses that lowest fd.
#[test]
fn put_unused_fd_rolls_back_reservation() {
    let t = FdTable::new();
    let fd = t.get_unused_fd_flags(OpenFlags::O_CLOEXEC, FD_TABLE_MAX).unwrap();
    assert_eq!(fd, 0);
    t.put_unused_fd(fd);
    // Slot reusable, cloexec residue gone.
    let reused = t.alloc(mk_file()).unwrap();
    assert_eq!(reused, 0, "released reservation frees the lowest fd for reuse");
    assert!(!t.cloexec(reused).unwrap(), "put_unused_fd cleared the stale cloexec bit");
}

/// The soft limit applies to the reserve path too: a limit of 0 admits
/// no fd (EMFILE), mirroring `alloc_limit`.
#[test]
fn get_unused_fd_respects_soft_limit() {
    let t = FdTable::new();
    assert_eq!(t.get_unused_fd_flags(OpenFlags::empty(), 0), Err(VfsError::Emfile),
        "RLIMIT_NOFILE soft limit 0 rejects every reservation");
    const N: usize = 4;
    for expect in 0..N {
        let fd = t.get_unused_fd_flags(OpenFlags::empty(), N).unwrap();
        assert_eq!(fd, expect as i32);
        t.fd_install(fd, mk_file());
    }
    assert_eq!(t.get_unused_fd_flags(OpenFlags::empty(), N), Err(VfsError::Emfile),
        "the N-th reservation at soft limit N is EMFILE");
}
