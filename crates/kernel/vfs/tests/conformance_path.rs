//! F721 host-oracle differential conformance — path family: open/openat
//! resolution ordering (missing parent, non-directory intermediate,
//! O_DIRECTORY, O_NOFOLLOW), mkdir EEXIST, rmdir ENOTEMPTY/ENOENT, rename
//! dir-onto-nonempty-dir, link/symlink EEXIST, unlink EISDIR, fstatat
//! AT_EMPTY_PATH/AT_SYMLINK_NOFOLLOW, readlink EINVAL.
//!
//! Oxide side drives the REAL, ungated `vfs::namei` resolver
//! (`path_lookup_path`) + permission gates (`may_open`, `may_create`,
//! `may_delete`, `may_rename`) exactly as the gated syscall shims
//! (`crates/kernel/syscalls/src/{083_mkdir,084_rmdir,086_link,087_unlink,
//! 088_symlink,089_readlink,082_rename}.rs`, all behind
//! `#[cfg(target_os = "oxide-kernel")]`) call them, over the writable
//! in-memory backend in `conformance_common` (the hosted-testable sibling,
//! `docs/53`). Where a gated file's remaining logic is a single trivial,
//! collaborator-free conditional (no fd table / uaccess / task lookup), it
//! is mirrored verbatim inline and the source line is cited — never a
//! reinvented approximation.

use conformance::corpus::{run_corpus, Case};
use conformance::oracle;
use conformance::outcome::Outcome;

use vfs::{Cred, CreateCtx, FileType, LookupFlags, VfsError, path_lookup_path};

#[path = "conformance_common/mod.rs"]
mod fx;

fn cred() -> Cred { Cred::root() }

// ---------------------------------------------------------- open family --

fn open_missing_parent_enoent() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("open-missing-parent");
    let host = oracle::open(&t.join("noexist").join("child"), libc::O_RDONLY, 0);

    let root = fx::build_root();
    let oxide = Outcome::from_oxide_rv(
        path_lookup_path(root.clone(), root, "/noexist/child", LookupFlags::default())
            .map(|_| 0).unwrap_or_else(errno_rv));
    (host, oxide)
}

/// Linux `path_init`/`link_path_walk`: a non-directory INTERMEDIATE
/// component is `ENOTDIR`, checked before the final component is even
/// consulted — so this fires even though the final component ("child")
/// also does not exist.
fn open_notdir_intermediate_enotdir() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("open-notdir-mid");
    std::fs::write(t.join("file"), b"x").unwrap();
    let host = oracle::open(&t.join("file").join("child"), libc::O_RDONLY, 0);

    let root_inode = fx::dir(2, &[("file", fx::regular_file(fx::next_ino()))]);
    let root = vfs::Dentry::new_root(root_inode);
    let oxide = Outcome::from_oxide_rv(
        path_lookup_path(root.clone(), root, "/file/child", LookupFlags::default())
            .map(|_| 0).unwrap_or_else(errno_rv));
    (host, oxide)
}

/// `O_DIRECTORY` on a regular file — real, ungated check:
/// `crates/kernel/vfs/src/namei/walk.rs:382`
/// (`if self.flags.directory && !matches!(.., Directory) { Enotdir }`),
/// which `257_openat.rs:260` feeds via `lookup.directory = (flags &
/// O_DIRECTORY) != 0`.
fn open_o_directory_on_file_enotdir() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("open-o-directory");
    std::fs::write(t.join("file"), b"x").unwrap();
    let host = oracle::open(&t.join("file"), libc::O_RDONLY | libc::O_DIRECTORY, 0);

    let root_inode = fx::dir(2, &[("file", fx::regular_file(fx::next_ino()))]);
    let root = vfs::Dentry::new_root(root_inode);
    let flags = LookupFlags { directory: true, ..Default::default() };
    let oxide = Outcome::from_oxide_rv(
        path_lookup_path(root.clone(), root, "/file", flags).map(|_| 0).unwrap_or_else(errno_rv));
    (host, oxide)
}

/// `O_NOFOLLOW` resolved onto a symlink — real, ungated check:
/// `crates/kernel/vfs/src/namei/permission.rs:173`
/// (`may_open`: `FileType::Symlink => Eloop`). The walk itself (with
/// `no_follow_final`) succeeds and returns the symlink inode as-is (Linux
/// `lookup_last` without `LOOKUP_FOLLOW`); `may_open` is the point that
/// turns "resolved to a symlink" into `ELOOP` for an actual open.
fn open_o_nofollow_on_symlink_eloop() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("open-o-nofollow");
    oracle::symlink("target-does-not-matter", &t.join("link"));
    let host = oracle::open(&t.join("link"), libc::O_RDONLY | libc::O_NOFOLLOW, 0);

    let root_inode = fx::dir(2, &[("link", fx::symlink_inode(fx::next_ino(), b"whatever"))]);
    let root = vfs::Dentry::new_root(root_inode);
    let flags = LookupFlags { no_follow_final: true, ..Default::default() };
    let oxide = Outcome::from_oxide_rv(
        match path_lookup_path(root.clone(), root, "/link", flags) {
            Err(e) => errno_rv(e),
            Ok(vp) => match vfs::may_open(&vp.inode, true, false, &cred()) {
                Ok(()) => 0,
                Err(e) => errno_rv(e),
            }
        });
    (host, oxide)
}

// ------------------------------------------------------------- mkdir -----

/// Sequenced from the real primitives in the ORDER `083_mkdir.rs` uses
/// (resolve parent → existence check → `may_create` → backend `mkdir`);
/// there is no callable raw-`&str` `do_mkdir_at` in that file (unlike
/// rmdir/unlink below) to call directly without also touching its
/// uaccess-bound `read_user_path` entry, so this lane sequences the real
/// building blocks itself rather than widening that file's cfg gate.
fn mkdir_eexist() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("mkdir-eexist");
    std::fs::create_dir(t.join("existing")).unwrap();
    let host = oracle::mkdir(&t.join("existing"), 0o755);

    let root_inode = fx::dir(2, &[("existing", fx::dir(fx::next_ino(), &[]))]);
    let root = vfs::Dentry::new_root(root_inode);
    let parent = path_lookup_path(root.clone(), root, "/existing", LookupFlags { parent: true, ..Default::default() }).unwrap();
    let oxide = Outcome::from_oxide_rv(match parent.inode.lookup("existing") {
        Ok(_) => -(VfsError::Eexist as i64),
        Err(VfsError::Enoent) => match vfs::may_create(&parent.inode, &cred()) {
            Ok(()) => parent.inode.mkdir("existing", 0o755, &CreateCtx::root()).map(|_| 0).unwrap_or_else(errno_rv),
            Err(e) => errno_rv(e),
        },
        Err(e) => errno_rv(e),
    });
    (host, oxide)
}

// ------------------------------------------------------------- rmdir -----

/// Sequenced in `084_rmdir.rs`'s real order: resolve parent → `may_delete`
/// (DAC + type gate, real ungated call) → backend `rmdir` (emptiness is a
/// BACKEND decision in Linux too — e.g. `ext4_rmdir`'s `ext4_empty_dir`,
/// not a `vfs::namei` gate).
fn rmdir_enotempty() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("rmdir-enotempty");
    std::fs::create_dir(t.join("d")).unwrap();
    std::fs::create_dir(t.join("d").join("child")).unwrap();
    let host = oracle::rmdir(&t.join("d"));

    let child_dir = fx::dir(fx::next_ino(), &[("child", fx::dir(fx::next_ino(), &[]))]);
    let root_inode = fx::dir(2, &[("d", child_dir)]);
    let root = vfs::Dentry::new_root(root_inode);
    let parent = path_lookup_path(root.clone(), root, "/d", LookupFlags { parent: true, ..Default::default() }).unwrap();
    let oxide = Outcome::from_oxide_rv(rmdir_seq(&parent, "d"));
    (host, oxide)
}

fn rmdir_enoent() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("rmdir-enoent");
    let host = oracle::rmdir(&t.join("missing"));

    let root_inode = fx::dir(2, &[]);
    let root = vfs::Dentry::new_root(root_inode);
    let parent = path_lookup_path(root.clone(), root, "/missing", LookupFlags { parent: true, ..Default::default() }).unwrap();
    let oxide = Outcome::from_oxide_rv(rmdir_seq(&parent, "missing"));
    (host, oxide)
}

fn rmdir_seq(parent: &vfs::VfsPath, name: &str) -> i64 {
    let victim = match parent.inode.lookup(name) {
        Ok(v) => Some(v),
        Err(VfsError::Enoent) => None,
        Err(e) => return errno_rv(e),
    };
    if let Some(v) = victim.as_ref() {
        if let Err(e) = vfs::namei::may_delete(&parent.inode, v, true, &cred()) { return errno_rv(e); }
    }
    match parent.inode.rmdir(name) { Ok(()) => 0, Err(e) => errno_rv(e) }
}

// ------------------------------------------------------------ rename -----

/// `RENAME_NOREPLACE`-less rename of one directory onto another, non-empty
/// one. `vfs::namei::may_rename` (real, ungated) allows it (type agreement:
/// dir↔dir); the backend `rename` op is where Linux rejects a non-empty
/// destination (matches the rmdir case above — same backend-owned
/// emptiness contract).
fn rename_dir_onto_nonempty_dir_enotempty() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("rename-nonempty");
    std::fs::create_dir(t.join("src")).unwrap();
    std::fs::create_dir(t.join("dst")).unwrap();
    std::fs::create_dir(t.join("dst").join("x")).unwrap();
    let host = oracle::rename(&t.join("src"), &t.join("dst"));

    let src = fx::dir(fx::next_ino(), &[]);
    let dst = fx::dir(fx::next_ino(), &[("x", fx::dir(fx::next_ino(), &[]))]);
    let root_inode = fx::dir(2, &[("src", src.clone()), ("dst", dst.clone())]);
    let oxide = Outcome::from_oxide_rv(
        match vfs::namei::may_rename(&root_inode, &src, &root_inode, Some(&dst), 0, true, &cred()) {
            Err(e) => errno_rv(e),
            Ok(()) => root_inode.rename_child("src", &root_inode, "dst", 0, &CreateCtx::root())
                .map(|_| 0).unwrap_or_else(errno_rv),
        });
    (host, oxide)
}

// -------------------------------------------------------- link/symlink ---

/// `086_link.rs`'s real order: resolve parent → `may_create` (no leaf
/// existence check at this layer!) → backend `link` — EEXIST surfaces from
/// the BACKEND, matching this fixture and (per Linux) a real filesystem's
/// own `->link`.
fn link_eexist() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("link-eexist");
    std::fs::write(t.join("target"), b"x").unwrap();
    std::fs::write(t.join("existing"), b"y").unwrap();
    let host = oracle::link(&t.join("target"), &t.join("existing"));

    let target = fx::regular_file(fx::next_ino());
    let root_inode = fx::dir(2, &[("target", target.clone()), ("existing", fx::regular_file(fx::next_ino()))]);
    let oxide = Outcome::from_oxide_rv(
        match vfs::may_create(&root_inode, &cred()) {
            Err(e) => errno_rv(e),
            Ok(()) => match vfs::may_link_source(&target, &cred()) {
                Err(e) => errno_rv(e),
                Ok(()) => root_inode.link_child(&target, "existing", &CreateCtx::root()).map(|_| 0).unwrap_or_else(errno_rv),
            }
        });
    (host, oxide)
}

/// `088_symlink.rs`'s real order DIFFERS from link: it checks
/// `child_exists` EXPLICITLY before `may_create`/backend `symlink`, so
/// EEXIST is caught one step earlier than link's (backend-only) EEXIST.
fn symlink_eexist() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("symlink-eexist");
    std::fs::write(t.join("existing"), b"y").unwrap();
    let host = oracle::symlink("whatever", &t.join("existing"));

    let root_inode = fx::dir(2, &[("existing", fx::regular_file(fx::next_ino()))]);
    let oxide = Outcome::from_oxide_rv(match root_inode.lookup("existing") {
        Ok(_) => -(VfsError::Eexist as i64),
        Err(VfsError::Enoent) => match vfs::may_create(&root_inode, &cred()) {
            Ok(()) => root_inode.symlink_child("existing", b"whatever", &CreateCtx::root()).map(|_| 0).unwrap_or_else(errno_rv),
            Err(e) => errno_rv(e),
        },
        Err(e) => errno_rv(e),
    });
    (host, oxide)
}

// -------------------------------------------------------------- unlink ---

/// `087_unlink.rs`'s real, ungated check: `may_delete(parent, victim,
/// isdir=false, cred)` (`permission.rs`: victim IS a dir while
/// `isdir=false` requested → `Eisdir`).
fn unlink_eisdir() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("unlink-eisdir");
    std::fs::create_dir(t.join("d")).unwrap();
    let host = oracle::unlink(&t.join("d"));

    let victim = fx::dir(fx::next_ino(), &[]);
    let root_inode = fx::dir(2, &[("d", victim.clone())]);
    let oxide = Outcome::from_oxide_rv(match vfs::namei::may_delete(&root_inode, &victim, false, &cred()) {
        Ok(()) => root_inode.unlink_child("d").map(|_| 0).unwrap_or_else(errno_rv),
        Err(e) => errno_rv(e),
    });
    (host, oxide)
}

// --------------------------------------------------------------- stat ----

fn fstatat_empty_path_ordering() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("fstatat-empty");
    std::fs::write(t.join("f"), b"x").unwrap();
    let fd = oracle::open_keep(&t.join("f"), libc::O_RDONLY, 0);
    let host_with_flag = oracle::fstatat_empty(fd, 0);
    let host_without_flag = oracle::fstatat_empty(fd, 0 /* AT_EMPTY_PATH always added by fstatat_empty */);
    oracle::close_raw(fd);
    let _ = host_without_flag; // host libc always needs AT_EMPTY_PATH for "" to work at all; the without-flag
                               // comparison point is the oxide-side LookupFlags::empty bit, exercised below.

    let root = fx::build_root();
    let f_dentry = vfs::Dentry::new_root(fx::regular_file(fx::next_ino()));
    let with_empty = path_lookup_path(f_dentry.clone(), root.clone(), "", LookupFlags { empty: true, ..Default::default() });
    let without_empty = path_lookup_path(f_dentry, root, "", LookupFlags::default());
    // AT_EMPTY_PATH set → resolves to the start itself (Ok); unset → ENOENT
    // on an empty pathname (`walk.rs`: `if path.is_empty() && !self.flags.empty { Enoent }`).
    let oxide_with = with_empty.is_ok();
    let oxide_without = matches!(without_empty, Err(VfsError::Enoent));
    let host_ok = host_with_flag.is_success();
    (Outcome::ok(host_ok as i64), Outcome::ok((oxide_with && oxide_without) as i64))
}

/// `AT_SYMLINK_NOFOLLOW` (`lstat`) reports the LINK itself;
/// its absence (`stat`) follows to the target — real `LookupFlags` gate in
/// `crates/kernel/vfs/src/namei/walk.rs` (`no_follow_final`/`follow`).
fn fstatat_symlink_nofollow_type_tag() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("fstatat-nofollow");
    std::fs::write(t.join("target"), b"x").unwrap();
    oracle::symlink("target", &t.join("link"));
    let host_lstat = oracle::stat_or_lstat_type_tag(&t.join("link"), false);
    let host_stat = oracle::stat_or_lstat_type_tag(&t.join("link"), true);

    let root_inode = fx::dir(2, &[("target", fx::regular_file(fx::next_ino())), ("link", fx::symlink_inode(fx::next_ino(), b"target"))]);
    let root = vfs::Dentry::new_root(root_inode);
    let nofollow = path_lookup_path(root.clone(), root.clone(), "/link", LookupFlags { no_follow_final: true, ..Default::default() }).unwrap();
    let follow = path_lookup_path(root.clone(), root, "/link", LookupFlags { follow: true, ..Default::default() }).unwrap();
    let oxide_lstat_tag = if matches!(nofollow.inode.file_type(), FileType::Symlink) { 1 } else { 2 };
    let oxide_stat_tag = if matches!(follow.inode.file_type(), FileType::Symlink) { 1 } else { 2 };
    let host_ok = host_lstat.is_success() && host_stat.is_success()
        && host_lstat.ret == 1 && host_stat.ret == 2;
    let oxide_ok = oxide_lstat_tag == 1 && oxide_stat_tag == 2;
    (Outcome::ok(host_ok as i64), Outcome::ok(oxide_ok as i64))
}

/// `089_readlink.rs`'s real, collaborator-free check
/// (`readlink_resolved`: `if !matches!(.., Symlink) { Einval }`, before any
/// buffer touch) — mirrored verbatim inline since it takes no fd
/// table/uaccess to reach.
fn readlink_einval_on_non_symlink() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("readlink-einval");
    std::fs::write(t.join("f"), b"x").unwrap();
    let host = oracle::readlink(&t.join("f")).0;

    let root_inode = fx::dir(2, &[("f", fx::regular_file(fx::next_ino()))]);
    let root = vfs::Dentry::new_root(root_inode);
    let vp = path_lookup_path(root.clone(), root, "/f", LookupFlags { no_follow_final: true, ..Default::default() }).unwrap();
    let oxide = if !matches!(vp.inode.file_type(), FileType::Symlink) { Outcome::err(libc::EINVAL) } else { unreachable!() };
    (host, oxide)
}

/// Placeholder body for the `skip: Some(..)` EXDEV row below — `run` is a
/// required field but `corpus::run_corpus` never invokes it for a skipped
/// case.
fn not_run() -> (Outcome, Outcome) { unreachable!("skipped case body must not run") }

fn errno_rv(e: VfsError) -> i64 {
    use syscall::errno::Errno;
    -((match e {
        VfsError::Eperm => Errno::Eperm, VfsError::Enoent => Errno::Enoent, VfsError::Eexist => Errno::Eexist,
        VfsError::Enotdir => Errno::Enotdir, VfsError::Eisdir => Errno::Eisdir, VfsError::Einval => Errno::Einval,
        VfsError::Enotempty => Errno::Enotempty, VfsError::Eloop => Errno::Eloop, VfsError::Eacces => Errno::Eacces,
        VfsError::Erofs => Errno::Erofs, VfsError::Exdev => Errno::Exdev, VfsError::Ebusy => Errno::Ebusy,
        _ => Errno::Eio,
    }).as_i32() as i64)
}

const CASES: &[Case] = &[
    Case { id: "open.missing_parent.enoent", known_divergence: None, skip: None, compare_ret_on_success: false, run: open_missing_parent_enoent },
    Case { id: "open.notdir_intermediate.enotdir", known_divergence: None, skip: None, compare_ret_on_success: false, run: open_notdir_intermediate_enotdir },
    Case { id: "open.o_directory_on_file.enotdir", known_divergence: None, skip: None, compare_ret_on_success: false, run: open_o_directory_on_file_enotdir },
    Case { id: "open.o_nofollow_on_symlink.eloop", known_divergence: None, skip: None, compare_ret_on_success: false, run: open_o_nofollow_on_symlink_eloop },
    Case { id: "mkdir.eexist", known_divergence: None, skip: None, compare_ret_on_success: false, run: mkdir_eexist },
    Case { id: "rmdir.enotempty", known_divergence: None, skip: None, compare_ret_on_success: false, run: rmdir_enotempty },
    Case { id: "rmdir.enoent", known_divergence: None, skip: None, compare_ret_on_success: false, run: rmdir_enoent },
    Case { id: "rename.dir_onto_nonempty_dir.enotempty", known_divergence: None, skip: None, compare_ret_on_success: false, run: rename_dir_onto_nonempty_dir_enotempty },
    Case { id: "rename.exdev_class", known_divergence: None, skip: Some("needs two real, distinctly-mounted host filesystems to trigger genuine cross-device EXDEV; not wired up in this lane"), compare_ret_on_success: false, run: not_run },
    Case { id: "link.eexist", known_divergence: None, skip: None, compare_ret_on_success: false, run: link_eexist },
    Case { id: "symlink.eexist", known_divergence: None, skip: None, compare_ret_on_success: false, run: symlink_eexist },
    Case { id: "unlink.eisdir", known_divergence: None, skip: None, compare_ret_on_success: false, run: unlink_eisdir },
    Case { id: "fstatat.at_empty_path.ordering", known_divergence: None, skip: None, compare_ret_on_success: true, run: fstatat_empty_path_ordering },
    Case { id: "fstatat.at_symlink_nofollow.type_tag", known_divergence: None, skip: None, compare_ret_on_success: true, run: fstatat_symlink_nofollow_type_tag },
    Case { id: "readlink.einval_on_non_symlink", known_divergence: None, skip: None, compare_ret_on_success: false, run: readlink_einval_on_non_symlink },
];

#[test]
fn path_family_corpus() {
    run_corpus(CASES);
}
