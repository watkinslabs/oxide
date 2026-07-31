//! Differential test: run the REAL `mkdir`/`rmdir`/`unlink`/`symlink`/`link`/
//! `mknod`/`readlink` on THIS machine's Linux kernel, then ask
//! `syscalls::path_ops_policy` what oxide would answer for the same fixture,
//! and require the two to agree. Nothing here is a remembered errno — every
//! expectation comes from the host syscall's own return.
//!
//! The policy module owns only the ORDER-sensitive leaf decisions, so each
//! case classifies its fixture the way the slot files do (last-component kind,
//! existence, trailing slash, victim type) and runs the same ladder. Cases
//! whose host verdict would come from a stage the policy does not own (DAC,
//! read-only mounts, cross-mount EXDEV) are deliberately absent — those are
//! covered by the `vfs` gate tests.

use std::path::Path;

use conformance::oracle::{self, TempDir};
use conformance::outcome::Outcome;
use syscalls::path_ops_policy::{
    check_create_leaf, check_create_leaf_kind, check_readlink_bufsiz, check_rmdir_leaf_kind,
    check_unlink_leaf_kind, check_unlink_trailing_slash, has_trailing_slash, readlink_copy_len,
    CreateKind, LastKind,
};

/// Classify a pathname's final component the way `resolve_leaf_at` does
/// (Linux `last_type`).
fn last_kind(raw: &str) -> LastKind {
    let t = raw.trim_end_matches('/');
    match t.rsplit('/').next().unwrap_or("") {
        ""   => LastKind::Root,
        "."  => LastKind::Dot,
        ".." => LastKind::Dotdot,
        _    => LastKind::Norm,
    }
}

fn stripped(raw: &str) -> &str {
    let t = raw.trim_end_matches('/');
    if t.is_empty() { "/" } else { t }
}
fn exists(raw: &str) -> bool { Path::new(stripped(raw)).symlink_metadata().is_ok() }
fn is_dir(raw: &str) -> bool { Path::new(stripped(raw)).symlink_metadata().is_ok_and(|m| m.is_dir()) }

fn e(x: syscall::errno::Errno) -> Outcome { Outcome::err(x.as_i32()) }

/// The oxide verdict for a create fixture already materialised on the host.
fn create_verdict(raw: &str, kind: CreateKind) -> Outcome {
    if let Err(x) = check_create_leaf_kind(last_kind(raw)) { return e(x); }
    if let Err(x) = check_create_leaf(exists(raw), has_trailing_slash(raw), kind) { return e(x); }
    Outcome::ok(0)
}

fn rmdir_verdict(raw: &str) -> Outcome {
    if let Err(x) = check_rmdir_leaf_kind(last_kind(raw)) { return e(x); }
    if !exists(raw) { return Outcome::err(libc::ENOENT); }
    // `may_delete`'s type agreement (its own unit tests pin the gate; here it
    // only completes the ladder so the host comparison is meaningful).
    if !is_dir(raw) { return Outcome::err(libc::ENOTDIR); }
    Outcome::ok(0)
}

fn unlink_verdict(raw: &str) -> Outcome {
    if let Err(x) = check_unlink_leaf_kind(last_kind(raw)) { return e(x); }
    if !exists(raw) { return Outcome::err(libc::ENOENT); }
    if let Err(x) = check_unlink_trailing_slash(has_trailing_slash(raw), is_dir(raw)) { return e(x); }
    // `may_delete`'s type agreement, as above.
    if is_dir(raw) { return Outcome::err(libc::EISDIR); }
    Outcome::ok(0)
}

// ---- create family: mkdir / symlink / link / mknod ------------------------

/// `mkdir` and the non-directory creates diverge on exactly one input: a
/// trailing slash. The host decides which way for both.
#[test]
fn create_leaf_matches_host_for_every_shape() {
    let t = TempDir::new("po-create");
    std::fs::create_dir(t.join("d")).unwrap();
    std::fs::write(t.join("f"), b"x").unwrap();
    let base = t.path().to_str().unwrap().to_string();

    for suffix in ["new", "new/", "d", "d/", "f", "f/", ".", "..", "d/.", "d/.."] {
        let p = format!("{base}/{suffix}");
        // mkdir — LOOKUP_DIRECTORY, so a trailing slash is agreeable.
        let oxide = create_verdict(&p, CreateKind::Dir);
        let host = oracle::mkdir(Path::new(&p), 0o755);
        assert!(host.same_errno_class(&oxide),
            "mkdir({p:?}) host={host:?} oxide={oxide:?}");
        if host.is_success() { std::fs::remove_dir(stripped(&p)).unwrap(); }

        // symlink — no LOOKUP_DIRECTORY, so a trailing slash suppresses create.
        let oxide = create_verdict(&p, CreateKind::NonDir);
        let host = oracle::symlink("target", Path::new(&p));
        assert!(host.same_errno_class(&oxide),
            "symlink(-> {p:?}) host={host:?} oxide={oxide:?}");
        if host.is_success() { std::fs::remove_file(stripped(&p)).unwrap(); }

        // link — same leaf rule as symlink; the source is a plain file.
        let oxide = create_verdict(&p, CreateKind::NonDir);
        let host = oracle::link(&t.join("f"), Path::new(&p));
        assert!(host.same_errno_class(&oxide),
            "link(f, {p:?}) host={host:?} oxide={oxide:?}");
        if host.is_success() { std::fs::remove_file(stripped(&p)).unwrap(); }

        // mknod of a FIFO — no privilege needed, same leaf rule.
        let oxide = create_verdict(&p, CreateKind::NonDir);
        let host = oracle::mknod(Path::new(&p), libc::S_IFIFO | 0o600, 0);
        assert!(host.same_errno_class(&oxide),
            "mknod(FIFO, {p:?}) host={host:?} oxide={oxide:?}");
        if host.is_success() { std::fs::remove_file(stripped(&p)).unwrap(); }
    }
}

/// The trailing-slash rule pinned on its own: the host must give a FREE name
/// under `foo/` a different errno for mkdir than for symlink.
#[test]
fn trailing_slash_splits_mkdir_from_symlink_on_the_host() {
    let t = TempDir::new("po-slash");
    let p = format!("{}/fresh/", t.path().to_str().unwrap());
    let sym = oracle::symlink("target", Path::new(&p));
    let dir = oracle::mkdir(Path::new(&p), 0o755);
    assert!(!sym.is_success(), "symlink to a slashed free name must fail: {sym:?}");
    assert!(dir.is_success(), "mkdir of a slashed free name must succeed: {dir:?}");
    assert!(sym.same_errno_class(&create_verdict(&p, CreateKind::NonDir)));
}

// ---- remove family: rmdir / unlink ---------------------------------------

#[test]
fn rmdir_leaf_matches_host_for_every_shape() {
    let t = TempDir::new("po-rmdir");
    let base = t.path().to_str().unwrap().to_string();
    for suffix in ["gone", "gone/", ".", "..", "e", "e/", "f", "f/"] {
        std::fs::create_dir_all(t.join("e")).unwrap();
        std::fs::write(t.join("f"), b"x").unwrap();
        let p = format!("{base}/{suffix}");
        let oxide = rmdir_verdict(&p);
        let host = oracle::rmdir(Path::new(&p));
        assert!(host.same_errno_class(&oxide), "rmdir({p:?}) host={host:?} oxide={oxide:?}");
        let _ = std::fs::remove_dir(t.join("e"));
        let _ = std::fs::remove_file(t.join("f"));
    }
}

#[test]
fn unlink_leaf_matches_host_for_every_shape() {
    let t = TempDir::new("po-unlink");
    let base = t.path().to_str().unwrap().to_string();
    for suffix in ["gone", "gone/", ".", "..", "f", "f/", "d", "d/"] {
        std::fs::write(t.join("f"), b"x").unwrap();
        std::fs::create_dir_all(t.join("d")).unwrap();
        let p = format!("{base}/{suffix}");
        let oxide = unlink_verdict(&p);
        let host = oracle::unlink(Path::new(&p));
        assert!(host.same_errno_class(&oxide), "unlink({p:?}) host={host:?} oxide={oxide:?}");
        let _ = std::fs::remove_file(t.join("f"));
        let _ = std::fs::remove_dir(t.join("d"));
    }
}

/// `file/` and `dir/` get DIFFERENT errnos from the same rule; confirm the
/// host really does split them so the policy's two-way branch is warranted.
#[test]
fn unlink_trailing_slash_errnos_differ_on_the_host() {
    let t = TempDir::new("po-uslash");
    std::fs::write(t.join("f"), b"x").unwrap();
    std::fs::create_dir(t.join("d")).unwrap();
    let base = t.path().to_str().unwrap().to_string();
    let f = oracle::unlink(Path::new(&format!("{base}/f/")));
    let d = oracle::unlink(Path::new(&format!("{base}/d/")));
    assert_ne!(f.errno, d.errno, "the victim's type must pick the errno: f={f:?} d={d:?}");
    assert!(f.same_errno_class(&unlink_verdict(&format!("{base}/f/"))));
    assert!(d.same_errno_class(&unlink_verdict(&format!("{base}/d/"))));
}

// ---- readlink -------------------------------------------------------------

#[test]
fn readlink_bufsiz_gate_matches_host() {
    let t = TempDir::new("po-readlink");
    let link = t.join("l");
    std::os::unix::fs::symlink("abcdefgh", &link).unwrap();
    for bufsiz in [i32::MIN, -4096, -1, 0, 1, 4, 8, 9, 4096] {
        let host = oracle::readlink_bufsiz(&link, bufsiz);
        let oxide = match check_readlink_bufsiz(bufsiz) {
            Err(x) => e(x),
            Ok(()) => Outcome::ok(readlink_copy_len("abcdefgh".len(), bufsiz) as i64),
        };
        assert_eq!(host, oxide, "readlink(bufsiz={bufsiz}) host={host:?} oxide={oxide:?}");
    }
}

/// A non-symlink is `EINVAL`, and the host proves the buffer gate runs FIRST:
/// a negative buffer on a regular file still reports the buffer's errno.
#[test]
fn readlink_bufsiz_gate_precedes_the_non_symlink_check() {
    let t = TempDir::new("po-readlink-order");
    let f = t.join("f");
    std::fs::write(&f, b"x").unwrap();
    let neg = oracle::readlink_bufsiz(&f, -1);
    let pos = oracle::readlink_bufsiz(&f, 64);
    assert_eq!(neg, e(syscall::errno::Errno::Einval));
    assert_eq!(pos.errno, libc::EINVAL, "a regular file is EINVAL too: {pos:?}");
    // Both are EINVAL on Linux, so the ordering claim is carried by the gate
    // returning without ever resolving the path — pinned in the policy unit
    // test; here we only confirm the host agrees on both inputs.
    assert!(neg.same_errno_class(&e(check_readlink_bufsiz(-1).unwrap_err())));
}
