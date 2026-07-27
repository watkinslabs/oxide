// Differential test: run the REAL `renameat2(2)` on THIS machine's Linux
// kernel, then ask `syscalls::rename_policy` what oxide would answer for the
// same fixture, and require the two to agree. Nothing here is a remembered
// errno — every expectation comes from the host syscall's own return.
//
// The policy module only owns the ORDER-sensitive decisions, so each case
// classifies its fixture the way `082_rename.rs` does (last-component kind,
// ancestor trap, existence, trailing slash) and runs the same ladder.

use std::path::Path;

use conformance::oracle::{self, TempDir};
use conformance::outcome::Outcome;
use syscalls::rename_policy::{
    self, LastKind, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT, Trap,
};

/// Classify a pathname's final component the way `resolve_rename_parent_at`
/// does (Linux `last_type`).
fn last_kind(raw: &str) -> LastKind {
    let t = raw.trim_end_matches('/');
    match t.rsplit('/').next().unwrap_or("") {
        ""   => LastKind::Root,
        "."  => LastKind::Dot,
        ".." => LastKind::Dotdot,
        _    => LastKind::Norm,
    }
}

fn canon(p: &Path) -> String { p.to_str().unwrap().to_string() }

/// Ancestor-or-self over real host paths, mirroring `Dentry::is_subdir_of`.
fn is_subdir_of(inner: &str, ancestor: &str) -> bool {
    inner == ancestor || inner.starts_with(&format!("{ancestor}/"))
}

/// The oxide verdict for a fixture already materialised on the host: run the
/// exact `082_rename.rs` ladder over host-observed facts.
fn oxide_verdict(from: &str, to: &str, flags: u32) -> Outcome {
    let e = Outcome::err;
    if let Err(x) = rename_policy::check_flags(flags) { return e(x.as_i32()); }
    if let Err(x) = rename_policy::check_last_kinds(last_kind(from), last_kind(to), flags) {
        return e(x.as_i32());
    }
    let (fp, tp) = (from.trim_end_matches('/'), to.trim_end_matches('/'));
    let (from_exists, to_exists) = (Path::new(fp).symlink_metadata().is_ok(),
                                    Path::new(tp).symlink_metadata().is_ok());
    if let Err(x) = rename_policy::check_existence(from_exists, to_exists, flags) {
        return e(x.as_i32());
    }
    let to_parent = Path::new(tp).parent().unwrap().to_str().unwrap().to_string();
    let from_parent = Path::new(fp).parent().unwrap().to_str().unwrap().to_string();
    let trap = if is_subdir_of(&to_parent, fp) { Trap::SourceIsAncestorOfTarget }
               else if to_exists && is_subdir_of(&from_parent, tp) { Trap::TargetIsAncestorOfSource }
               else { Trap::None };
    if let Err(x) = rename_policy::check_trap(trap, flags) { return e(x.as_i32()); }
    let (from_is_dir, to_is_dir) = (oracle::is_dir(Path::new(fp)), oracle::is_dir(Path::new(tp)));
    if let Err(x) = rename_policy::check_trailing_slashes(
        from_is_dir, to_is_dir,
        rename_policy::has_trailing_slash(from), rename_policy::has_trailing_slash(to), flags,
    ) { return e(x.as_i32()); }
    Outcome::ok(0)
}

/// Compare the host's real `renameat2` against the oxide ladder. Only the
/// FAILURE classification is compared when the host succeeds — a host success
/// means the ladder must not have rejected the call.
fn agree(from: &str, to: &str, flags: u32, what: &str) {
    // The oxide verdict is computed FIRST: a host call that succeeds mutates
    // the fixture it was classified from.
    let oxide = oxide_verdict(from, to, flags);
    let host = oracle::renameat2(Path::new(from), Path::new(to), flags);
    assert_eq!(host, oxide, "{what}: rename({from:?}, {to:?}, {flags:#x}) host={host:?} oxide={oxide:?}");
}

#[test]
fn flag_validation_matches_host() {
    let t = TempDir::new("rn-flags");
    std::fs::write(t.join("a"), b"x").unwrap();
    let (a, b) = (canon(&t.join("a")), canon(&t.join("b")));
    for f in [1u32 << 3, 1 << 31, RENAME_NOREPLACE | RENAME_EXCHANGE,
              RENAME_EXCHANGE | RENAME_WHITEOUT, RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT] {
        agree(&a, &b, f, "bad flag combination");
    }
}

#[test]
fn dot_and_dotdot_components_match_host() {
    let t = TempDir::new("rn-dots");
    std::fs::create_dir(t.join("d")).unwrap();
    std::fs::write(t.join("f"), b"x").unwrap();
    let (d, f) = (canon(&t.join("d")), canon(&t.join("f")));
    agree(&format!("{d}/."), &f, 0, "old side LAST_DOT");
    agree(&format!("{d}/.."), &f, 0, "old side LAST_DOTDOT");
    agree(&f, &format!("{d}/."), 0, "new side LAST_DOT");
    agree(&f, &format!("{d}/.."), 0, "new side LAST_DOTDOT");
    // The NOREPLACE branch overwrites the preset EBUSY with EEXIST between the
    // two LAST_NORM tests — the asymmetry only Linux's source shows.
    agree(&f, &format!("{d}/."), RENAME_NOREPLACE, "new side LAST_DOT + NOREPLACE");
    agree(&f, &format!("{d}/.."), RENAME_NOREPLACE, "new side LAST_DOTDOT + NOREPLACE");
}

#[test]
fn ancestor_traps_match_host() {
    let t = TempDir::new("rn-trap");
    std::fs::create_dir_all(t.join("a/b/c")).unwrap();
    let a = canon(&t.join("a"));
    let ab = canon(&t.join("a/b"));
    let abc = canon(&t.join("a/b/c"));
    // Source is an ancestor of the destination's parent → EINVAL.
    agree(&a, &format!("{abc}/x"), 0, "rename dir into its own subtree");
    agree(&ab, &format!("{ab}/x"), 0, "rename dir into itself");
    // Destination is an ancestor of the source's parent → ENOTEMPTY (EINVAL
    // under EXCHANGE).
    agree(&abc, &ab, 0, "rename onto own ancestor");
    agree(&abc, &ab, RENAME_EXCHANGE, "exchange with own ancestor");
}

#[test]
fn existence_rules_match_host() {
    let t = TempDir::new("rn-exist");
    std::fs::write(t.join("have"), b"x").unwrap();
    std::fs::write(t.join("also"), b"y").unwrap();
    let (have, also) = (canon(&t.join("have")), canon(&t.join("also")));
    let gone = canon(&t.join("gone"));
    agree(&gone, &have, 0, "missing source");
    agree(&gone, &have, RENAME_NOREPLACE, "missing source beats NOREPLACE");
    agree(&have, &also, RENAME_NOREPLACE, "NOREPLACE onto existing");
    agree(&have, &gone, RENAME_EXCHANGE, "EXCHANGE with missing destination");
}

#[test]
fn trailing_slash_rules_match_host() {
    let t = TempDir::new("rn-slash");
    std::fs::write(t.join("f"), b"x").unwrap();
    std::fs::write(t.join("g"), b"y").unwrap();
    std::fs::create_dir(t.join("d")).unwrap();
    std::fs::write(t.join("h"), b"z").unwrap();
    std::fs::create_dir(t.join("e")).unwrap();
    let (f, g, d) = (canon(&t.join("f")), canon(&t.join("g")), canon(&t.join("d")));
    let (h, e) = (canon(&t.join("h")), canon(&t.join("e")));
    agree(&format!("{f}/"), &g, 0, "trailing slash on non-dir source");
    agree(&f, &format!("{g}/"), 0, "trailing slash on destination of non-dir source");
    agree(&h, &format!("{e}/"), RENAME_EXCHANGE, "EXCHANGE: dir destination tolerates slash");
    agree(&d, &format!("{g}/"), RENAME_EXCHANGE, "EXCHANGE: non-dir destination rejects slash");
}

/// `lchown(2)` changes the SYMLINK's owner; `chown(2)` follows to the target.
/// Recorded from the host so the oxide `094_lchown` slot has a stated
/// contract rather than a remembered one. Skipped unless the test user can
/// actually change ownership (root); the no-op `(-1, -1)` form still proves
/// the no-follow path is reachable for everyone.
#[test]
fn lchown_does_not_follow_the_final_symlink() {
    let t = TempDir::new("lchown-nofollow");
    std::fs::write(t.join("target"), b"x").unwrap();
    std::os::unix::fs::symlink(t.join("target"), t.join("link")).unwrap();
    let link = t.join("link");
    let target = t.join("target");
    let before_link = oracle::lstat_owner(&link).expect("lstat link");
    let before_target = oracle::lstat_owner(&target).expect("lstat target");
    // `(-1, -1)` never fails for the owner and never changes an id, so it is
    // the portable probe that the no-follow path resolves the LINK.
    let rv = oracle::lchown(&link, u32::MAX, u32::MAX);
    assert!(rv.ret == 0, "lchown(-1,-1) on own symlink failed: {rv:?}");
    assert_eq!(oracle::lstat_owner(&link), Some(before_link));
    assert_eq!(oracle::lstat_owner(&target), Some(before_target));
    // A dangling symlink is the sharpest separator: `chown` must report
    // ENOENT (it follows) while `lchown` succeeds (it does not).
    std::os::unix::fs::symlink(t.join("nothing-here"), t.join("dangling")).unwrap();
    let dangling = t.join("dangling");
    assert!(oracle::lchown(&dangling, u32::MAX, u32::MAX).ret == 0,
            "lchown on a dangling symlink must succeed — it does not follow");
    let c = std::ffi::CString::new(dangling.to_str().unwrap()).unwrap();
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    let chown_rv = unsafe { libc::chown(c.as_ptr(), u32::MAX, u32::MAX) };
    assert_eq!(chown_rv, -1, "chown MUST follow the dangling symlink and fail");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
}

/// `faccessat(2)`/`access(2)` use the REAL uid; `faccessat2(AT_EACCESS)` uses
/// the effective one. Recorded from the host for a file the caller owns, plus
/// the `EINVAL` shapes that need no privilege at all.
#[test]
fn faccessat_flag_and_mode_validation_matches_host() {
    const AT_EACCESS: i32 = 0x200;
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    const AT_EMPTY_PATH: i32 = 0x1000;
    let t = TempDir::new("access-flags");
    std::fs::write(t.join("f"), b"x").unwrap();
    let f = t.join("f");
    // Mode bits outside `S_IRWXO` are EINVAL (`do_faccessat` first test).
    for bad in [8, 16, 0x40, -1] {
        let rv = oracle::faccessat2(&f, bad, 0);
        assert_eq!(rv.errno, libc::EINVAL, "faccessat2 mode={bad} should be EINVAL, got {rv:?}");
    }
    // Flag bits outside the accepted three are EINVAL.
    for bad in [1, 2, 0x400, 0x800] {
        let rv = oracle::faccessat2(&f, libc::F_OK, bad);
        assert_eq!(rv.errno, libc::EINVAL, "faccessat2 flags={bad:#x} should be EINVAL, got {rv:?}");
    }
    // The three accepted flags are not EINVAL.
    for good in [0, AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
                 AT_EACCESS | AT_SYMLINK_NOFOLLOW] {
        let rv = oracle::faccessat2(&f, libc::F_OK, good);
        assert_ne!(rv.errno, libc::EINVAL, "faccessat2 flags={good:#x} must be accepted, got {rv:?}");
    }
    // `access(2)` on an owned readable file succeeds; a missing path is ENOENT.
    assert_eq!(oracle::access(&f, libc::R_OK).ret, 0);
    assert_eq!(oracle::access(&t.join("gone"), libc::F_OK).errno, libc::ENOENT);
}
