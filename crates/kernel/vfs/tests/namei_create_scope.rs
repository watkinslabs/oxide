//! `openat2(2)` scoping on the O_CREAT path — the causality test for the
//! sandbox escape B1478 fixed.
//!
//! `257_openat.rs` resolves an open in TWO phases: a scoped full-path walk,
//! and — when that returns ENOENT and `O_CREAT` is set — a `LOOKUP_PARENT`
//! walk that yields the directory the new file is created in. The same
//! resolved lookup-flags value is handed to both phases; there is no
//! create-path exception. The slot
//! file built phase 2 from `LookupFlags::default()`, so every `RESOLVE_*` bit
//! stopped constraining resolution the instant a create was involved.
//!
//! Each case runs BOTH phase-2 flag sets against the real walker: `old` is
//! what shipped, `new` is what the fix builds. `old` escaping is the bug;
//! `new` refusing is the fix.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl vfs::InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}

struct SymData { target: Vec<u8> }
struct SymOps;
impl vfs::InodeOps for SymOps {
    fn readlink(&self, inode: &Inode) -> vfs::KResult<Vec<u8>> {
        Ok(inode.private::<SymData>().unwrap().target.clone())
    }
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn sym(ino: u64, t: &str) -> InodeRef {
    let body = t.as_bytes().to_vec();
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Symlink, 0o777),
        Arc::new(SymOps), vfs::default_file_ops())
        .size(body.len() as u64).private(Arc::new(SymData { target: body })).build()
}

const INO_ROOT: u64 = 2;
const INO_BOX: u64 = 10;
const INO_SUB: u64 = 11;
/// The escape target: a SIBLING of the sandbox, one level above it.
const INO_OUTSIDE: u64 = 99;

// Synthetic tree:
//   /            (2)
//   /box         (10)  ← the dirfd; the sandbox
//   /box/sub     (11)  ← an ordinary child, inside
//   /box/link          ← symlink "../outside", leads OUT
//   /outside     (99)  ← must never be reachable under a scoping bit
fn build_root() -> Arc<Dentry> {
    let boxd = dir(INO_BOX, &[
        ("sub", dir(INO_SUB, &[])),
        ("link", sym(12, "../outside")),
    ]);
    Dentry::new_root(dir(INO_ROOT, &[
        ("box", boxd),
        ("outside", dir(INO_OUTSIDE, &[])),
    ]))
}

fn scope(root: &Arc<Dentry>) -> Arc<Dentry> {
    vfs::path_lookup(root.clone(), root.clone(), "/box", LookupFlags::default())
        .expect("resolve /box dentry").1
}

/// Phase 2 as the slot file performs it: resolve the PARENT of `path` with
/// `flags`, and report which directory the create would land in.
fn parent_of(start: &Arc<Dentry>, root: &Arc<Dentry>, path: &str, flags: LookupFlags)
    -> vfs::KResult<u64>
{
    vfs::path_lookup_path(start.clone(), root.clone(), path, flags).map(|p| p.inode.ino())
}

/// What shipped: every `RESOLVE_*` bit dropped.
fn old_parent_flags() -> LookupFlags { LookupFlags { parent: true, ..Default::default() } }

/// What the fix builds — mirrors `syscalls::openat2_resolve::parent_lookup_flags`.
fn new_parent_flags(extra: LookupFlags) -> LookupFlags {
    LookupFlags {
        parent: true,
        no_xdev: extra.no_xdev,
        no_magiclinks: extra.no_magiclinks,
        no_symlinks: extra.no_symlinks,
        beneath_exdev: extra.beneath_exdev,
        in_root: extra.in_root,
        ..Default::default()
    }
}

// RESOLVE_IN_ROOT is the sharp one: it CLAMPS `..` at the dirfd instead of
// erroring, so phase 1 of `openat2(box, "../outside/esc", O_CREAT, IN_ROOT)`
// walks to box/outside/esc, finds nothing, and returns ENOENT — handing
// control to the create branch. An unscoped phase 2 then walks the REAL `..`
// and creates in /outside.
#[test]
fn in_root_dotdot_create_escapes_with_old_flags() {
    let root = build_root();
    let boxd = scope(&root);

    // Phase 1 (scoped) really does end in ENOENT, so the create branch runs.
    let mut p1 = LookupFlags::default();
    p1.in_root = true;
    assert_eq!(vfs::path_lookup(boxd.clone(), root.clone(), "../outside/esc", p1).err(),
        Some(VfsError::Enoent),
        "in_root clamps `..`, so the scoped full-path walk yields ENOENT and the create branch is entered");

    // FAILS BEFORE: the shipped parent flags reach /outside (ino 99).
    assert_eq!(parent_of(&boxd, &root, "../outside/esc", old_parent_flags()),
        Ok(INO_OUTSIDE),
        "the dropped-RESOLVE_* parent walk escapes the sandbox — this is the bug");

    // PASSES AFTER: the scoped parent flags clamp at the dirfd, and `box` has
    // no `outside` child, so there is nowhere outside to create.
    assert_eq!(parent_of(&boxd, &root, "../outside/esc", new_parent_flags(p1)).err(),
        Some(VfsError::Enoent),
        "RESOLVE_IN_ROOT must confine the O_CREAT parent walk to the dirfd");
}

// Same escape reached by an ABSOLUTE pathname. Under IN_ROOT the dirfd IS "/",
// so `/outside/esc` must restart inside the box.
#[test]
fn in_root_absolute_create_escapes_with_old_flags() {
    let root = build_root();
    let boxd = scope(&root);
    let mut p1 = LookupFlags::default();
    p1.in_root = true;

    assert_eq!(parent_of(&boxd, &root, "/outside/esc", old_parent_flags()), Ok(INO_OUTSIDE),
        "an absolute pathname re-based on the PROCESS root escapes — this is the bug");
    assert_eq!(parent_of(&boxd, &root, "/outside/esc", new_parent_flags(p1)).err(),
        Some(VfsError::Enoent),
        "RESOLVE_IN_ROOT: an absolute create path restarts at the dirfd");
}

// RESOLVE_BENEATH errors rather than clamping, so `..` at the scoped root is
// EXDEV — for the parent walk exactly as for a plain open.
#[test]
fn beneath_dotdot_create_is_exdev() {
    let root = build_root();
    let boxd = scope(&root);
    let mut p1 = LookupFlags::default();
    p1.beneath_exdev = true;

    // CORRECTION to the audit, which named RESOLVE_BENEATH as the escaping
    // flag: unlike IN_ROOT, BENEATH ERRORS on an escape instead of clamping, so
    // phase 1 already answers EXDEV and the create branch is never entered.
    // BENEATH was incidentally covered; IN_ROOT was the live hole. The parent
    // flags are fixed for both regardless — phase 1 is not a security boundary
    // anyone should be relying on.
    assert_eq!(vfs::path_lookup(boxd.clone(), root.clone(), "../outside/esc", p1).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH errors in phase 1, so the create branch is unreachable for this path");

    assert_eq!(parent_of(&boxd, &root, "../outside/esc", old_parent_flags()), Ok(INO_OUTSIDE),
        "unscoped parent walk reaches /outside");
    assert_eq!(parent_of(&boxd, &root, "../outside/esc", new_parent_flags(p1)).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH: `..` above the dirfd is EXDEV on the create path too");
}

#[test]
fn beneath_absolute_create_is_exdev() {
    let root = build_root();
    let boxd = scope(&root);
    let mut p1 = LookupFlags::default();
    p1.beneath_exdev = true;
    assert_eq!(parent_of(&boxd, &root, "/outside/esc", new_parent_flags(p1)).err(),
        Some(VfsError::Exdev),
        "RESOLVE_BENEATH: an absolute create path is EXDEV");
}

// RESOLVE_NO_SYMLINKS: any symlink anywhere in the walk is ELOOP. `box/link`
// points out of the sandbox, so an unscoped parent walk both FOLLOWS it and
// escapes.
#[test]
fn no_symlinks_create_via_symlink_is_eloop() {
    let root = build_root();
    let boxd = scope(&root);
    let mut p1 = LookupFlags::default();
    p1.no_symlinks = true;

    // Like BENEATH and unlike IN_ROOT, NO_SYMLINKS errors in phase 1, so this
    // path never reached the unscoped create branch either. RESOLVE_IN_ROOT is
    // the ONLY scoping bit that clamps rather than errors, which is exactly why
    // it was the one flag whose escape was live.
    assert_eq!(vfs::path_lookup(boxd.clone(), root.clone(), "link/esc", p1).err(),
        Some(VfsError::Eloop),
        "RESOLVE_NO_SYMLINKS errors in phase 1");

    assert_eq!(parent_of(&boxd, &root, "link/esc", old_parent_flags()), Ok(INO_OUTSIDE),
        "unscoped parent walk follows the escaping symlink — this is the bug");
    assert_eq!(parent_of(&boxd, &root, "link/esc", new_parent_flags(p1)).err(),
        Some(VfsError::Eloop),
        "RESOLVE_NO_SYMLINKS must ELOOP on the O_CREAT parent walk");
}

// The scoped flags must not break ordinary in-scope creates, or a kernel that
// simply refuses everything would read as fixed.
#[test]
fn in_scope_create_still_resolves_under_every_scoping_bit() {
    let root = build_root();
    let boxd = scope(&root);
    for (name, mut f) in [
        ("in_root",     { let mut f = LookupFlags::default(); f.in_root = true; f }),
        ("beneath",     { let mut f = LookupFlags::default(); f.beneath_exdev = true; f }),
        ("no_symlinks", { let mut f = LookupFlags::default(); f.no_symlinks = true; f }),
        ("no_xdev",     { let mut f = LookupFlags::default(); f.no_xdev = true; f }),
    ] {
        f = new_parent_flags(f);
        assert_eq!(parent_of(&boxd, &root, "sub/esc", f), Ok(INO_SUB),
            "{name}: an in-scope create must still resolve its parent");
    }
}

// The plain-openat path (no `open_how`) must be byte-identical to what shipped.
#[test]
fn plain_openat_parent_walk_unchanged() {
    let root = build_root();
    let boxd = scope(&root);
    let new = new_parent_flags(LookupFlags::default());
    assert_eq!(parent_of(&boxd, &root, "../outside/esc", new),
               parent_of(&boxd, &root, "../outside/esc", old_parent_flags()),
        "an openat(2) with no RESOLVE_* word keeps the historical parent walk");
}
