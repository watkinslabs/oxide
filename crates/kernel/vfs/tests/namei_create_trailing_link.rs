//! Where an `O_CREAT` lands when its FINAL component is a symlink.
//!
//! The reference resolves the trailing component inside the SAME walk it used
//! for the parent: `open_last_lookups` looks the leaf up and hands it to
//! `step_into` with `WALK_TRAILING`, which picks the link up and continues the
//! walk on the link's target. So a create through `/etc/resolv.conf ->
//! ../run/systemd/resolve/stub-resolv.conf` acts on the TARGET's name in the
//! TARGET's directory, and a link whose target does not exist yet is created
//! THROUGH rather than reported as a name already taken. `EEXIST` is only ever
//! correct for `O_EXCL`, which the reference implements by forcing `O_NOFOLLOW`
//! (`fs/open.c` `build_open_flags`) so the link is not followed at all.
//!
//! Each case drives the real walker. `parent_of` is exactly what the open slot
//! file asks for on the create path: the directory the new name goes in, plus
//! the name itself.

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
fn reg(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        Arc::new(DirOps), vfs::default_file_ops()).build()
}

const INO_ROOT: u64 = 2;
const INO_ETC: u64 = 10;
const INO_RUN: u64 = 11;
const INO_DEEP: u64 = 12;

// Synthetic tree, shaped like the case that made this visible in the guest:
//   /                       (2)
//   /etc                    (10)
//   /etc/resolv.conf        -> ../run/stub        (DANGLING: /run/stub absent)
//   /etc/abs                -> /run/stub          (dangling, absolute)
//   /etc/here               -> sibling            (dangling, same directory)
//   /etc/taken              -> /etc/real          (target EXISTS)
//   /etc/real               (regular, ino 20)
//   /etc/hop1 -> hop2 -> hop3 -> ../run/stub      (chain, dangling at the end)
//   /etc/loopa -> loopb, /etc/loopb -> loopa      (cycle)
//   /etc/todir              -> /run/deep          (target is a DIRECTORY)
//   /run                    (11)
//   /run/deep               (12)
fn build_root() -> Arc<Dentry> {
    let deep = dir(INO_DEEP, &[]);
    let etc = dir(INO_ETC, &[
        ("resolv.conf", sym(30, "../run/stub")),
        ("abs",         sym(31, "/run/stub")),
        ("here",        sym(32, "sibling")),
        ("taken",       sym(33, "/etc/real")),
        ("real",        reg(20)),
        ("hop1",        sym(34, "hop2")),
        ("hop2",        sym(35, "hop3")),
        ("hop3",        sym(36, "../run/stub")),
        ("loopa",       sym(37, "loopb")),
        ("loopb",       sym(38, "loopa")),
        ("todir",       sym(39, "/run/deep")),
    ]);
    Dentry::new_root(dir(INO_ROOT, &[
        ("etc", etc),
        ("run", dir(INO_RUN, &[("deep", deep)])),
    ]))
}

/// The create path's question: which directory does the new name go in, and
/// what is the name? `follow` is the one bit that separates `open(O_CREAT)`
/// (set — act on what the link points at) from `mknod`/`link`/`rename` (clear —
/// an existing final component is the caller's to reject).
fn parent_of(root: &Arc<Dentry>, path: &str, follow: bool) -> vfs::KResult<(u64, String)> {
    let flags = LookupFlags { parent: true, follow, ..Default::default() };
    vfs::path_lookup_path(root.clone(), root.clone(), path, flags)
        .map(|p| (p.inode.ino(), p.last_component.clone().unwrap_or_default()))
}

// The reported defect, in its original form: nothing in the guest could write
// /etc/resolv.conf, because the create was aimed at the link's own name — a
// name already taken — instead of at what the link points at.
#[test]
fn a_create_through_a_dangling_relative_link_lands_on_the_links_target() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/resolv.conf", true), Ok((INO_RUN, "stub".to_string())),
        "the create must land in /run as `stub`, the name the link points at");
}

// A relative target is anchored at the directory holding the LINK, not at the
// caller's working directory and not at the root.
#[test]
fn a_relative_target_resolves_from_the_directory_holding_the_link() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/here", true), Ok((INO_ETC, "sibling".to_string())),
        "`here -> sibling` names /etc/sibling, so the create stays in /etc");
}

#[test]
fn an_absolute_target_restarts_at_the_resolution_root() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/abs", true), Ok((INO_RUN, "stub".to_string())));
}

// Every link in a chain is followed, and the create lands past the last one.
#[test]
fn a_chain_of_links_is_followed_to_its_end() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/hop1", true), Ok((INO_RUN, "stub".to_string())),
        "hop1 -> hop2 -> hop3 -> ../run/stub");
}

// A cycle is bounded by the walk's OWN symlink budget — the same one every
// other component is bounded by, not a second budget kept beside it.
#[test]
fn a_cycle_in_the_trailing_links_is_eloop_not_a_hang() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/loopa", true).err(), Some(VfsError::Eloop));
}

// The leaf exists and is NOT a link: the walk stops on the parent and reports
// the name, leaving EEXIST/EISDIR/plain-open to the caller exactly as before.
#[test]
fn an_existing_non_link_leaf_still_stops_at_its_parent() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/real", true), Ok((INO_ETC, "real".to_string())));
}

// A link whose target EXISTS resolves to the target's parent and name, so an
// open finds the existing file rather than the link.
#[test]
fn a_link_to_an_existing_file_reports_the_targets_parent_and_name() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/taken", true), Ok((INO_ETC, "real".to_string())));
}

// Without FOLLOW nothing changes: the leaf is reported verbatim. This is the
// `O_EXCL` / `O_NOFOLLOW` shape (the reference forces `O_NOFOLLOW` for
// `O_EXCL`), and the mknod/link/rename shape.
#[test]
fn without_follow_the_leaf_is_reported_verbatim() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/resolv.conf", false),
        Ok((INO_ETC, "resolv.conf".to_string())),
        "O_EXCL/O_NOFOLLOW keep the link's own name as the subject");
    assert_eq!(parent_of(&root, "/etc/hop1", false), Ok((INO_ETC, "hop1".to_string())));
}

// A leaf that does not exist at all is the ordinary create, and following
// changes nothing about it.
#[test]
fn a_leaf_that_does_not_exist_is_unaffected_by_following() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/brand-new", true), Ok((INO_ETC, "brand-new".to_string())));
    assert_eq!(parent_of(&root, "/etc/brand-new", false), Ok((INO_ETC, "brand-new".to_string())));
}

// `..` is a control segment, not a name: the reference sends it to
// `handle_dots`, never to the trailing-link path, so it is still reported
// verbatim for the caller to reject.
#[test]
fn a_trailing_dotdot_is_still_reported_verbatim_under_follow() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/..", true), Ok((INO_ETC, "..".to_string())));
}

// The flag rule itself, which the open slot file applies to its parent walk.
// These replace unit tests that lived in a `#![cfg(target_os = "oxide-kernel")]`
// module and therefore never ran: `cargo test` reported them as neither passed
// nor failed because the module was not compiled at all.
#[test]
fn a_plain_create_follows_its_trailing_link() {
    let mut f = LookupFlags { parent: true, ..Default::default() };
    f.set_open_create_trailing(false, false);
    assert!(f.follow && !f.no_follow_final);
}

#[test]
fn o_excl_outranks_o_nofollow_and_both_keep_the_link_as_the_subject() {
    for (excl, nofollow) in [(true, false), (false, true), (true, true)] {
        let mut f = LookupFlags { parent: true, ..Default::default() };
        f.set_open_create_trailing(excl, nofollow);
        assert!(!f.follow && f.no_follow_final,
            "O_EXCL={excl} O_NOFOLLOW={nofollow} must not follow the trailing link");
    }
}

// The rule drives the walk, not just a bool: the same flags fed to the resolver
// must produce the two different leaves.
#[test]
fn the_flag_rule_and_the_walk_agree_on_the_same_link() {
    let root = build_root();
    let mut plain = LookupFlags { parent: true, ..Default::default() };
    plain.set_open_create_trailing(false, false);
    let mut excl = LookupFlags { parent: true, ..Default::default() };
    excl.set_open_create_trailing(true, false);

    let got = |f: LookupFlags| vfs::path_lookup_path(root.clone(), root.clone(), "/etc/resolv.conf", f)
        .map(|p| (p.inode.ino(), p.last_component.clone().unwrap_or_default()));

    assert_eq!(got(plain), Ok((INO_RUN, "stub".to_string())));
    assert_eq!(got(excl), Ok((INO_ETC, "resolv.conf".to_string())));
}

// Following the leaf must not skip the parent's own resolution rules: a link
// pointing at a DIRECTORY reports that directory's parent and name, so an
// O_CREAT on it is EISDIR at the caller rather than a create inside it.
#[test]
fn a_link_to_a_directory_reports_the_directory_not_its_contents() {
    let root = build_root();
    assert_eq!(parent_of(&root, "/etc/todir", true), Ok((INO_RUN, "deep".to_string())));
}
