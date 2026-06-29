//! D1/D12 — split symlink limits: `nd->depth` (NESTING, cap MAX_NESTED_LINKS=8)
//! vs `nd->total_link_count` (TOTAL follows, cap MAXSYMLINKS=40). The flat
//! per-follow counter is wrong on BOTH ends: it would ELOOP a long FLAT chain
//! (no nesting) at 8, and it would not distinguish over-nesting from
//! over-counting. These tests lock the two caps independently against the real
//! `vfs::path_lookup` over a synthetic inode tree (`docs/16§3`).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: Vec<(String, InodeRef)>) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n, i); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), default_file_ops()).build()
}
fn sym(ino: u64, t: &str) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), vfs::default_inode_ops(), default_file_ops())
        .size(t.len() as u64).link(t.as_bytes().to_vec().into_boxed_slice()).build()
}
fn look(root: &Arc<Dentry>, path: &str) -> KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
}

// A long FLAT symlink chain — each link's target is a SINGLE component
// (`s0 -> s1 -> ... -> s19 -> target`), so no remainder frame is ever stacked
// (nesting depth stays 0). 20 follows is under MAXSYMLINKS(40), so it MUST
// resolve. The old flat per-follow counter capped at 8 would have wrongly
// ELOOP'd this — the regression this split fixes.
#[test]
fn flat_chain_under_total_cap_resolves() {
    let mut kids: Vec<(String, InodeRef)> = Vec::new();
    for i in 0..20u64 { kids.push((format!("s{i}"), sym(100 + i, &format!("s{}", i + 1)))); }
    kids.push(("s20".to_string(), file(9999)));
    let root = Dentry::new_root(dir(2, kids));
    let (i, _) = look(&root, "/s0").expect("20-deep FLAT symlink chain resolves (total<40, nesting=0)");
    assert_eq!(i.ino(), 9999, "flat chain followed through to the target file");
}

// A FLAT chain LONGER than MAXSYMLINKS(40) is ELOOP — the total-link cap still
// catches a runaway flat chain even though nesting never rises.
#[test]
fn flat_chain_over_total_cap_is_eloop() {
    let mut kids: Vec<(String, InodeRef)> = Vec::new();
    for i in 0..45u64 { kids.push((format!("s{i}"), sym(200 + i, &format!("s{}", i + 1)))); }
    kids.push(("s45".to_string(), file(8888)));
    let root = Dentry::new_root(dir(2, kids));
    assert_eq!(look(&root, "/s0").err(), Some(VfsError::Eloop),
        "45-deep flat chain exceeds MAXSYMLINKS(40) → ELOOP via the total cap");
}

// A NESTED chain — each link's target carries a TRAILING remainder
// (`l0 -> "l1/t"`, `l1 -> "l2/t"`, ...), so following `l1..l9` STACKS a
// suspended frame each time (nesting depth climbs 1..9). The 9th push exceeds
// MAX_NESTED_LINKS(8) → ELOOP, while the TOTAL count is only ~10 (far under
// 40). Proves the NESTING cap fires independently of the total cap: a finite
// 10-link chain would otherwise terminate non-ELOOP.
#[test]
fn nested_chain_over_nesting_cap_is_eloop() {
    let mut kids: Vec<(String, InodeRef)> = Vec::new();
    for i in 0..10u64 { kids.push((format!("l{i}"), sym(300 + i, &format!("l{}/t", i + 1)))); }
    // `l10` and `t` exist so the chain is finite & otherwise resolvable — the
    // ELOOP can only come from the nesting cap, not a dead end or a real cycle.
    kids.push(("l10".to_string(), dir(400, vec![("t".to_string(), file(7777))])));
    let root = Dentry::new_root(dir(2, kids));
    assert_eq!(look(&root, "/l0").err(), Some(VfsError::Eloop),
        "9 stacked remainder frames exceed MAX_NESTED_LINKS(8) → ELOOP (total≈10 < 40)");
}
