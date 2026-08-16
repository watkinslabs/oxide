// The node tree, its population, and the rebuild a policy load forces.
//
// The tree is this filesystem's own `kernfs` root; nothing about it lives in
// another filesystem's registry. Four of its directories are built from the
// LOADED POLICY's tables and are therefore replaced wholesale on every load —
// a policy's classes, permissions, booleans and initial contexts are its own,
// and leaving a previous policy's nodes in place would publish names the
// running policy does not have.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use kernfs::PseudoDir;
use sync::{SecurityPolicy as LockClass, Spinlock};
use vfs::pseudo_ino::{overlaps, Region, RegionAllocator, REGIONS};
use vfs::{Ino, InodeRef};

use crate::nodes::{booleans, caps, classes, enforce, initcon, load, misc, stats, transaction};

/// Filesystem identity reported as `st_dev` for every node here.
pub const SELINUXFS_FSID: u64 = 0x0102_1994_0000_0007;

/// Inode numbers this filesystem mints.
const SELINUXFS_INOS: Region = Region::new("selinuxfs", 0x7B00_0000, 0x7B0F_FFFF);

/// Whether a region collides with none of the declared ones. # C: O(regions)
const fn disjoint_from_declared(r: &Region) -> bool {
    let mut i = 0;
    while i < REGIONS.len() {
        if overlaps(&REGIONS[i], r) { return false; }
        i += 1;
    }
    true
}

// A number minted into another owner's range resolves to that owner's object
// somewhere far from here; the collision is caught at build time instead.
const _: () = assert!(disjoint_from_declared(&SELINUXFS_INOS),
                      "selinuxfs inode region collides with a declared region");

/// Allocator for this filesystem's inode numbers.
static NEXT_INO: RegionAllocator = RegionAllocator::new(&SELINUXFS_INOS);

/// The mount root.
static ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Whether the fixed nodes have been built.
static POPULATED: AtomicBool = AtomicBool::new(false);

/// Mint one inode number. # C: O(1)
pub fn alloc_ino() -> Ino { NEXT_INO.alloc() }

/// Get-or-create the tree root, without building its nodes. # C: O(1)
fn root_dir() -> Arc<PseudoDir> {
    let mut slot = ROOT.lock();
    if let Some(r) = slot.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(alloc_ino(), SELINUXFS_FSID);
    *slot = Some(Arc::clone(&r));
    r
}

/// The populated tree root. # C: O(1) after the first call
///
/// Population happens here as well as at boot so a mount finds the interface
/// built even on a path that never called the boot entry point; an empty
/// directory would read to userspace as a kernel without the module.
pub fn selinux_root() -> Arc<PseudoDir> {
    populate();
    root_dir()
}

/// Build every fixed node, once. # C: O(nodes)
pub fn populate() {
    if POPULATED.swap(true, Ordering::AcqRel) { return; }
    let root = root_dir();
    for (path, inode) in fixed_nodes() { root.insert_path(&path, inode); }
    rebuild_policy_nodes();
}

/// Every node whose existence does not depend on the loaded policy. # C: O(nodes)
fn fixed_nodes() -> Vec<(String, InodeRef)> {
    let mut out: Vec<(String, InodeRef)> = alloc::vec![
        (String::from("enforce"), enforce::make_enforce()),
        (String::from("load"), load::make_load()),
        (String::from("policy"), load::make_policy()),
        (String::from("policyvers"), misc::make_policyvers()),
        (String::from("mls"), misc::make_mls()),
        (String::from("reject_unknown"), misc::make_reject_unknown()),
        (String::from("deny_unknown"), misc::make_deny_unknown()),
        (String::from("checkreqprot"), misc::make_checkreqprot()),
        (String::from("disable"), misc::make_disable()),
        (String::from("validatetrans"), misc::make_validatetrans()),
        (String::from("commit_pending_bools"), booleans::make_commit()),
        (String::from("null"), misc::make_null()),
        (alloc::format!("{}/{}", stats::AVC_DIR, stats::HASH_STATS_NODE),
         stats::make_avc_hash_stats()),
        (alloc::format!("{}/{}", stats::AVC_DIR, stats::CACHE_STATS_NODE),
         stats::make_cache_stats()),
        (alloc::format!("{}/{}", stats::AVC_DIR, stats::CACHE_THRESHOLD_NODE),
         stats::make_cache_threshold()),
        (alloc::format!("{}/{}", stats::SS_DIR, stats::SIDTAB_HASH_STATS_NODE),
         stats::make_sidtab_hash_stats()),
        (String::from(stats::STATUS_NODE), stats::make_status()),
    ];
    for (name, kind) in transaction::TRANSACTION_NODES {
        out.push((String::from(name), transaction::make_transaction(kind)));
    }
    out
}

/// Directories rebuilt from the loaded policy's own tables.
const POLICY_DIRS: [&str; 4] = [booleans::BOOLEANS_DIR, classes::CLASS_DIR,
                                initcon::INITIAL_CONTEXTS_DIR, caps::POLICYCAP_DIR];

/// Replace every policy-derived directory. # C: O(classes × perms)
pub fn rebuild_policy_nodes() {
    let root = root_dir();
    for dir in POLICY_DIRS { root.remove_subtree(dir); }
    for (path, inode) in policy_nodes() { root.insert_path(&path, inode); }
}

/// Every node built from the loaded policy's tables. # C: O(classes × perms)
fn policy_nodes() -> Vec<(String, InodeRef)> {
    let mut out = Vec::new();
    for name in crate::server::with_ops(|o| o.bool_names()) {
        out.push((alloc::format!("{}/{name}", booleans::BOOLEANS_DIR), booleans::make_bool(&name)));
    }
    for class in crate::server::with_ops(|o| o.classes()) {
        out.extend(classes::class_nodes(&class));
    }
    out.extend(initcon::initial_context_nodes());
    out.extend(caps::cap_nodes());
    out
}
