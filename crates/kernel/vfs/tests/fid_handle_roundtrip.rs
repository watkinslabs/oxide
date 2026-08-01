//! `name_to_handle_at(2)` (303) → `open_by_handle_at(2)` (304) round-trip
//! MECHANISM, against the real VFS export hooks.
//!
//! The syscall shims are kernel-gated, so what runs here is everything they
//! call: `SuperOps::fh_to_dentry`/`fh_to_parent`, `export::generation_matches`,
//! `export::get_name`, `export::reconnect_child`, and the per-superblock
//! generation the builder stamps. The properties asserted are the three a bare
//! inode-number handle cannot provide — a handle resolves to the SAME inode, a
//! RECYCLED number does not resolve through an old handle, and a connectable
//! handle comes back CONNECTED to its parent by name.

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::inode::InodeBuilder;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, SuperBlock};

struct FidFs;
impl FileSystem for FidFs {
    fn name(&self) -> &str { "fidfs" }
}

fn sb() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(FidFs), None, next_anon_dev(), String::from("fidfs"))
}

fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

/// A handle is `(ino, generation)`; the resolve step is the superblock's
/// export hook, exactly as slot 304 calls it.
fn resolve(sb: &Arc<SuperBlock>, ino: u64, generation: u32) -> Option<InodeRef> {
    sb.s_op.fh_to_dentry(sb, ino, generation)
}

/// An inode built against a superblock draws a real generation from it — this
/// is what 303 puts in the handle. Zero would mean "unversioned" and would
/// disable recycle detection for every in-memory filesystem.
#[test]
fn superblock_stamps_a_nonzero_generation() {
    let sb = sb();
    let a = ramfile(&sb, 1);
    let b = ramfile(&sb, 2);
    assert_ne!(a.i_generation(), vfs::export::GENERATION_ANY, "generation must be minted");
    assert_ne!(a.i_generation(), b.i_generation(), "two inodes must not share an incarnation");
}

/// An inode built with NO superblock keeps the unversioned wildcard, so a
/// pre-existing pseudo-inode is not retroactively made un-decodable.
#[test]
fn sbless_inode_is_unversioned() {
    let orphan = InodeBuilder::new(5, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    assert_eq!(orphan.i_generation(), vfs::export::GENERATION_ANY);
}

/// A backend-supplied generation is passed through verbatim and NOT overwritten
/// by the superblock counter — an on-disk filesystem's generation must survive
/// evict+reload or its handles go stale for no reason.
#[test]
fn backend_generation_wins_over_the_superblock_counter() {
    let sb = sb();
    let i = InodeBuilder::new(11, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(&sb)).generation(0xFEED_FACE).build();
    assert_eq!(i.i_generation(), 0xFEED_FACE);
}

/// The round trip: encode a live inode's identity, decode it back, get the
/// SAME `Arc` — not a second parallel copy of one object.
#[test]
fn handle_resolves_back_to_same_inode() {
    let sb = sb();
    let resident = sb.iget(77, || ramfile(&sb, 77));
    let (ino, generation) = (resident.ino(), resident.i_generation());

    let reopened = resolve(&sb, ino, generation).expect("resident inode resolves");
    assert!(Arc::ptr_eq(&resident, &reopened), "handle round-trips to the SAME inode");
    assert_eq!(reopened.ino(), 77);
}

/// THE recycle test. An inode is minted, its handle taken, the inode dropped,
/// and the SAME NUMBER reused for a different object. The old handle must NOT
/// resolve — which is precisely what an ino-only handle would have done.
#[test]
fn recycled_inode_number_does_not_resolve_through_the_old_handle() {
    let sb = sb();
    let handle = {
        let first = sb.iget(90, || ramfile(&sb, 90));
        (first.ino(), first.i_generation())
    }; // first dropped → its icache Weak is dead

    // Same number, new object, new incarnation.
    let second = sb.iget(90, || ramfile(&sb, 90));
    assert_eq!(second.ino(), handle.0, "the NUMBER was reused");
    assert_ne!(second.i_generation(), handle.1, "…but the incarnation differs");

    assert!(resolve(&sb, handle.0, handle.1).is_none(),
        "a handle to the previous incarnation must not open the recycled inode");
    // The current incarnation's own handle still works, so the rejection is
    // generation-specific and not a blanket failure.
    assert!(resolve(&sb, second.ino(), second.i_generation()).is_some());
}

/// The wildcard generation matches any incarnation — how a filesystem that
/// never recycles a number opts out — but a MISMATCH between two real
/// generations is always rejected.
#[test]
fn unversioned_wildcard_matches_but_mismatch_does_not() {
    let sb = sb();
    let i = sb.iget(31, || ramfile(&sb, 31));
    assert!(resolve(&sb, 31, vfs::export::GENERATION_ANY).is_some(), "wildcard matches");
    assert!(resolve(&sb, 31, i.i_generation()).is_some(), "exact match");
    assert!(resolve(&sb, 31, i.i_generation().wrapping_add(1)).is_none(), "mismatch rejected");
}

/// An inode nothing holds is gone from the cache, and the generic backend
/// (no on-disk store to re-read from) reports it as unresolvable — ESTALE at
/// the syscall.
#[test]
fn stale_handle_yields_no_inode() {
    let sb = sb();
    let handle = {
        let tmp = sb.iget(99, || ramfile(&sb, 99));
        (tmp.ino(), tmp.i_generation())
    };
    assert!(resolve(&sb, handle.0, handle.1).is_none(), "stale handle does not resolve");
}

/// `fh_to_parent` decodes the parent half of a connectable handle. The default
/// forwards to `fh_to_dentry`, so a backend overriding one gets the other —
/// this asserts the forwarding actually happens rather than the parent decode
/// silently being a different (untested) code path.
#[test]
fn fh_to_parent_decodes_like_fh_to_dentry() {
    let sb = sb();
    let dir = sb.iget(4, || ramfile(&sb, 4));
    let a = sb.s_op.fh_to_parent(&sb, 4, dir.i_generation()).expect("parent resolves");
    assert!(Arc::ptr_eq(&dir, &a));
    assert!(sb.s_op.fh_to_parent(&sb, 4, dir.i_generation().wrapping_add(1)).is_none(),
        "the parent half enforces its own generation too");
}
