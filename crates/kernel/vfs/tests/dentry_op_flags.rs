//! dcache-D14: DCACHE_OP_* — the `d_op` presence cache. At construction the
//! non-NULL hooks of the inherited `d_op` vector are stamped into `d_flags`
//! (Linux `d_set_d_op`), so the hot path branches on a `d_flags` bit instead of
//! dereferencing `d_op` and probing each `Option` hook. Mirrors Linux
//! `__d_lookup` (`parent->d_flags & DCACHE_OP_COMPARE`) + the `dput` delete gate.

use std::sync::Arc;

use vfs::dentry::{
    DCompareFn, DDeleteFn, DHashFn, DRevalidateFn, Dentry, DentryOps, D_OP_COMPARE, D_OP_DELETE,
    D_OP_HASH, D_OP_MASK, D_OP_REVALIDATE,
};
use vfs::{FileType, InodeRef};

fn dir() -> InodeRef {
    vfs::InodeBuilder::new(1, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// Stand-in hook impls (only presence matters for the stamp).
fn h(_n: &str) -> u32 { 0 }
fn cmp(name: &str, cand: &Dentry) -> bool { cand.name() == name }
fn cmp_ci(name: &str, cand: &Dentry) -> bool { cand.name().eq_ignore_ascii_case(name) }
fn rev(_d: &Arc<Dentry>, _reval: bool) -> bool { true }
fn del(_d: &Dentry) -> bool { true }

const HASH_FN: DHashFn = h;
const CMP_FN: DCompareFn = cmp;
const CMP_CI_FN: DCompareFn = cmp_ci;
const REV_FN: DRevalidateFn = rev;
const DEL_FN: DDeleteFn = del;

// d_op vectors covering the relevant presence combinations.
static OPS_NONE: DentryOps = DentryOps::empty();
static OPS_CMP: DentryOps = DentryOps { d_hash: None, d_compare: Some(CMP_FN), d_revalidate: None, d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None };
static OPS_CI: DentryOps = DentryOps { d_hash: None, d_compare: Some(CMP_CI_FN), d_revalidate: None, d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None };
static OPS_ALL4: DentryOps = DentryOps { d_hash: Some(HASH_FN), d_compare: Some(CMP_FN), d_revalidate: Some(REV_FN), d_weak_revalidate: None, d_delete: Some(DEL_FN), d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None };

fn root_with(ops: &'static DentryOps) -> Arc<Dentry> {
    Dentry::new_root(dir()).set_d_op(ops)
}

#[test]
fn no_d_op_stamps_no_presence_bits() {
    let d = Dentry::new_root(dir());
    assert_eq!(d.flags() & D_OP_MASK, 0, "default (None) d_op ⇒ no presence bits");
    assert!(!d.d_has_op_hash() && !d.d_has_op_compare() && !d.d_has_op_revalidate() && !d.d_has_op_delete());
}

#[test]
fn empty_ops_stamps_no_presence_bits() {
    // A non-NULL d_op whose every hook is None still stamps zero bits.
    let d = root_with(&OPS_NONE);
    assert_eq!(d.flags() & D_OP_MASK, 0, "all-None hooks ⇒ no presence bits");
}

#[test]
fn single_hook_stamps_exactly_one_bit() {
    let d = root_with(&OPS_CMP);
    assert!(d.d_has_op_compare(), "d_compare present ⇒ D_OP_COMPARE set");
    assert!(!d.d_has_op_hash() && !d.d_has_op_revalidate() && !d.d_has_op_delete(), "only compare bit set");
    assert_eq!(d.flags() & D_OP_MASK, D_OP_COMPARE, "exactly one presence bit");
}

#[test]
fn all_hooks_stamp_all_bits() {
    let d = root_with(&OPS_ALL4);
    assert_eq!(d.flags() & D_OP_MASK, D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE, "all four bits set");
    assert!(d.d_has_op_hash() && d.d_has_op_compare() && d.d_has_op_revalidate() && d.d_has_op_delete());
}

#[test]
fn child_inherits_parent_op_flags() {
    // new_child propagates d_op down (Linux s_d_op at d_alloc) ⇒ presence bits
    // follow the same path.
    let parent = root_with(&OPS_ALL4);
    let child = Dentry::new_child(&parent, "kid", Some(dir()));
    assert_eq!(child.flags() & D_OP_MASK, D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE, "child inherits all op bits");
    let plain_child = Dentry::new_child(&Dentry::new_root(dir()), "kid", Some(dir()));
    assert_eq!(plain_child.flags() & D_OP_MASK, 0, "child of default-op parent has no op bits");
}

#[test]
fn set_inode_transition_preserves_op_flags() {
    // The DCACHE_ENTRY_TYPE re-stamp in set_inode must not clobber the
    // independent DCACHE_OP_* field.
    let d = Dentry::new_child(&root_with(&OPS_ALL4), "kid", None); // negative
    assert_eq!(d.flags() & D_OP_MASK, D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE);
    d.set_inode(Some(dir()));
    assert_eq!(d.flags() & D_OP_MASK, D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE, "op bits survive negative→positive");
    d.set_inode(None);
    assert_eq!(d.flags() & D_OP_MASK, D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE, "op bits survive positive→negative");
}

#[test]
fn key_matches_consults_compare_hook_iff_bit_set() {
    let parent = Dentry::new_root(dir());

    // Candidate with a case-insensitive d_compare: stored name "KID" matches a
    // "kid" query only because the D_OP_COMPARE branch calls the hook.
    let ci = Dentry::new_child(&parent, "KID", Some(dir())).set_d_op(&OPS_CI);
    assert!(ci.d_has_op_compare(), "ci candidate has D_OP_COMPARE");
    assert!(ci.key_matches(Arc::as_ptr(&parent), ci.d_hash(), "kid"), "compare hook folds case ⇒ match");

    // Default-ops candidate (no D_OP_COMPARE): byte-exact, "KID" != "kid".
    let plain = Dentry::new_child(&parent, "KID", Some(dir()));
    assert!(!plain.d_has_op_compare(), "default candidate has no D_OP_COMPARE");
    assert!(!plain.key_matches(Arc::as_ptr(&parent), plain.d_hash(), "kid"), "byte-exact ⇒ no match");
    assert!(plain.key_matches(Arc::as_ptr(&parent), plain.d_hash(), "KID"), "byte-exact ⇒ exact match");
}
