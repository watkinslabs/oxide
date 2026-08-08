// Generic case-insensitive dentry operations for a casefolded filesystem
// (Linux `generic_ci_d_hash` / `generic_ci_d_compare` /
// `generic_ci_validate_strict_name`).
//
// Both hooks are conditional on the PARENT directory's `S_CASEFOLD`, not on the
// superblock: casefolding is a per-directory attribute on an instance that
// merely declared an encoding, so a case-sensitive directory on a casefolded
// filesystem keeps byte-exact lookups.
//
// A filesystem declares its encoding once with [`sb_enable_casefold`] and
// installs the returned operations on its root dentry; every child inherits
// them (`new_child`), which is what `sb->s_d_op` propagation does in the
// reference.

use crate::inode::{Inode, S_CASEFOLD};
use crate::superblock::{encoding_errno, SuperBlock, SB_ENC_STRICT_MODE};
use crate::types::KResult;

use super::{default_name_hash, Dentry, DentryOps};

/// Dentry operations every dentry on a casefolded instance carries.
pub static GENERIC_CI_DENTRY_OPS: DentryOps = DentryOps {
    d_hash:    Some(generic_ci_d_hash),
    d_compare: Some(generic_ci_d_compare),
    d_revalidate: None, d_weak_revalidate: None, d_delete: None, d_release: None,
    d_iput: None, d_dname: None, d_init: None, d_prune: None,
};

/// Does `dir` fold case for the names inside it (Linux `IS_CASEFOLDED`)?
/// # C: O(1)
pub fn is_casefolded(dir: &Inode) -> bool { dir.i_flags() & S_CASEFOLD != 0 }

/// `d_hash` for a casefolded directory: hash the case-folded normalized name,
/// so every spelling of one name lands in one bucket and finds the one dentry.
///
/// A name the encoding cannot normalize falls back to the byte hash — the
/// reference's error return means the same thing for a non-strict instance, and
/// a strict instance refuses such a name before it reaches the dcache
/// ([`generic_ci_validate_strict_name`]). # C: O(name.len())
pub fn generic_ci_d_hash(dir: &Dentry, name: &str) -> u32 {
    let Some(inode) = dir.inode() else { return default_name_hash(name); };
    if !is_casefolded(&inode) { return default_name_hash(name); }
    let Some(enc) = dir.d_sb().and_then(|sb| sb.s_encoding()) else { return default_name_hash(name); };
    utf8::casefold_hash(&enc, name.as_bytes()).unwrap_or_else(|_| default_name_hash(name))
}

/// `d_compare` for a casefolded directory: `name` names the cached dentry
/// `cand` if the two fold to the same normalized sequence. # C: O(name.len())
pub fn generic_ci_d_compare(name: &str, cand: &Dentry) -> bool {
    // Byte-exact first: cheaper, and it is what most lookups are.
    if cand.name() == name { return true; }
    let Some(dir) = cand.parent().and_then(|p| p.inode()) else { return false; };
    if !is_casefolded(&dir) { return false; }
    let Some(enc) = cand.d_sb().and_then(|sb| sb.s_encoding()) else { return false; };
    // A name that does not normalize matches nothing but its own bytes, which
    // the byte-exact test above already answered.
    utf8::casefold_eq(&enc, name.as_bytes(), cand.name().as_bytes()).unwrap_or(false)
}

/// May `name` be created in, or looked up in, directory `dir`?
///
/// Only a casefolded directory on an instance that is STRICT about its encoding
/// restricts names; anywhere else any byte string is a legal name. This is the
/// point at which strict mode refuses a malformed name instead of storing it as
/// opaque bytes — a filesystem calls it from its create and lookup paths and
/// answers `EINVAL`. # C: O(name.len())
pub fn generic_ci_validate_strict_name(dir: &Inode, name: &[u8]) -> bool {
    if !is_casefolded(dir) { return true; }
    let Some(sb) = dir.i_sb() else { return true; };
    if !sb.has_strict_encoding() { return true; }
    match sb.s_encoding() {
        Some(enc) => utf8::validate(&enc, name),
        // A casefolded directory on an instance with no encoding is a corrupt
        // filesystem, not a reason to refuse the name.
        None => true,
    }
}

/// Is `charset` a name encoding this kernel has a table for?
///
/// The mount-option parser answers with this, so a charset this kernel cannot
/// fold by — an unknown name, or a Unicode version newer than the table —
/// fails the OPTION rather than the fill-super, which is where the reference
/// rejects it too. # C: O(charset.len())
pub fn charset_ok(charset: &str) -> KResult<()> {
    utf8::Encoding::from_charset(charset).map(|_| ()).map_err(encoding_errno)
}

/// Do `a` and `b` name the same child of `dir`?
///
/// Byte equality in a case-sensitive directory; the encoding's case-folded
/// normalized comparison in a casefolded one. A filesystem that keeps its own
/// child index — rather than letting the dcache be the directory — probes it
/// with this, so one name cannot resolve to two entries.
///
/// A name the encoding cannot normalize compares byte-exactly, which is what
/// the reference's hash-and-compare pair does for a non-strict instance; a
/// strict instance refuses such a name at create and lookup.
/// # C: O(a.len() + b.len())
pub fn names_eq(dir: &Inode, a: &str, b: &str) -> bool {
    if a == b { return true; }
    if !is_casefolded(dir) { return false; }
    let Some(sb) = dir.i_sb() else { return false; };
    let Some(enc) = sb.s_encoding() else { return false; };
    utf8::casefold_eq(&enc, a.as_bytes(), b.as_bytes()).unwrap_or(false)
}

/// Declare `charset` as this instance's name encoding and return the dentry
/// operations its dentries must carry — THE entry point a filesystem uses to
/// support `casefold` / `strict_encoding`.
///
/// `charset` is the name the mount option or the on-disk superblock field
/// carries: `utf8` for the kernel's table version, or `utf8-<maj>.<min>.<rev>`
/// for a specific one. `EINVAL` for any other charset, or for a Unicode version
/// newer than this kernel's table.
///
/// Call it from `fill_super`, before the root dentry is built, then pass the
/// returned operations to the root dentry constructor; children inherit them.
/// Casefolding is then enabled per directory by setting `S_CASEFOLD` in that
/// directory inode's `i_flags`. # C: O(charset.len())
pub fn sb_enable_casefold(sb: &SuperBlock, charset: &str, strict: bool) -> KResult<&'static DentryOps> {
    let enc = utf8::Encoding::from_charset(charset).map_err(encoding_errno)?;
    sb.set_encoding(enc, if strict { SB_ENC_STRICT_MODE } else { 0 });
    Ok(&GENERIC_CI_DENTRY_OPS)
}
