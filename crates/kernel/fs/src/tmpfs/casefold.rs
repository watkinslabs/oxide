// Case-insensitive name resolution for a tmpfs directory.
//
// tmpfs keeps its own child index rather than letting the dcache be the
// directory, so folding has to reach that index too: a casefolded directory
// must find the child a differently-spelled name refers to, and must refuse to
// create a second entry that only differs by case. The FOLDING RULE itself
// lives in the VFS (one owner, shared with every other filesystem that folds);
// this module only applies it to the child map.

use alloc::string::String;
use alloc::collections::BTreeMap;

use vfs::dentry::casefold::{generic_ci_validate_strict_name, is_casefolded, names_eq,
    GENERIC_CI_DENTRY_OPS};
use vfs::dentry::DentryOps;
use vfs::{Inode, InodeRef, KResult, VfsError};

/// The key `kids` actually stores for `name`, or `None` when no child of this
/// directory answers to it.
///
/// Byte-exact directories cost one lookup. A casefolded directory falls back to
/// a scan, because the map is keyed by the name as CREATED — the spelling
/// `readdir` must report — and a second map keyed by the folded name would be a
/// second source of truth about which children exist.
/// # C: O(1) exact, O(N_children) folded
pub(super) fn stored_key(dir: &Inode, kids: &BTreeMap<String, InodeRef>, name: &str)
    -> Option<String>
{
    if kids.contains_key(name) { return Some(String::from(name)); }
    if !is_casefolded(dir) { return None; }
    kids.keys().find(|k| names_eq(dir, k, name)).cloned()
}

/// Is there already a child answering to `name`? # C: O(1) or O(N_children)
pub(super) fn taken(dir: &Inode, kids: &BTreeMap<String, InodeRef>, name: &str) -> bool {
    stored_key(dir, kids, name).is_some()
}

/// May `name` be created in, or looked up in, this directory?
///
/// Only a strict casefolded instance refuses anything: a name its encoding
/// cannot represent is not stored as opaque bytes, because a later lookup could
/// not fold it back to the same entry.
/// # C: O(name.len())
pub(super) fn name_ok(dir: &Inode, name: &str) -> KResult<()> {
    if generic_ci_validate_strict_name(dir, name.as_bytes()) { Ok(()) } else { Err(VfsError::Einval) }
}

/// Operations a child dentry of `dir` carries: the case-insensitive hash and
/// compare pair exactly while `dir` folds case. # C: O(1)
pub(super) fn child_ops(dir: &Inode) -> Option<&'static DentryOps> {
    if is_casefolded(dir) { Some(&GENERIC_CI_DENTRY_OPS) } else { None }
}

/// Pass the casefold attribute from a directory to a directory created inside
/// it. Only directories carry it — a regular file has no names inside it to
/// fold. # C: O(1)
pub(super) fn inherit(parent: &Inode, child: &InodeRef) {
    if is_casefolded(parent) { child.set_i_flags(child.i_flags() | vfs::inode::S_CASEFOLD); }
}

#[cfg(test)]
mod tests;
