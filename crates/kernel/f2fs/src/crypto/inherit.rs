//! What a new file inherits, and what an existing one is allowed to be.
//!
//! A policy is never chosen per file. A new file takes its parent's policy
//! whole and gets only a fresh nonce of its own, and an existing file is only
//! reachable if its policy still matches the directory it is in. Together
//! those two rules make an encrypted directory tree uniform, which is what
//! lets a reader trust that every name below a locked directory is locked.
//!
//! The second rule has to be checked on ACCESS and not only on creation: a
//! volume can be edited offline, and a file whose policy was swapped for one
//! whose key an attacker holds would otherwise be readable from inside a tree
//! it does not belong to.

use super::inode::Info;
use super::policy::{self, Context, FsFacts, InodeFacts, Policy};
use super::uapi::FILE_NONCE_SIZE;
use super::{support, FscryptError};

/// The context a new child of `parent` is created with.
///
/// `None` when the parent is not encrypted: an unencrypted directory's
/// children are unencrypted, and nothing is inherited.
///
/// The nonce must be fresh randomness. Reusing one across files gives them the
/// same per-file key, which is the whole thing the nonce prevents.
/// # C: O(1)
pub fn context_for_new(
    parent: Option<&Info>,
    child: &InodeFacts,
    fs: &FsFacts,
    nonce: [u8; FILE_NONCE_SIZE],
) -> Result<Option<Context>, FscryptError> {
    let Some(dir) = parent else { return Ok(None) };
    let policy = *dir.policy();
    // The parent's policy has to be usable for what the CHILD is: a policy
    // that is fine on a plain directory can be refused on a case-folding one,
    // and refusing at creation is what keeps the tree consistent.
    support::check(&policy, child, fs)?;
    Ok(Some(Context { policy, nonce }))
}

/// Whether `child` may be reached from, or linked into, `parent`.
///
/// File types that are never encrypted are unrestricted; an unencrypted parent
/// restricts nothing; an encrypted parent admits only children encrypted under
/// the identical policy.
/// # C: O(1)
pub fn permitted(
    parent: Option<&Policy>,
    child_kind: &InodeFacts,
    child: Option<&Policy>,
) -> bool {
    if !child_kind.is_reg && !child_kind.is_dir && !child_kind.is_symlink { return true; }
    let Some(p) = parent else { return true };
    match child {
        // An encrypted directory holding a plaintext file would be a hole in
        // the tree that no policy covers.
        None => false,
        Some(c) => policy::equal(p, c),
    }
}
