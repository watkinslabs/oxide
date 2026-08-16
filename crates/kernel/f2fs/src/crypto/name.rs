//! Preparing a name for a lookup, and presenting a stored one to a listing.
//!
//! Three states, and the directory is in exactly one of them:
//!
//! - Not encrypted: the name the caller gave is the name on the medium.
//! - Encrypted, key present: the caller's name is the plaintext, so it is
//!   encrypted and the ciphertext is what the entry is compared against.
//! - Encrypted, key absent: the caller's name is a no-key name that a previous
//!   listing produced, so it is decoded back into the hash and whatever part
//!   of the ciphertext it carries.
//!
//! The third state is only permitted for operations that can proceed without
//! the key — finding an entry, and removing one. Creating an entry needs the
//! plaintext to encrypt, so without the key it is `ENOKEY` rather than a name
//! made of whatever bytes were supplied.

use alloc::vec::Vec;

use super::inode::Info;
use super::nokey::{self, NoKeyName};
use super::FscryptError;

/// A name prepared for searching a directory.
pub enum Search {
    /// Compare the stored bytes against these.
    Exact(Vec<u8>),
    /// Compare by the abbreviated record, which carries a digest of the tail
    /// rather than the whole ciphertext.
    NoKey(NoKeyName),
}

impl Search {
    /// The bytes an entry must hold, when the whole name is known. # C: O(1)
    pub fn disk_name(&self) -> Option<&[u8]> {
        match self {
            Search::Exact(v) => Some(v),
            Search::NoKey(n) => n.disk_name(),
        }
    }

    /// The hash decoded from a no-key name, which is the only way to find the
    /// bucket when the stored hash cannot be recomputed. # C: O(1)
    pub fn hash(&self) -> Option<u32> {
        match self { Search::NoKey(n) => Some(n.hash), Search::Exact(_) => None }
    }

    /// Whether the entry named `de_name` answers this search.
    /// # C: O(len(de_name))
    pub fn matches(&self, de_name: &[u8]) -> bool {
        match self {
            Search::Exact(v) => de_name == &v[..],
            Search::NoKey(n) => n.matches(de_name),
        }
    }
}

/// Prepare `name` for a search of a directory whose encryption is `dir`.
///
/// `may_be_nokey` is true for the operations that are allowed to proceed
/// without the key. When it is false and the key is absent, the answer is
/// `ENOKEY`: there is no way to produce the ciphertext a new entry would need.
/// # C: O(len(name))
pub fn setup(dir: Option<&Info>, name: &[u8], may_be_nokey: bool)
    -> Result<Search, FscryptError> {
    match dir {
        // The two exempt names are stored as themselves in every directory.
        _ if crate::hash::is_dot_or_dotdot(name) => Ok(Search::Exact(Vec::from(name))),
        Some(info) => Ok(Search::Exact(info.encrypt_name(name)?)),
        None if may_be_nokey => Ok(Search::NoKey(nokey::parse(name)?)),
        None => Err(FscryptError::NoKey),
    }
}

/// The name a listing reports for an entry storing `disk_name` under `hash`.
///
/// With the key it is the plaintext; without it, the encoded record that a
/// later lookup can decode back — so what a listing shows is always a name
/// that works.
/// # C: O(len(disk_name))
pub fn present(dir: Option<&Info>, hash: u32, disk_name: &[u8])
    -> Result<Vec<u8>, FscryptError> {
    match dir {
        Some(info) => info.decrypt_name(disk_name),
        None => nokey::present(hash, 0, disk_name),
    }
}
