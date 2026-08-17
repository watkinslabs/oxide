//! File-name and file-contents encryption.
//!
//! An encrypted file's bytes and an encrypted directory's names are never
//! stored in the clear, and the key is not on the volume. What IS on the
//! volume, in an extended attribute on every encrypted inode, is a CONTEXT: a
//! policy naming the modes and the derivation rules, plus a per-file random
//! nonce. The context says how to use the key; it never says what the key is.
//!
//! Four ideas run through everything here, and each of them, got wrong,
//! produces bytes that decrypt perfectly against themselves and against no
//! other reader of the same volume:
//!
//! - **The master key is not a cipher key.** Every key that actually encrypts
//!   something is derived from it, under a context byte that keeps the
//!   purposes apart. The older policy version is the exception, and its
//!   inability to derive a second output is exactly why it cannot be used on
//!   a case-folding directory.
//! - **The IV carries the derivation choice.** A per-file key needs only the
//!   data unit index; a key shared across a volume needs the inode number in
//!   the IV instead; a key shared across a mode needs the file's nonce there.
//!   All three are well-formed IVs and only one is right for a given policy.
//! - **A name is a message, not a stream.** It is padded to hide its length
//!   and encrypted whole at index zero, so one name has one ciphertext and a
//!   lookup can search by it.
//! - **A locked directory must still list.** Without the key a name is shown
//!   as an encoded record carrying the entry's hash and its ciphertext, so the
//!   name a listing prints is a name a later lookup or unlink can use.
//!
//! Case folding meets encryption in one place and it is not optional: such a
//! directory hashes the FOLDED PLAINTEXT under a derived key, not the stored
//! ciphertext, because two spellings of one name encrypt differently and would
//! otherwise land in different buckets.
//!
//! Module manifest:
//! - `uapi`:     modes, policy flags, the context layout, derivation contexts.
//! - `mode`:     what a mode number means — key width, IV width, strength.
//! - `policy`:   the policy and the stored context, parsed and serialized.
//! - `support`:  whether a policy may be used, here, on this inode.
//! - `key`:      the master key and every subkey derived from it.
//! - `cipher`:   the prepared ciphers the modes name.
//! - `iv`:       the initialisation vector for one data unit.
//! - `fname`:    name padding and the stored length it implies.
//! - `base64`:   the encoding a presented ciphertext name uses.
//! - `nokey`:    the name a locked directory shows, and matching by it.
//! - `inode`:    an inode's assembled encryption and its operations.
//! - `name`:     preparing a lookup and presenting a listing.
//! - `symlink`:  an encrypted link's stored target.
//! - `inherit`:  what a new file takes, and what an existing one may be.
//! - `inline`:   choosing the block layer to encrypt file contents instead.

use syscall::errno::Errno;

pub mod uapi;
pub mod mode;
pub mod policy;
pub mod support;
pub mod key;
pub mod cipher;
pub mod iv;
pub mod fname;
pub mod base64;
pub mod nokey;
pub mod inode;
pub mod name;
pub mod symlink;
pub mod inherit;
pub mod inline;

pub use inode::Info;
pub use key::MasterKey;
pub use name::{present, setup, Search};
pub use policy::{Context, FsFacts, InodeFacts, KeyId, Policy};

/// Why an encrypted file could not be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FscryptError {
    /// The stored context is not a record of any known version and size.
    BadContext,
    /// A context version this build does not know.
    UnknownContextVersion(u8),
    /// Bytes the format holds back for later fields are set, so the context
    /// describes something this build would silently ignore.
    ReservedSet,
    /// A mode number the format does not assign.
    UnknownMode(u8),
    /// A mode the format assigns and this build has no cipher for.
    UnsupportedMode(u8),
    /// Contents and filename modes that were never defined to pair.
    ModePairNotAllowed,
    /// Policy flags outside the set this version defines.
    UnsupportedFlags(u8),
    /// More than one key-derivation flag, which names no derivation.
    MutuallyExclusiveFlags(u8),
    /// The direct-key flag with different contents and filename modes.
    DirectKeyModesDiffer,
    /// The direct-key flag with a mode whose IV cannot hold the file nonce.
    DirectKeyIvTooSmall,
    /// An inode-in-the-IV policy with a mode it was not defined for.
    IvInoLblkMode,
    /// An inode-in-the-IV policy on a volume that cannot satisfy it.
    IvInoLblkVolume,
    /// A data unit size outside what the policy and volume admit.
    DataUnitSize,
    /// The older policy version on a case-folding directory, which it has no
    /// way to derive a hash key for.
    V1WithCasefold,
    /// A file type that is never encrypted.
    NotEncryptable,
    /// A key length no mode or derivation accepts.
    BadKeySize(usize),
    /// A master key too short for the key it must produce.
    KeyTooShort,
    /// The key presented is not the key the policy names.
    KeyMismatch,
    /// The key is absent, and the operation cannot proceed without it.
    NoKey,
    /// A buffer whose length no cipher in use accepts.
    BadLength(usize),
    /// A stored name that did not come from this construction.
    CorruptName,
    /// A name whose padded, encrypted form would exceed what an entry holds.
    NameTooLong,
    /// A presented name that decodes to no well-formed record, and so names
    /// no entry.
    NoSuchName,
    /// A hardware-wrapped key under a policy that cannot use one: the older
    /// policy version, or a derivation rule whose key is per file. Neither can
    /// be satisfied by a blob software cannot unwrap.
    HwWrappedPolicy,
    /// A hardware-wrapped key on a file whose contents nothing here can
    /// encrypt: the mount did not ask for inline encryption, or no device
    /// under it takes wrapped keys. Refused rather than served in software,
    /// which for this key is not possible at all.
    HwWrappedNoInline,
    /// A filesystem-side crypto operation on an inode whose contents the block
    /// layer encrypts. Doing it here as well would encipher the bytes twice.
    InlineOnly,
}

impl FscryptError {
    /// What a caller reports for this.
    ///
    /// A policy this build cannot honour is `EINVAL` — the volume is
    /// intelligible and the request is not. An absent key is `ENOKEY`, which a
    /// caller can act on by supplying one. A stored record that cannot have
    /// been written by this construction is `EUCLEAN`: the volume is damaged,
    /// not merely unreadable here.
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self {
            Self::BadContext | Self::UnknownContextVersion(_) | Self::ReservedSet
            | Self::UnknownMode(_) | Self::ModePairNotAllowed | Self::UnsupportedFlags(_)
            | Self::MutuallyExclusiveFlags(_) | Self::DirectKeyModesDiffer
            | Self::DirectKeyIvTooSmall | Self::IvInoLblkMode | Self::IvInoLblkVolume
            | Self::DataUnitSize | Self::V1WithCasefold | Self::NotEncryptable
            | Self::BadKeySize(_) | Self::BadLength(_) | Self::HwWrappedPolicy
            | Self::HwWrappedNoInline | Self::InlineOnly => Errno::Einval,
            // A mode another kernel carries is not a broken volume: the file
            // is intact and a different reader can open it.
            Self::UnsupportedMode(_) => Errno::Enopkg,
            Self::KeyTooShort | Self::KeyMismatch | Self::NoKey => Errno::Enokey,
            Self::CorruptName => Errno::Euclean,
            Self::NameTooLong => Errno::Enametoolong,
            Self::NoSuchName => Errno::Enoent,
        }
    }
}

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod tests;
