//! The policy a file is encrypted under, and the context that records it.
//!
//! The context is an extended attribute on the inode; the policy is what it
//! says minus the per-file nonce. Two versions exist and they are not a
//! superset relationship:
//!
//! - v1 names its master key by an arbitrary 8-byte DESCRIPTOR the user chose,
//!   and derives per-file keys with a construction that predates the current
//!   one. It cannot derive a directory hash key, so it cannot be combined with
//!   case folding — a v1 policy on a case-folding directory is refused rather
//!   than silently hashed the wrong way.
//! - v2 names its key by a 16-byte IDENTIFIER that is a hash OF the key, so
//!   presenting the wrong key is detected instead of producing garbage.
//!
//! A context that survives parsing has NOT been checked for sense: whether the
//! modes pair, whether the flags are mutually exclusive, and whether the
//! volume can honour them is a separate question, asked by `check`.

use super::uapi::*;
use super::{mode, FscryptError};

/// How a policy names its master key.
///
/// Ordered so a mount can hold its added keys in a map keyed by the name a
/// policy refers to one by — which is the only lookup an inode ever does.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum KeyId {
    /// v1: eight bytes the user picked. Nothing verifies the key matches.
    Descriptor([u8; KEY_DESCRIPTOR_SIZE]),
    /// v2: sixteen bytes derived from the key, so a wrong key is caught.
    Identifier([u8; KEY_IDENTIFIER_SIZE]),
}

/// An encryption policy.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Policy {
    pub version: u8,
    pub contents_mode: u8,
    pub filenames_mode: u8,
    pub flags: u8,
    /// v2 only; zero means "the block size".
    pub log2_data_unit_size: u8,
    pub key: KeyId,
}

/// A policy plus the file's own nonce: what the inode stores.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Context {
    pub policy: Policy,
    pub nonce: [u8; FILE_NONCE_SIZE],
}

/// What the volume can offer a policy, so the checks that depend on the
/// filesystem are answered from facts rather than assumed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FsFacts {
    /// Largest byte offset a file on this volume can reach.
    pub max_file_bytes: u64,
    /// log2 of the block size.
    pub blkbits: u8,
}

/// What the inode is, for the checks that depend on it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct InodeFacts {
    pub is_dir: bool,
    pub is_reg: bool,
    pub is_symlink: bool,
    pub casefolded: bool,
}

impl Policy {
    /// Bytes a filename is padded up to. # C: O(1)
    pub fn padding(&self) -> usize { 4usize << (self.flags & FLAGS_PAD_MASK) }

    /// log2 of the contents encryption granularity for an inode on this
    /// volume. A v1 policy has no field for it and always uses the block.
    /// # C: O(1)
    pub fn data_unit_bits(&self, fs: &FsFacts) -> u8 {
        match self.version {
            POLICY_V2 if self.log2_data_unit_size != 0 => self.log2_data_unit_size,
            _ => fs.blkbits,
        }
    }

    /// The mode this inode encrypts with: contents for a regular file, names
    /// for a directory or a symlink. Nothing else is encryptable.
    /// # C: O(1)
    pub fn mode_for(&self, inode: &InodeFacts) -> Result<mode::Mode, FscryptError> {
        if inode.is_reg { return mode::by_number(self.contents_mode); }
        if inode.is_dir || inode.is_symlink { return mode::by_number(self.filenames_mode); }
        Err(FscryptError::NotEncryptable)
    }
}

/// Read a stored context. The size must be exactly what the version implies —
/// a short record is a different structure, not a truncated one, and reading
/// a nonce out of the bytes past it would produce a plausible wrong key.
/// # C: O(1)
pub fn parse(bytes: &[u8]) -> Result<Context, FscryptError> {
    let version = *bytes.first().ok_or(FscryptError::BadContext)?;
    let want = match version {
        CONTEXT_V1 => CONTEXT_V1_SIZE,
        CONTEXT_V2 => CONTEXT_V2_SIZE,
        _ => return Err(FscryptError::UnknownContextVersion(version)),
    };
    if bytes.len() != want { return Err(FscryptError::BadContext); }
    let mut nonce = [0u8; FILE_NONCE_SIZE];
    let policy = match version {
        CONTEXT_V1 => {
            let mut d = [0u8; KEY_DESCRIPTOR_SIZE];
            d.copy_from_slice(&bytes[CTX_V1_DESCRIPTOR..CTX_V1_DESCRIPTOR + KEY_DESCRIPTOR_SIZE]);
            nonce.copy_from_slice(&bytes[CTX_V1_NONCE..CTX_V1_NONCE + FILE_NONCE_SIZE]);
            Policy {
                version: POLICY_V1,
                contents_mode: bytes[CTX_CONTENTS_MODE],
                filenames_mode: bytes[CTX_FILENAMES_MODE],
                flags: bytes[CTX_FLAGS],
                log2_data_unit_size: 0,
                key: KeyId::Descriptor(d),
            }
        }
        _ => {
            let mut id = [0u8; KEY_IDENTIFIER_SIZE];
            id.copy_from_slice(&bytes[CTX_V2_IDENTIFIER..CTX_V2_IDENTIFIER + KEY_IDENTIFIER_SIZE]);
            nonce.copy_from_slice(&bytes[CTX_V2_NONCE..CTX_V2_NONCE + FILE_NONCE_SIZE]);
            // The reserved bytes are part of the policy: a context with them
            // set describes settings this build would ignore, so it is
            // refused by `check` rather than read past.
            Policy {
                version: POLICY_V2,
                contents_mode: bytes[CTX_CONTENTS_MODE],
                filenames_mode: bytes[CTX_FILENAMES_MODE],
                flags: bytes[CTX_FLAGS],
                log2_data_unit_size: bytes[CTX_V2_LOG2_DU],
                key: KeyId::Identifier(id),
            }
        }
    };
    if version == CONTEXT_V2
        && bytes[CTX_V2_RESERVED..CTX_V2_RESERVED + CTX_V2_RESERVED_LEN].iter().any(|&b| b != 0)
    {
        return Err(FscryptError::ReservedSet);
    }
    Ok(Context { policy, nonce })
}

/// The bytes a context is stored as, and how many of the buffer they use.
/// # C: O(1)
pub fn serialize(ctx: &Context) -> ([u8; CONTEXT_V2_SIZE], usize) {
    let mut out = [0u8; CONTEXT_V2_SIZE];
    out[CTX_CONTENTS_MODE] = ctx.policy.contents_mode;
    out[CTX_FILENAMES_MODE] = ctx.policy.filenames_mode;
    out[CTX_FLAGS] = ctx.policy.flags;
    match ctx.policy.key {
        KeyId::Descriptor(d) => {
            out[CTX_VERSION] = CONTEXT_V1;
            out[CTX_V1_DESCRIPTOR..CTX_V1_DESCRIPTOR + KEY_DESCRIPTOR_SIZE].copy_from_slice(&d);
            out[CTX_V1_NONCE..CTX_V1_NONCE + FILE_NONCE_SIZE].copy_from_slice(&ctx.nonce);
            (out, CONTEXT_V1_SIZE)
        }
        KeyId::Identifier(id) => {
            out[CTX_VERSION] = CONTEXT_V2;
            out[CTX_V2_LOG2_DU] = ctx.policy.log2_data_unit_size;
            out[CTX_V2_IDENTIFIER..CTX_V2_IDENTIFIER + KEY_IDENTIFIER_SIZE].copy_from_slice(&id);
            out[CTX_V2_NONCE..CTX_V2_NONCE + FILE_NONCE_SIZE].copy_from_slice(&ctx.nonce);
            (out, CONTEXT_V2_SIZE)
        }
    }
}

/// Whether two policies are the same policy. # C: O(1)
pub fn equal(a: &Policy, b: &Policy) -> bool { a == b }
