//! The encryption policy as the ioctl carries it, which is NOT the form the
//! medium stores.
//!
//! The stored context puts the version byte first and appends the file's own
//! nonce; the wire policy has neither the nonce nor the same field order, and
//! its first byte is a version number rather than a context version. Treating
//! one as the other reads a mode byte as a version and sets a policy nothing
//! can open.

use alloc::vec::Vec;

use crate::crypto::policy::{KeyId, Policy};
use crate::crypto::uapi::*;
use crate::crypto::FscryptError;

use super::uapi::{POLICY_V1_SIZE, POLICY_V2_SIZE};

/// Offsets shared by both wire versions.
const W_VERSION: usize = 0;
const W_CONTENTS_MODE: usize = 1;
const W_FILENAMES_MODE: usize = 2;
const W_FLAGS: usize = 3;
/// Version one puts the eight-byte descriptor straight after the head.
const W_V1_DESCRIPTOR: usize = 4;
/// Version two spends the same word on a data-unit shift and three reserved
/// bytes before the sixteen-byte identifier.
const W_V2_LOG2_DU: usize = 4;
const W_V2_RESERVED: usize = 5;
const W_V2_RESERVED_LEN: usize = 3;
const W_V2_IDENTIFIER: usize = 8;

/// Decode a policy as a caller sends it.
///
/// The first byte decides the length, so a caller sending the shorter version
/// is accepted from a buffer that only holds the shorter version.
/// # C: O(1)
pub fn parse_wire(b: &[u8]) -> Result<Policy, FscryptError> {
    let version = *b.first().ok_or(FscryptError::BadContext)?;
    match version {
        POLICY_V1 => {
            if b.len() < POLICY_V1_SIZE as usize { return Err(FscryptError::BadContext); }
            let mut d = [0u8; KEY_DESCRIPTOR_SIZE];
            d.copy_from_slice(&b[W_V1_DESCRIPTOR..W_V1_DESCRIPTOR + KEY_DESCRIPTOR_SIZE]);
            Ok(Policy {
                version,
                contents_mode: b[W_CONTENTS_MODE],
                filenames_mode: b[W_FILENAMES_MODE],
                flags: b[W_FLAGS],
                log2_data_unit_size: 0,
                key: KeyId::Descriptor(d),
            })
        }
        POLICY_V2 => {
            if b.len() < POLICY_V2_SIZE as usize { return Err(FscryptError::BadContext); }
            if b[W_V2_RESERVED..W_V2_RESERVED + W_V2_RESERVED_LEN].iter().any(|&x| x != 0) {
                return Err(FscryptError::ReservedSet);
            }
            let mut id = [0u8; KEY_IDENTIFIER_SIZE];
            id.copy_from_slice(&b[W_V2_IDENTIFIER..W_V2_IDENTIFIER + KEY_IDENTIFIER_SIZE]);
            Ok(Policy {
                version,
                contents_mode: b[W_CONTENTS_MODE],
                filenames_mode: b[W_FILENAMES_MODE],
                flags: b[W_FLAGS],
                log2_data_unit_size: b[W_V2_LOG2_DU],
                key: KeyId::Identifier(id),
            })
        }
        _ => Err(FscryptError::UnknownContextVersion(version)),
    }
}

/// How many wire bytes a policy occupies. # C: O(1)
pub fn wire_len(p: &Policy) -> usize {
    match p.key {
        KeyId::Descriptor(_) => POLICY_V1_SIZE as usize,
        KeyId::Identifier(_) => POLICY_V2_SIZE as usize,
    }
}

/// Encode a policy as a caller reads it back. # C: O(1)
pub fn encode_wire(p: &Policy) -> Vec<u8> {
    let mut b = alloc::vec![0u8; wire_len(p)];
    b[W_CONTENTS_MODE] = p.contents_mode;
    b[W_FILENAMES_MODE] = p.filenames_mode;
    b[W_FLAGS] = p.flags;
    match p.key {
        KeyId::Descriptor(d) => {
            b[W_VERSION] = POLICY_V1;
            b[W_V1_DESCRIPTOR..W_V1_DESCRIPTOR + KEY_DESCRIPTOR_SIZE].copy_from_slice(&d);
        }
        KeyId::Identifier(id) => {
            b[W_VERSION] = POLICY_V2;
            b[W_V2_LOG2_DU] = p.log2_data_unit_size;
            b[W_V2_IDENTIFIER..W_V2_IDENTIFIER + KEY_IDENTIFIER_SIZE].copy_from_slice(&id);
        }
    }
    b
}

/// Encode a policy for the OLDER query, which has no room for the newer form.
///
/// `None` when the policy is a version that query cannot express — the
/// caller is told to ask through the extended query rather than handed a
/// truncated policy that names a different key.
/// # C: O(1)
pub fn encode_v1(p: &Policy) -> Option<Vec<u8>> {
    match p.key {
        KeyId::Descriptor(_) => Some(encode_wire(p)),
        KeyId::Identifier(_) => None,
    }
}

#[cfg(test)]
#[path = "../tests/ioctl/policy.rs"]
mod tests;
