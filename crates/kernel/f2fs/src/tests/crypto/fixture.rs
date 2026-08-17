//! One master key, one nonce, one volume identity, shared by every vector.
//!
//! The values are arbitrary but FIXED: every derived key below is a known
//! answer computed from them by an independent implementation of the same
//! specifications, so a change to any step of the derivation shows up as a
//! changed key rather than as a still-round-tripping different one.

use alloc::vec::Vec;

use crate::crypto::policy::{Context, FsFacts, InodeFacts, KeyId, Policy};
use crate::crypto::uapi::*;
use crate::crypto::{Info, MasterKey};

/// Bytes of a hex literal. # C: O(n)
pub fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 2 * N, "hex literal is the wrong width");
    let d = |c: u8| -> u8 {
        match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => panic!("hex") }
    };
    let mut out = [0u8; N];
    for i in 0..N { out[i] = (d(b[2 * i]) << 4) | d(b[2 * i + 1]); }
    out
}

/// Hex of arbitrary length, for a vector whose width is not a constant.
/// # C: O(n)
pub fn hexv(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    let b = s.as_bytes();
    let d = |c: u8| -> u8 {
        match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => panic!("hex") }
    };
    (0..s.len() / 2).map(|i| (d(b[2 * i]) << 4) | d(b[2 * i + 1])).collect()
}

/// The 64-byte master key every vector derives from.
pub fn master_bytes() -> [u8; 64] { core::array::from_fn(|i| (0x40 + i) as u8) }
/// The per-file nonce every vector uses.
pub fn nonce() -> [u8; FILE_NONCE_SIZE] { core::array::from_fn(|i| (0x10 + i) as u8) }
/// The volume identity the per-mode derivations bind to.
pub fn uuid() -> [u8; 16] { core::array::from_fn(|i| (0xa0 + i) as u8) }

pub fn master() -> MasterKey { MasterKey::new(&master_bytes()).unwrap() }

/// The identifier the master key hashes to, which a v2 policy must name.
pub const IDENTIFIER: &str = "db8e98d43245f645e5b16a209bb2752b";

/// A volume with 4 KiB blocks and a file ceiling wide enough for the
/// inode-in-the-IV policies.
pub fn fs() -> FsFacts { FsFacts { max_file_bytes: 1 << 42, blkbits: 12 } }

pub fn reg() -> InodeFacts {
    InodeFacts { is_dir: false, is_reg: true, is_symlink: false, casefolded: false }
}
pub fn dir() -> InodeFacts {
    InodeFacts { is_dir: true, is_reg: false, is_symlink: false, casefolded: false }
}
pub fn folding_dir() -> InodeFacts {
    InodeFacts { is_dir: true, is_reg: false, is_symlink: false, casefolded: true }
}
pub fn lnk() -> InodeFacts {
    InodeFacts { is_dir: false, is_reg: false, is_symlink: true, casefolded: false }
}

/// A v2 policy naming this fixture's key.
pub fn policy_v2(contents: u8, names: u8, flags: u8) -> Policy {
    Policy {
        version: POLICY_V2,
        contents_mode: contents,
        filenames_mode: names,
        flags,
        log2_data_unit_size: 0,
        key: KeyId::Identifier(hex(IDENTIFIER)),
    }
}

/// A v1 policy naming an arbitrary descriptor.
pub fn policy_v1(contents: u8, names: u8, flags: u8) -> Policy {
    Policy {
        version: POLICY_V1,
        contents_mode: contents,
        filenames_mode: names,
        flags,
        log2_data_unit_size: 0,
        key: KeyId::Descriptor([1, 2, 3, 4, 5, 6, 7, 8]),
    }
}

pub fn ctx(policy: Policy) -> Context { Context { policy, nonce: nonce() } }

/// The default v2 pairing: contents by the tweakable mode, names by stealing.
pub fn default_v2() -> Policy { policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAGS_PAD_4) }

/// An inode's encryption under the default policy.
pub fn info(kind: InodeFacts, ino: u32) -> Info {
    Info::setup(&ctx(default_v2()), &kind, &fs(), &master(), &uuid(), ino).unwrap()
}
