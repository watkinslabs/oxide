// XTS over AES.
//
// The mode is written once, generically, in `blockcipher`, because the tweak's
// field arithmetic is a property of the 128-bit block and not of AES — SM4-XTS
// is the same construction with a different transform underneath. A second
// copy of the little-endian doubling would agree with itself on the first
// block of every unit and with nothing after it, which no round-trip catches.
//
// `Xts` names the AES pairing: a 32-byte key is AES-128-XTS and a 64-byte key
// is AES-256-XTS, because the halves are what the cipher sees.

use crate::block::AesKey;

pub use blockcipher::xts::{unit_tweak, XtsError};

/// XTS with AES underneath.
pub type Xts = blockcipher::xts::Xts<AesKey>;
