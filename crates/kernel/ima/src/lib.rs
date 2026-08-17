// Module manifest — integrity measurement and appraisal (IMA/EVM).
//
//   hash        digest algorithm identity, ABI numbering, hex rendering
//   uapi        xattr type tags, signature header, status ladder, hook identity
//   flags       action bits, rule condition bits, access mask, mode bits
//   fsmagic     filesystem magic numbers the built-in policies name
//   limits      fixed sizes, counts and the default measurement PCR
//   policy      the policy language: rules, parsing, matching, built-ins
//   template    measurement record templates and their serialisation
//   list        the measurement list: append, dedup, violations, PCR extend
//   appraise    the appraisal ladder over the security.ima xattr
//   evm         the EVM HMAC/signature over an inode's protected metadata
//   securityfs  rendering of the files the securityfs integrity tree exposes

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod appraise;
pub mod evm;
pub mod flags;
pub mod fsmagic;
pub mod hash;
pub mod limits;
pub mod list;
pub mod policy;
pub mod securityfs;
pub mod template;
pub mod uapi;

pub use hash::HashAlgo;
pub use uapi::{Hook, SigV2Hdr, Status, XattrType};
