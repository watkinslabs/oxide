// Message-digest algorithm identity as the integrity ABI numbers it. The
// numeric value is on the wire: `security.ima` digest-NG records carry the
// algorithm as its index byte, and a signature header carries it in
// `hash_algo`. Renumbering silently reinterprets every stored xattr.

use alloc::string::String;
use alloc::vec::Vec;
use crypt::Digest;

/// Algorithm slot. Discriminants are the integrity ABI's algorithm ids.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HashAlgo {
    Md4 = 0, Md5, Sha1, RipeMd160, Sha256, Sha384, Sha512, Sha224,
    RipeMd128, RipeMd256, RipeMd320, Wp256, Wp384, Wp512,
    Tgr128, Tgr160, Tgr192, Sm3_256, Streebog256, Streebog512,
    Sha3_256, Sha3_384, Sha3_512,
}

/// Number of defined algorithm slots; the first invalid id. # C: O(1)
pub const HASH_ALGO_LAST: u8 = 23;

const NAMES: [&str; HASH_ALGO_LAST as usize] = [
    "md4", "md5", "sha1", "rmd160", "sha256", "sha384", "sha512", "sha224",
    "rmd128", "rmd256", "rmd320", "wp256", "wp384", "wp512",
    "tgr128", "tgr160", "tgr192", "sm3", "streebog256", "streebog512",
    "sha3-256", "sha3-384", "sha3-512",
];

const SIZES: [usize; HASH_ALGO_LAST as usize] = [
    16, 16, 20, 20, 32, 48, 64, 28,
    16, 32, 40, 32, 48, 64,
    16, 20, 24, 32, 32, 64,
    32, 48, 64,
];

impl HashAlgo {
    /// Algorithm for an ABI id, `None` when the id is out of range. # C: O(1)
    pub fn from_id(id: u8) -> Option<Self> {
        if id >= HASH_ALGO_LAST { return None; }
        // SAFETY: HashAlgo is repr(u8) with contiguous discriminants 0..HASH_ALGO_LAST
        // and the range check above proves `id` names one of them.
        Some(unsafe { core::mem::transmute::<u8, HashAlgo>(id) })
    }

    /// ABI id of this algorithm. # C: O(1)
    pub fn id(self) -> u8 { self as u8 }

    /// Algorithm named as the policy language and xattr tooling spell it. # C: O(n)
    pub fn by_name(name: &str) -> Option<Self> {
        NAMES.iter().position(|n| *n == name).and_then(|i| Self::from_id(i as u8))
    }

    /// Canonical name. # C: O(1)
    pub fn name(self) -> &'static str { NAMES[self as usize] }

    /// Digest length in bytes. # C: O(1)
    pub fn size(self) -> usize { SIZES[self as usize] }

    /// The digest engine backing this algorithm, `None` when this kernel has
    /// no implementation — never a substitute algorithm. # C: O(1)
    pub fn engine(self) -> Option<Digest> {
        match self {
            Self::Sha1 => Some(Digest::Sha1),
            Self::Sha224 => Some(Digest::Sha224),
            Self::Sha256 => Some(Digest::Sha256),
            Self::Sha384 => Some(Digest::Sha384),
            Self::Sha512 => Some(Digest::Sha512),
            _ => None,
        }
    }

    /// Digest of `parts` hashed as one concatenated run. `None` when this
    /// kernel has no engine for the algorithm. # C: O(total)
    pub fn digest(self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        self.engine().map(|e| e.digest(parts))
    }
}

/// Lowercase hex of a digest, as the measurement list renders it. # C: O(n)
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push(nibble(b >> 4)); s.push(nibble(b & 0xf)); }
    s
}

fn nibble(v: u8) -> char { if v < 10 { (b'0' + v) as char } else { (b'a' + v - 10) as char } }

#[cfg(test)]
mod tests;
