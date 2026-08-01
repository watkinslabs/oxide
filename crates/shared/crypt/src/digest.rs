// The message-digest algorithms this kernel provides, and the ONE mapping from
// the algorithm names userspace uses to them. Anything asking for a digest by
// name — the keyring key-derivation path, a signature-scheme encoding — goes
// through here, so "which hashes exist" has a single answer and a name this
// kernel does not implement is absent rather than silently substituted.

use alloc::vec::Vec;

use crate::sha1::Sha1;
use crate::sha256::Sha256;
use crate::sha512::Sha512;

/// SHA-224 initial chaining value (FIPS 180-4 §5.3.2) over the SHA-256 core.
const H224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];
/// SHA-384 initial chaining value (FIPS 180-4 §5.3.4) over the SHA-512 core.
const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// A digest algorithm, named as userspace names it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Digest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    /// Resolve an algorithm name. `None` means this kernel has no such digest
    /// registered — the caller reports that as the absence it is, never by
    /// falling back to a different algorithm. # C: O(1)
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "sha1"   => Some(Self::Sha1),
            "sha224" => Some(Self::Sha224),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Digest output size in bytes. # C: O(1)
    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20, Self::Sha224 => 28, Self::Sha256 => 32,
            Self::Sha384 => 48, Self::Sha512 => 64,
        }
    }

    /// Compression block size in bytes. # C: O(1)
    pub fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha224 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    /// The canonical name, as it is spelled on the way in. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1", Self::Sha224 => "sha224", Self::Sha256 => "sha256",
            Self::Sha384 => "sha384", Self::Sha512 => "sha512",
        }
    }

    /// One-shot digest of a sequence of byte runs, hashed as though they were
    /// concatenated — callers hash a counter followed by key material without
    /// building the joined buffer. # C: O(total)
    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut h = Sha1::new();
                for p in parts { h.update(p); }
                h.finish().to_vec()
            }
            Self::Sha224 => {
                let mut h = Sha256::with_iv(H224);
                for p in parts { h.update(p); }
                h.finish()[..Self::Sha224.size()].to_vec()
            }
            Self::Sha256 => {
                let mut h = Sha256::new();
                for p in parts { h.update(p); }
                h.finish().to_vec()
            }
            Self::Sha384 => {
                let mut h = Sha512::with_iv(H384);
                for p in parts { h.update(p); }
                h.finish()[..Self::Sha384.size()].to_vec()
            }
            Self::Sha512 => {
                let mut h = Sha512::new();
                for p in parts { h.update(p); }
                h.finish().to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 published "abc" vectors for every algorithm the table names.
    #[test]
    fn published_abc_vectors() {
        let cases: [(&str, &str); 5] = [
            ("sha1",   "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("sha224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            ("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("sha384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
8086072ba1e7cc2358baeca134c825a7"),
            ("sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ];
        for (name, want) in cases {
            let d = Digest::by_name(name).expect("registered digest");
            let got = d.digest(&[b"abc"]);
            assert_eq!(hexed(&got), want, "{name}");
            assert_eq!(got.len(), d.size(), "{name} digest size");
        }
    }

    // A name this kernel does not implement is absent, not a near-miss.
    #[test]
    fn unknown_name_is_absent() {
        assert!(Digest::by_name("md5").is_none());
        assert!(Digest::by_name("sha3-256").is_none());
        assert!(Digest::by_name("SHA256").is_none(), "algorithm names are lowercase");
        assert!(Digest::by_name("").is_none());
    }

    // Hashing separate runs must equal hashing the concatenation, or the
    // counter-mode derivation below would depend on how its input was split.
    #[test]
    fn parts_hash_as_the_concatenation() {
        for name in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
            let d = Digest::by_name(name).expect("registered digest");
            assert_eq!(d.digest(&[b"abc", b"def", b"ghi"]), d.digest(&[b"abcdefghi"]), "{name}");
        }
    }

    fn hexed(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b { let _ = write!(s, "{x:02x}"); }
        s
    }
}
