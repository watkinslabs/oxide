// Keyed hashing for the EVM metadata label. The construction is the standard
// one: the key padded to the compression block, XORed with two distinct pads,
// hashed inner-then-outer.
//
// This lives here only because no shared keyed-hash module exists yet; it is a
// candidate to move beside the digest implementations once one does.

use alloc::vec::Vec;

use crate::hash::HashAlgo;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Keyed hash of `msg` under `key` with `algo`. `None` when this kernel has no
/// engine for the algorithm. # C: O(len(key) + len(msg))
pub fn hmac(algo: HashAlgo, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let engine = algo.engine()?;
    let block = engine.block_size();
    let mut k = alloc::vec![0u8; block];
    if key.len() > block {
        let h = algo.digest(&[key])?;
        k[..h.len()].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = alloc::vec![0u8; block];
    let mut opad = alloc::vec![0u8; block];
    for i in 0..block { ipad[i] = k[i] ^ IPAD; opad[i] = k[i] ^ OPAD; }
    let inner = algo.digest(&[&ipad, msg])?;
    algo.digest(&[&opad, &inner])
}
