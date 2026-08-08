//! FNV-1a, the mixer the folded name hash is built from — the same function the
//! dcache uses for a byte-exact name, so a casefolded superblock's hashes are
//! distributed like every other superblock's.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME:  u64 = 0x0000_0100_0000_01B3;
const FOLD_SHIFT: u32 = 32;

/// # C: O(1)
pub(crate) fn init() -> u64 { FNV_OFFSET }

/// # C: O(1)
pub(crate) fn step(h: u64, b: u8) -> u64 { (h ^ b as u64).wrapping_mul(FNV_PRIME) }

/// Fold the 64-bit accumulator down to the dcache's 32-bit hash. # C: O(1)
pub(crate) fn finish(h: u64) -> u32 { (h ^ (h >> FOLD_SHIFT)) as u32 }
