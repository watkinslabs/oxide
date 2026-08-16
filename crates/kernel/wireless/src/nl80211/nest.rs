// Writing a 64-bit value inside a nested attribute space.
//
// Netlink needs an eight-byte-aligned payload for a 64-bit attribute and
// reaches that by emitting a padding attribute first. The padding attribute's
// NUMBER is per-namespace: the padding type of the top-level space is a
// different number inside the station report, the network report, the survey
// and the per-identifier counters. Using the top-level number inside a nest
// writes an attribute the reader will try to interpret as something else.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::attr;

/// Append a `u64` attribute inside a nest, padding with that nest's own
/// padding attribute. # C: O(1)
pub fn put_u64(out: &mut Vec<u8>, ty: u16, v: u64, pad_ty: u16) {
    attr::put_u64_64bit(out, ty, v, pad_ty);
}
