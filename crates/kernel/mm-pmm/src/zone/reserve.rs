//! Lowmem reserve. `reserve[i][j]`, for `j > i`, is how many pages zone `i`
//! must keep back from an allocation class that is allowed to use zones up to
//! `j`. A class with a wider choice of zones must not be the one that empties
//! the narrow zone the constrained classes depend on, so the reserve grows
//! with the amount of memory the class could have used instead, divided by a
//! per-zone ratio. A zero ratio, or an unpopulated zone, means no reserve.

use super::types::NR_ZONES;

/// Per-zone divisor. Larger divisor, smaller reserve: the low zones hold back
/// a small fraction of the memory their fallback-capable callers could have
/// taken from higher zones instead, and the top zones hold back nothing.
pub const DEFAULT_LOWMEM_RESERVE_RATIO: [u64; NR_ZONES] = [256, 256, 32, 0];

/// Reserve matrix indexed `[zone][highest_zoneidx]`.
pub type LowmemReserve = [[u64; NR_ZONES]; NR_ZONES];

/// Derive the reserve matrix from per-zone managed page counts.
/// Monotonically non-decreasing in the second index, because a class with a
/// wider zone choice can never be entitled to deplete a low zone harder than a
/// narrower one. # C: O(NR_ZONES^2)
pub fn lowmem_reserve(managed: [u64; NR_ZONES], ratio: [u64; NR_ZONES]) -> LowmemReserve {
    let mut out = [[0u64; NR_ZONES]; NR_ZONES];
    for i in 0..NR_ZONES - 1 {
        let clear = ratio[i] == 0 || managed[i] == 0;
        let mut upper = 0u64;
        for j in (i + 1)..NR_ZONES {
            upper = upper.saturating_add(managed[j]);
            out[i][j] = if clear { 0 } else { upper / ratio[i] };
        }
    }
    out
}
