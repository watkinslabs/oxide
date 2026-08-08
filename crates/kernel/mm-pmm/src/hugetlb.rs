// Hugetlb page pool — Linux `hstate` + `hugepage_subpool` per `10§5`, `11§5`.
//
// Module manifest:
//   `sizes`   owns the supported huge-page granules and the flag-word
//             size-log encoding every syscall that names one shares.
//   `hstate`  owns the per-size pool COUNTERS and their state machine
//             (persistent/surplus/reserve/free) with no allocator contact.
//   `subpool` owns per-mount max/min accounting (`hugetlbfs` `size=` /
//             `min_size=`) with no allocator contact.
//   `pool`    owns the live pool: the reserved huge frames themselves,
//             grow/shrink against the buddy, and hand-out/return.
//   `tests`   owns the hosted unit tests for the three ungated modules.
//
// `hstate` and `subpool` are deliberately free of allocator calls so the
// accounting decisions are hosted-testable; `pool` is the only module that
// touches physical memory.

mod sizes;
mod hstate;
mod subpool;
mod pool;
#[cfg(test)]
mod tests;

pub use sizes::{HugePageSize, size_from_log, DEFAULT_HUGE_SHIFT, HUGE_FLAG_ENCODE_MASK, HUGE_FLAG_ENCODE_SHIFT};
pub use hstate::{HstateCounts, ResizePlan};
pub use subpool::{Subpool, SubpoolCharge, NO_LIMIT};
pub use pool::{
    alloc_huge_frame, free_huge_frame, huge_frame_dec_and_maybe_release, huge_frame_inc_ref,
    huge_frame_unmap_ref, nr_hugepages, free_hugepages, resv_hugepages, surplus_hugepages,
    nr_overcommit_hugepages, set_nr_overcommit_hugepages, set_nr_hugepages, reserve, unreserve,
    owns,
};
pub use sizes::{size_from_flags, size_log_from_flags, GIGANTIC_HUGE_SHIFT};
