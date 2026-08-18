//! PMM bootstrap phase boundary for early kernel initialization.

use crate::BootInfo;

/// Keep PMM construction's fixed metadata frame separate from the rest of
/// early boot, whose preceding work has already consumed part of that stack.
/// # C: O(boot memory map + managed PFNs)
#[inline(never)]
pub(super) fn init(info: &BootInfo) {
    super::init_pmm_and_arch(info);
}
