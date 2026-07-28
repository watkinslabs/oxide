// `vm.mmap_rnd_bits` — the live entropy width `arch_mmap_rnd()` reads.
// Linux `mm/mmap.c:66-75` plus its `proc_dointvec_minmax` registration
// (`mm/mmap.c:1539-1560`, mode 0600), bounded by the arch's Kconfig pair.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::limits::CURRENT;

/// Linux `int mmap_rnd_bits __read_mostly = CONFIG_ARCH_MMAP_RND_BITS`.
/// Neither x86 nor arm64 sets `ARCH_MMAP_RND_BITS_DEFAULT`, so the boot value
/// is the arch minimum (`arch/Kconfig:1227-1232`).
static MMAP_RND_BITS: AtomicU32 = AtomicU32::new(CURRENT.mmap_rnd_bits);

/// Linux `const int mmap_rnd_bits_min`. # C: O(1)
pub const fn mmap_rnd_bits_min() -> u32 { CURRENT.mmap_rnd_bits_min }

/// Linux `int mmap_rnd_bits_max __ro_after_init`. # C: O(1)
pub const fn mmap_rnd_bits_max() -> u32 { CURRENT.mmap_rnd_bits_max }

/// Live `vm.mmap_rnd_bits`. # C: O(1)
pub fn mmap_rnd_bits() -> u32 { MMAP_RND_BITS.load(Ordering::Relaxed) }

/// `proc_dointvec_minmax` write path: out-of-range writes are rejected by the
/// handler in Linux, so the clamp here is belt-and-braces for callers that
/// bypass the sysctl bounds.
/// # C: O(1)
pub fn set_mmap_rnd_bits(v: u32) {
    MMAP_RND_BITS.store(v.clamp(mmap_rnd_bits_min(), mmap_rnd_bits_max()), Ordering::Relaxed);
}
