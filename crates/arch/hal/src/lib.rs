// HAL trait definitions per docs/20 (x86_64) + docs/21 (aarch64) + docs/14
// (Context). All five trait names listed in 07§5: MmuOps, CpuOps, Context,
// IrqOps, TimerOps. Per 07§5 these are NEVER `dyn`; arch-specific impls live
// in `hal-x86_64` and `hal-aarch64`, monomorphized at compile time.
//
// Method bodies live in arch crates; this crate is trait-only.

#![no_std]

pub mod fault_reentry;
pub mod fault_class;
pub mod siginfo;
pub use siginfo::{read_siginfo, write_siginfo, SigFault, SigPayload, SigPoll, Sigsys};

/// Canonical compile-time capacity for logical-CPU and per-CPU state.
pub const MAX_CPUS: usize = 256;

mod types;
pub use types::{
    AltStack, Cycles, Nanos, PageSize, Pa, Pfn, UserVirtAddr, Va,
    KERNEL_STACK_BYTES, PAGE_SHIFT, PAGE_SIZE_BYTES, USER_VA_END,
};

mod flags;
pub use flags::PageFlags;

pub mod pt_walker;
pub mod time;
pub mod uregs;
pub mod zerotrap;
pub mod smp_call;
pub mod tlb;

mod traits;
pub use traits::{Context, CpuOps, IrqOps, MachineOps, MmuOps, TimerOps};

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    #[test]
    fn each_walk_level_names_the_granule_a_leaf_there_covers() {
        assert_eq!(PageSize::from_walk_level(3), Some(PageSize::P4K));
        assert_eq!(PageSize::from_walk_level(2), Some(PageSize::P2M));
        assert_eq!(PageSize::from_walk_level(1), Some(PageSize::P1G));
    }

    #[test]
    fn a_level_that_carries_no_leaf_resolves_to_nothing() {
        // The L0 root holds no legal block leaf on either arch, so a teardown
        // walk must never turn that depth into a plausible-looking granule.
        assert_eq!(PageSize::from_walk_level(0), None);
        assert_eq!(PageSize::from_walk_level(4), None);
        assert_eq!(PageSize::from_walk_level(255), None);
    }

    #[test]
    fn a_granule_round_trips_through_its_byte_size() {
        for g in [PageSize::P4K, PageSize::P2M, PageSize::P1G] {
            assert_eq!(PageSize::from_bytes(g.bytes()), Some(g));
        }
        assert_eq!(PageSize::P4K.bytes(), PAGE_SIZE_BYTES);
    }

    #[test]
    fn a_size_no_leaf_covers_resolves_to_nothing() {
        for b in [0u64, 1, 8192, 3 << 20, (2 << 20) + 1] {
            assert_eq!(PageSize::from_bytes(b), None, "{b} bytes is not a granule");
        }
    }

    #[test]
    fn pfn_pa_roundtrip() {
        let pa = Pa(0x1234_5000);
        assert_eq!(Pfn::from_pa(pa).to_pa(), pa);
    }

    #[test]
    fn nanos_from_duration_saturates() {
        let n = Nanos::from_duration(Duration::from_secs(u64::MAX));
        assert_eq!(n, Nanos(u64::MAX));
    }
}
