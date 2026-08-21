// Taking the crash region out of the page allocator at boot.
//
// A shim over `parse` and `place`: it supplies the physical facts (the boot
// line, the usable ranges, the total managed memory) and performs the one
// side effect. Every decision it acts on is made in an ungated module, so the
// only thing a boot can get wrong here is the wiring.

use crate::crashk::parse::{parse_line, round_system_ram};
use crate::crashk::place::{place, Placement, RamRange};
use crate::uapi::PAGE_SIZE;

/// Resolve the boot line against the machine and reserve the result.
///
/// MUST run immediately after allocator init and before the first allocation.
/// The reservation removes pages from the free lists and a page already handed
/// out is silently skipped — a region reserved late would overlap live kernel
/// memory, and the overlap would only be discovered by the crash kernel
/// overwriting it during the one boot that had to work.
/// # SAFETY: caller is the boot path, single-CPU, after allocator init and
/// before any allocation from it.
/// # C: O(region length / page size)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn reserve() {
    let Some(pmm) = pmm::setup::pmm_static() else { return };
    let total = pmm.snapshot().managed_pages * PAGE_SIZE;
    let spec = parse_line(cmdline::get(), round_system_ram(total));
    let ram = usable_ranges();
    let Ok(p) = place(&spec, &ram) else { return };
    // The companion region first: its failure aborts the whole reservation,
    // and undoing a main region already removed from the free lists is not
    // something the boot path can do.
    if p.low_size != 0 && !take(p.low_base, p.low_size) { return; }
    if !take(p.base, p.size) { return; }
    crate::crashk::publish(p.base, p.size);
    announce(&p);
}

/// Remove `[base, base+size)` from the page allocator. # C: O(size / page size)
fn take(base: u64, size: u64) -> bool {
    let Some(pmm) = pmm::setup::pmm_static() else { return false };
    pmm.reserve_early_nosave(hal::Pfn(base / PAGE_SIZE), size / PAGE_SIZE).is_ok()
}

/// The usable-RAM ranges the allocator was seeded from. # C: O(N_ranges)
fn usable_ranges() -> alloc::vec::Vec<RamRange> {
    pmm::setup::usable_regions().iter().map(|r| RamRange {
        start: r.start.0 * PAGE_SIZE,
        end: (r.start.0 + r.len_pfn) * PAGE_SIZE,
    }).collect()
}

/// Say what was reserved. The size and the base are the two facts that decide
/// whether a later crash load can succeed at all, and neither is derivable
/// from anything else in the boot log. # C: O(1)
fn announce(p: &Placement) {
    #[cfg(feature = "debug-kexec")] {
        klog::write_raw(b"crashkernel: base=");
        klog::write_hex_u64(p.base);
        klog::write_raw(b" size=");
        klog::write_dec_u64(p.size);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-kexec"))] { let _ = p; }
}
