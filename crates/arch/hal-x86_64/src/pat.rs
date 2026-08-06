//! x86 Page Attribute Table setup and cache-mode encoding.
//!
//! Linux programs the same table on every CPU:
//! `WB, WC, UC-, UC, WB, WP, UC-, WT`. Keeping strong UC in slot 3 means
//! device mappings encoded as `PCD|PWT` remain safe before and after PAT is
//! enabled; WC becomes slot 1 (`PWT`) and WT moves to slot 7.

use core::sync::atomic::{AtomicU8, Ordering};

use hal::PageFlags;

#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
const CPUID_1_EDX_PAT: u32 = 1 << 16;

const MEMTYPE_UC: u64 = 0;
const MEMTYPE_WC: u64 = 1;
const MEMTYPE_WT: u64 = 4;
const MEMTYPE_WP: u64 = 5;
const MEMTYPE_WB: u64 = 6;
const MEMTYPE_UC_MINUS: u64 = 7;

const fn pat_value(entries: [u64; 8]) -> u64 {
    entries[0]
        | (entries[1] << 8)
        | (entries[2] << 16)
        | (entries[3] << 24)
        | (entries[4] << 32)
        | (entries[5] << 40)
        | (entries[6] << 48)
        | (entries[7] << 56)
}

/// Linux's full-PAT layout from `arch/x86/mm/pat/memtype.c`.
pub const LINUX_PAT: u64 = pat_value([
    MEMTYPE_WB,
    MEMTYPE_WC,
    MEMTYPE_UC_MINUS,
    MEMTYPE_UC,
    MEMTYPE_WB,
    MEMTYPE_WP,
    MEMTYPE_UC_MINUS,
    MEMTYPE_WT,
]);

/// Linux's lower-four-entry layout for the early Intel PAT-errata families.
#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
const LINUX_PAT_LEGACY: u64 = pat_value([
    MEMTYPE_WB,
    MEMTYPE_WC,
    MEMTYPE_UC_MINUS,
    MEMTYPE_UC,
    MEMTYPE_WB,
    MEMTYPE_WC,
    MEMTYPE_UC_MINUS,
    MEMTYPE_UC,
]);

const PAT_UNDECIDED: u8 = 0;
#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
const PAT_DISABLED: u8 = 1;
const PAT_LEGACY: u8 = 2;
const PAT_FULL: u8 = 3;
static PAT_STATE: AtomicU8 = AtomicU8::new(PAT_UNDECIDED);

/// PTE cache bits shared by the direct PTE helper and the live walker.
pub(crate) const PWT: u64 = 1 << 3;
pub(crate) const PCD: u64 = 1 << 4;
pub(crate) const PAT_4K: u64 = 1 << 7;
pub(crate) const PAT_LARGE: u64 = 1 << 12;

/// Test the architectural PAT feature bit returned by CPUID leaf 1.
/// # C: O(1)
#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
pub const fn cpuid_has_pat(edx: u32) -> bool {
    edx & CPUID_1_EDX_PAT != 0
}

/// Whether the BSP selected an enabled PAT layout.
/// # C: O(1)
pub fn enabled() -> bool {
    PAT_STATE.load(Ordering::Acquire) >= PAT_LEGACY
}

#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
const fn select_mode(supported: bool, intel: bool, family: u32, model: u32) -> u8 {
    if !supported {
        PAT_DISABLED
    } else if intel && ((family == 6 && model >= 1 && model <= 0x0d)
        || (family == 15 && model >= 1 && model <= 6)) {
        PAT_LEGACY
    } else {
        PAT_FULL
    }
}

/// Encode one neutral cache policy against either Linux's PAT layout or the
/// architectural reset table. `NO_CACHE` wins for the established device
/// spelling `NO_CACHE|WRITE_THROUGH`; WC and WT are otherwise exclusive.
/// # C: O(1)
pub(crate) fn cache_bits_for(flags: PageFlags, pat_mode: u8, large: bool) -> u64 {
    if flags.contains(PageFlags::NO_CACHE) {
        return PCD | PWT;
    }
    if flags.contains(PageFlags::WRITE_COMBINE) {
        return if pat_mode >= PAT_LEGACY { PWT } else { PCD };
    }
    if flags.contains(PageFlags::WRITE_THROUGH) {
        return if pat_mode == PAT_FULL {
            PCD | PWT | if large { PAT_LARGE } else { PAT_4K }
        } else {
            if pat_mode == PAT_LEGACY { PCD } else { PWT }
        };
    }
    0
}

/// Encode cache policy using the BSP-selected PAT layout.
/// # C: O(1)
pub(crate) fn cache_bits(flags: PageFlags, large: bool) -> u64 {
    cache_bits_for(flags, PAT_STATE.load(Ordering::Acquire), large)
}

/// Reverse Linux's PAT PTE encoding into the neutral cache flags.
/// # C: O(1)
pub(crate) fn cache_flags_for(bits: u64, pat_mode: u8, large: bool) -> PageFlags {
    let pat = if large { PAT_LARGE } else { PAT_4K };
    let slot = ((bits & PWT != 0) as u8)
        | (((bits & PCD != 0) as u8) << 1)
        | (((bits & pat != 0) as u8) << 2);
    if pat_mode == PAT_FULL {
        match slot {
            1 => PageFlags::WRITE_COMBINE,
            3 => PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH,
            7 => PageFlags::WRITE_THROUGH,
            _ => PageFlags::empty(),
        }
    } else if pat_mode == PAT_LEGACY {
        match slot & 3 {
            1 => PageFlags::WRITE_COMBINE,
            2 => PageFlags::NO_CACHE,
            3 => PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH,
            _ => PageFlags::empty(),
        }
    } else {
        match slot & 3 {
            1 => PageFlags::WRITE_THROUGH,
            2 => PageFlags::NO_CACHE,
            3 => PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH,
            _ => PageFlags::empty(),
        }
    }
}

/// Decode cache policy using the BSP-selected PAT layout.
/// # C: O(1)
pub(crate) fn cache_flags(bits: u64, large: bool) -> PageFlags {
    cache_flags_for(bits, PAT_STATE.load(Ordering::Acquire), large)
}

/// Program this CPU's PAT MSR. The BSP publishes support before any WC leaf
/// can be installed; every AP writes the identical value before joining the
/// scheduler, matching Linux's `pat_cpu_init()` ordering.
///
/// # Safety
/// Caller runs at CPL0 with interrupts masked during per-CPU bring-up.
/// # C: O(1)
pub unsafe fn init_for_cpu() -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: CPUID is unprivileged and leaf 1 exists on x86_64.
        let (_, _, _, edx) = unsafe { crate::cpuid::cpuid(1) };
        let supported = cpuid_has_pat(edx);
        let vendor = crate::cpuid::vendor();
        let (family, model, _) = crate::cpuid::family_model();
        let selected = select_mode(supported, vendor == *b"GenuineIntel", family, model);
        let state = match PAT_STATE.compare_exchange(
            PAT_UNDECIDED,
            selected,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => selected,
            Err(state) => state,
        };
        if state == PAT_DISABLED {
            return false;
        }
        hal::kassert!(supported, "PAT missing on secondary CPU");
        let value = if state == PAT_LEGACY { LINUX_PAT_LEGACY } else { LINUX_PAT };
        // SAFETY: PAT support is established and bring-up owns this CPU's privileged MSR state.
        unsafe { crate::cpu::wrmsr(crate::msr::IA32_CR_PAT, value); }
        crate::mmu::flush_local_all();
        true
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_pat_layout_is_byte_exact() {
        assert_eq!(LINUX_PAT, 0x0407_0506_0007_0106);
        assert_eq!(LINUX_PAT_LEGACY, 0x0007_0106_0007_0106);
        assert!(cpuid_has_pat(1 << 16));
        assert!(!cpuid_has_pat(0));
    }

    #[test]
    fn full_pat_cache_modes_use_linux_slots() {
        assert_eq!(cache_bits_for(PageFlags::empty(), PAT_FULL, false), 0);
        assert_eq!(cache_bits_for(PageFlags::WRITE_COMBINE, PAT_FULL, false), PWT);
        assert_eq!(cache_bits_for(PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH, PAT_FULL, false), PCD | PWT);
        assert_eq!(cache_bits_for(PageFlags::WRITE_THROUGH, PAT_FULL, false), PCD | PWT | PAT_4K);
        assert_eq!(cache_bits_for(PageFlags::WRITE_THROUGH, PAT_FULL, true), PCD | PWT | PAT_LARGE);
    }

    #[test]
    fn no_pat_fallback_never_claims_wc() {
        let wc = cache_bits_for(PageFlags::WRITE_COMBINE, PAT_DISABLED, false);
        assert_eq!(wc, PCD, "Linux falls WC back to UC- without PAT");
        assert_eq!(cache_flags_for(wc, PAT_DISABLED, false), PageFlags::NO_CACHE);
    }

    #[test]
    fn full_pat_cache_modes_round_trip() {
        for (flags, large) in [
            (PageFlags::empty(), false),
            (PageFlags::WRITE_COMBINE, false),
            (PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH, false),
            (PageFlags::WRITE_THROUGH, false),
            (PageFlags::WRITE_THROUGH, true),
        ] {
            let bits = cache_bits_for(flags, PAT_FULL, large);
            assert_eq!(cache_flags_for(bits, PAT_FULL, large), flags);
        }
    }

    #[test]
    fn linux_errata_families_use_only_the_lower_four_entries() {
        assert_eq!(select_mode(true, true, 6, 0x0d), PAT_LEGACY);
        assert_eq!(select_mode(true, true, 15, 6), PAT_LEGACY);
        assert_eq!(select_mode(true, true, 6, 0x8f), PAT_FULL);
        assert_eq!(select_mode(true, false, 15, 6), PAT_FULL);
        assert_eq!(select_mode(false, true, 6, 0x8f), PAT_DISABLED);
        assert_eq!(cache_bits_for(PageFlags::WRITE_COMBINE, PAT_LEGACY, false), PWT);
        assert_eq!(cache_bits_for(PageFlags::WRITE_THROUGH, PAT_LEGACY, false), PCD);
    }
}
