// Whether a single page can be taken out of the kernel's linear map on this
// architecture, and the two independent mechanisms that make it possible.
//
// Taking a page out means the leaf naming it must stop translating, which
// requires a bottom-level leaf that names only that page. Either the linear map
// already has one — because the RAM it covers was mapped at page granularity
// when it was built — or the mapping covering the page has to be re-granularised
// while it is live, and that is only free of translation-conflict aborts when
// the implementation advertises the relaxed break-before-make behaviour at
// level 2. Neither mechanism is a property of the other, and the capability is
// the union: the caller only needs ONE of them to hold.
//
// The boot policy here is the first mechanism, unconditionally, because it is
// the one that does not depend on a CPU feature. It costs one bottom-level
// table per 2 MiB of covered RAM, paid once out of the kernel image's own
// static memory, and in exchange every "hide this page from the kernel"
// contract works on every implementation instead of only on the ones that
// advertise the relaxed behaviour.

/// Bit position of the break-before-make level field in the second memory-model
/// feature identification register.
pub const BBM_FIELD_SHIFT: u32 = 52;
/// Width mask of that field.
pub const BBM_FIELD_MASK: u64 = 0xf;
/// Field value promising no translation-conflict abort when a live mapping's
/// granularity changes.
pub const BBM_LEVEL2: u64 = 2;

/// Whether the RAM covered by the kernel linear map is mapped at page
/// granularity. The boot trampoline builds it that way; the code that builds it
/// carries a compile-time check against this declaration, so the two cannot
/// disagree.
pub const LINEAR_MAP_RAM_PAGE_GRANULAR: bool = true;

/// Break-before-make level advertised by a memory-model feature register value.
/// # C: O(1)
pub const fn bbm_level(id_aa64mmfr2: u64) -> u64 {
    (id_aa64mmfr2 >> BBM_FIELD_SHIFT) & BBM_FIELD_MASK
}

/// Whether the implementation re-granularises a live kernel mapping without a
/// translation-conflict abort.
/// # C: O(1)
pub const fn bbm_allows_live_split(id_aa64mmfr2: u64) -> bool {
    bbm_level(id_aa64mmfr2) >= BBM_LEVEL2
}

/// Whether a single page can be removed from the kernel linear map, given how
/// the map was built and what the implementation advertises.
/// # C: O(1)
pub const fn page_removable_from_linear_map(ram_page_granular: bool, id_aa64mmfr2: u64) -> bool {
    ram_page_granular || bbm_allows_live_split(id_aa64mmfr2)
}

/// Value of the second memory-model feature identification register.
/// # C: O(1)
pub fn read_id_aa64mmfr2() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: reads a read-only feature identification register through
        // `mrs id_aa64mmfr2_el1`; privileged at EL1, no memory effect, and the
        // value is architecturally constant for the life of the machine.
        unsafe {
            core::arch::asm!(
                "mrs {}, id_aa64mmfr2_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        return v;
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

#[cfg(test)]
mod tests;
