// Boot page tables. Reserved in zero-init BSS rather than allocated, because the
// trampoline runs before any allocator exists; the region is inside the kernel
// image, whose whole extent `build_selfboot_memmap` reserves from the PMM.

core::arch::global_asm!(
    r#"
    /* ---- boot page tables (zero-init BSS, 4 KiB each) ------------- */
    /* .global the tables the PSCI AP trampoline (hal-aarch64) reaches by
       physical address: the AP identity L0, the shared kernel high map,
       and the (cleared-[0]) kernel user-AS root it switches to up high.  */
    .global _sb_ap_l0
    .global _sb_l1_ident
    .global _sb_ttbr0_l0
    .global _sb_ttbr1_l0
    .section .bss
    .align 12
_sb_ttbr0_l0:  .skip 4096
_sb_ap_l0:     .skip 4096
_sb_l1_ident:  .skip 4096
_sb_ttbr1_l0:  .skip 4096
_sb_l1_kernel: .skip 4096
_sb_l2_kernel: .skip 4096
    /* L3 page tables for the KB->load_base mapping: 256 tables (one per
       2 MiB of image, up to 512 MiB) so any 4 KiB-aligned load base maps
       with 4 KiB pages. BSS (zero-cost in the file; zeroed by the EFI PE
       loader / unused entries never walked under booti).               */
    .align 12
_sb_l3_kernel: .skip 256 * 4096

    /* Page-granular linear map of the RAM slots: one L2 table per slot,
       one bottom-level table per 2 MiB of covered RAM. Reserved here
       rather than allocated because the trampoline runs before any
       allocator exists, and the region is inside the kernel image, whose
       whole extent `build_selfboot_memmap` already reserves from the PMM.
       Both blocks are laid out contiguously so a single flat index walks
       every table of a level.                                          */
    .align 12
_sb_l2_hhdm:   .skip {l2_bytes}
    .align 12
_sb_l3_hhdm:   .skip {l3_bytes}

    /* Return the assembler to .text before this block ends. `lto = "fat"` +
       `codegen-units = 1` concatenate every crate's module-level asm into ONE
       assembly unit, so the section left current here is inherited by whichever
       block follows. Leaving a non-.text section current made the next crate's
       instructions land in the wrong section: "BSS section '.bss' cannot have
       non-zero bytes", appearing and disappearing with unrelated edits that only
       perturbed the LTO module order. Every block in this module therefore names
       its own section on entry and restores .text on exit. */
    .section .text
    "#,
    l2_bytes          = const crate::linear_map::L2_BYTES,
    l3_bytes          = const crate::linear_map::L3_BYTES,
);
