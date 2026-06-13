/* x86_64 kernel link script per docs/07§6.
 * Kernel virtual base: 0xFFFF_FFFF_8000_0000 (upper-half).
 * Sections per 07§6: .text.boot, .text, .rodata, .data, .bss,
 * .percpu (linker emits 1 copy; runtime allocates MAX_CPUS copies),
 * .klog_strings (interned format strings; userspace decoder resolves
 * by addr per 04§Format-interning), .init_array.
 *
 * FROZEN once boot works (per 07§6). Until then, revisions allowed.
 */

ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

KERNEL_BASE = 0xFFFFFFFF80000000;
/* Physical load address (LMA). GRUB's multiboot2 loader copies each
 * PT_LOAD by physical address (p_paddr); a higher-half p_paddr (== VMA)
 * trips "segment crosses 4 GiB border". AT() below pins every section's
 * LMA to KERNEL_PHYS + (VMA - KERNEL_BASE) — a low, under-4-GiB image
 * GRUB can load. 2 MiB clears the low 1 MiB BIOS/legacy region and the
 * GRUB-occupied area below it. Limine ignores p_paddr (it maps by VMA),
 * so this is invisible to the Limine path. */
KERNEL_PHYS = 0x200000;

SECTIONS {
    . = KERNEL_BASE;
    __kernel_start = .;

    /* Multiboot2 header: GRUB scans the first 32 KiB of the file for the
     * magic, so this section comes first (right after the ELF headers).
     * KEEP-retained against --gc-sections. The self-bootstrap path
     * (GRUB loads our kernel directly); Limine ignores it. */
    .multiboot2_header ALIGN(8) : AT(ADDR(.multiboot2_header) - KERNEL_BASE + KERNEL_PHYS) {
        __multiboot2_header_start = .;
        KEEP(*(.multiboot2_header))
        __multiboot2_header_end = .;
    }

    .text.boot ALIGN(4K) : AT(ADDR(.text.boot) - KERNEL_BASE + KERNEL_PHYS) {
        __text_boot_start = .;
        KEEP(*(.text.boot))
        KEEP(*(.text.boot.*))
        __text_boot_end = .;
    }

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_BASE + KERNEL_PHYS) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_BASE + KERNEL_PHYS) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    /* Limine protocol request markers per `36§3`. Bootloader scans
     * for magic header words before kernel entry; section must be
     * KEEP-retained even with --gc-sections. ALIGN(4K) so this
     * section starts a fresh PT_LOAD page — Limine rejects ELFs
     * whose PT_LOADs share a page across permission classes
     * (`.rodata` is R-only; this lives with `.data` in RW). */
    .limine_requests ALIGN(4K) : AT(ADDR(.limine_requests) - KERNEL_BASE + KERNEL_PHYS) {
        __limine_requests_start = .;
        KEEP(*(.limine_requests.start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests.end))
        KEEP(*(.limine_requests.*))
        __limine_requests_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_BASE + KERNEL_PHYS) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    /* PerCpu: linker emits 1 copy; runtime allocates MAX_CPUS slots
     * and per-CPU GS_BASE points into its own slot. Vars use
     * #[link_section=".percpu"]. */
    .percpu ALIGN(4K) : AT(ADDR(.percpu) - KERNEL_BASE + KERNEL_PHYS) {
        __percpu_start = .;
        *(.percpu .percpu.*)
        __percpu_end = .;
    }

    /* Interned klog format strings (defmt-style). Decoder resolves
     * by virtual address. */
    .klog_strings ALIGN(8) : AT(ADDR(.klog_strings) - KERNEL_BASE + KERNEL_PHYS) {
        __klog_strings_start = .;
        KEEP(*(.klog_strings .klog_strings.*))
        __klog_strings_end = .;
    }

    .init_array ALIGN(8) : AT(ADDR(.init_array) - KERNEL_BASE + KERNEL_PHYS) {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    }

    /* .bss LAST in the RW segment so the on-disk PT_LOAD's
     * file_sz can stop before .bss's mem_sz. Otherwise lld pads
     * file space across the NOBITS hole because the segment has
     * non-NOBITS sections after it. With STATIC_HEAP_SIZE=64 MiB
     * the misordering bloated oxide-x86_64 from ~18 MB to ~85 MB. */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_BASE + KERNEL_PHYS) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.gnu.hash)
        *(.gnu.version*)
    }
}
