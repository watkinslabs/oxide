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

SECTIONS {
    . = KERNEL_BASE;
    __kernel_start = .;

    .text.boot ALIGN(4K) : {
        __text_boot_start = .;
        KEEP(*(.text.boot))
        KEEP(*(.text.boot.*))
        __text_boot_end = .;
    }

    .text ALIGN(4K) : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : {
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
    .limine_requests ALIGN(4K) : {
        __limine_requests_start = .;
        KEEP(*(.limine_requests.start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests.*))
        __limine_requests_end = .;
    }

    .data ALIGN(4K) : {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* PerCpu: linker emits 1 copy; runtime allocates MAX_CPUS slots
     * and per-CPU GS_BASE points into its own slot. Vars use
     * #[link_section=".percpu"]. */
    .percpu ALIGN(4K) : {
        __percpu_start = .;
        *(.percpu .percpu.*)
        __percpu_end = .;
    }

    /* Interned klog format strings (defmt-style). Decoder resolves
     * by virtual address. */
    .klog_strings ALIGN(8) : {
        __klog_strings_start = .;
        KEEP(*(.klog_strings .klog_strings.*))
        __klog_strings_end = .;
    }

    .init_array ALIGN(8) : {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
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
