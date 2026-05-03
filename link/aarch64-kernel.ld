/* aarch64 kernel link script per docs/07§6.
 * Kernel virtual base: 0xFFFF_0000_0000_0000.
 * code-model not in JSON (07§3.2); PC-relative ±2 GiB suffices.
 *
 * Same section shape as x86_64-kernel.ld: .text.boot, .text, .rodata,
 * .data, .bss, .percpu, .klog_strings, .init_array.
 *
 * FROZEN once boot works (per 07§6).
 */

ENTRY(_start)
OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)

/* High kernel base; mirrors the x86_64 linker script. Limine ≥ 9
 * classifies anything below `0xFFFF_FFFF_8000_0000` as "lower half"
 * on aarch64 and rejects it ("Lower half PHDRs are not allowed").
 * Using the same -2 GiB region as x86 lets `-mcmodel=kernel` work
 * uniformly across arches. */
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

    /* Limine protocol request markers per `36§3` (mirror of x86_64-
     * kernel.ld §43). ALIGN(4K) so this section starts a fresh
     * PT_LOAD page — Limine rejects ELFs whose PT_LOADs share a
     * page across permission classes. */
    .limine_requests ALIGN(4K) : {
        __limine_requests_start = .;
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

    /* Per-CPU; runtime replicates per MAX_CPUS; TPIDR_EL1 selects.  */
    .percpu ALIGN(4K) : {
        __percpu_start = .;
        *(.percpu .percpu.*)
        __percpu_end = .;
    }

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
