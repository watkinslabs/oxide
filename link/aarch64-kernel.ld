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

/* High kernel base; mirrors the x86_64 linker script. Using the same
 * -2 GiB region as x86 lets `-mcmodel=kernel` work uniformly across
 * arches. */
KERNEL_BASE = 0xFFFFFFFF80000000;

/* Physical load address for the self-bootstrap (Limine-free) path. QEMU
 * `virt` RAM base is 0x4000_0000; the arm64 Image protocol loads us at
 * RAM_base + text_offset (text_offset=0). AT() pins every section's LMA
 * to KERNEL_PHYS + (VMA - KERNEL_BASE) so `objcopy -O binary` yields a
 * flat Image whose byte 0 is the arm64 Image header at phys KERNEL_PHYS.
 * The MMU trampoline (`selfboot.rs`) maps VMA KERNEL_BASE -> the actual
 * load base (KERNEL_PHYS for `-kernel`/booti, a 4K-aligned addr under the
 * GRUB/UEFI PE loader). */
KERNEL_PHYS = 0x40000000;

SECTIONS {
    . = KERNEL_BASE;
    __kernel_start = .;

    .text.boot ALIGN(4K) : AT(ADDR(.text.boot) - KERNEL_BASE + KERNEL_PHYS) {
        __text_boot_start = .;
        /* arm64 Image header + PE32+ header MUST be byte 0 of the flat
         * binary so QEMU `-kernel` / U-Boot `booti` / GRUB `linux` accept
         * it. selfboot.rs emits them into `.text.boot.header`. */
        KEEP(*(.text.boot.header))
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

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_BASE + KERNEL_PHYS) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    /* Per-CPU; runtime replicates per MAX_CPUS; TPIDR_EL1 selects.  */
    .percpu ALIGN(4K) : AT(ADDR(.percpu) - KERNEL_BASE + KERNEL_PHYS) {
        __percpu_start = .;
        *(.percpu .percpu.*)
        __percpu_end = .;
    }

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

    /* .bss LAST so the on-disk PT_LOAD's file_sz stops before .bss's
     * mem_sz — otherwise lld pads file space across the NOBITS hole.
     * See x86_64-kernel.ld for the diagnosis. */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_BASE + KERNEL_PHYS) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* 4 KiB-align the end so __image_size doubles as the PE32+ SizeOfImage
     * (a whole number of SectionAlignment=4K pages) — the EFI PE loader
     * (GRUB `linux` on arm64) requires it. */
    . = ALIGN(4K);
    __kernel_end = .;
    /* Total image size (incl. .bss): arm64 Image header AND PE SizeOfImage. */
    __image_size = __kernel_end - __kernel_start;

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.gnu.hash)
        *(.gnu.version*)
    }
}
