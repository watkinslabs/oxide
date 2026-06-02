// Multiboot2 boot path (GRUB loads our kernel directly, replacing
// Limine). The header GRUB scans for in the first 32 KiB of the ELF
// carries an entry-address tag pointing at `_mb2_entry` — a 32-bit
// trampoline (GRUB enters in protected mode, paging off). Stage 1c
// proves GRUB reaches our physical entry: the trampoline writes "MB2"
// to COM1 and halts. The 32->64-bit long-mode switch + MB2-info parsing
// build on top once entry is confirmed on real serial output.
//
// Header layout per Multiboot2 spec §3.1.2: magic, architecture,
// header_length, checksum, then 8-byte-aligned tags terminated by the
// end tag (type 0, size 8). Entry-address tag is type 3 (§3.1.5): the
// u32 entry_addr GRUB jumps to in 32-bit protected mode. It must be a
// *physical* address — our kernel is linked higher-half (VMA
// 0xFFFFFFFF80000000) but loaded low (LMA KERNEL_PHYS=0x200000 via the
// link script's AT()), so the tag computes `_mb2_entry`'s LMA as
// VMA - KERNEL_BASE + KERNEL_PHYS at link time.

#![allow(dead_code)]

// GRUB entry state (MB2 spec §3.3): 32-bit protected mode, paging off,
// A20 on, EFLAGS.IF=0, EAX=0x36d76289 (bootloader magic), EBX=physical
// address of the MB2 info struct, flat 4 GiB CS/DS/ES/SS (base 0).
// The trampoline writes a literal "MB2\n" to the COM1 THR (0x3F8) — on
// QEMU the holding register accepts writes at reset (LSR.THRE set), so
// no init/poll is needed for this proof-of-entry step.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    r#"
    .set MB2_MAGIC,      0xE85250D6
    .set MB2_ARCH_I386,  0
    .set KERNEL_BASE,    0xFFFFFFFF80000000
    .set KERNEL_PHYS,    0x200000

    .section .multiboot2_header, "a"
    .align 8
mb2_hdr_start:
    .long MB2_MAGIC
    .long MB2_ARCH_I386
    .long mb2_hdr_end - mb2_hdr_start
    .long -(MB2_MAGIC + MB2_ARCH_I386 + (mb2_hdr_end - mb2_hdr_start))

    /* entry-address tag (type 3): physical entry GRUB jumps to. */
    .align 8
    .short 3
    .short 0
    .long 12
    .long _mb2_entry - KERNEL_BASE + KERNEL_PHYS

    /* end tag (type 0, size 8). */
    .align 8
    .short 0
    .short 0
    .long 8
mb2_hdr_end:

    .section .text.boot, "ax"
    .code32
    .global _mb2_entry
_mb2_entry:
    cli
    cld
    /* Write "MB2\n" to COM1 (0x3F8) to prove GRUB reached our entry at
       the correct physical address with flat 32-bit segments. */
    mov $0x3F8, %dx
    mov $0x4D, %al      /* 'M' */
    out %al, %dx
    mov $0x42, %al      /* 'B' */
    out %al, %dx
    mov $0x32, %al      /* '2' */
    out %al, %dx
    mov $0x0A, %al      /* '\n' */
    out %al, %dx
1:  hlt
    jmp 1b
    /* Restore 64-bit assembler mode so subsequent asm in this crate
       (the real _start, fault stubs) assembles as 64-bit. */
    .code64
    "#,
    options(att_syntax)
);
