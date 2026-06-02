// Multiboot2 boot path (GRUB loads our kernel directly, replacing
// Limine). The header GRUB scans for in the first 32 KiB of the ELF
// carries an entry-address tag pointing at `_mb2_entry` — a 32-bit
// trampoline (GRUB enters in protected mode, paging off). The
// trampoline builds boot page tables, switches to 64-bit long mode, and
// jumps to the kernel's higher-half virtual address.
//
// Header layout per Multiboot2 spec §3.1.2: magic, architecture,
// header_length, checksum, then 8-byte-aligned tags terminated by the
// end tag (type 0, size 8). Entry-address tag is type 3 (§3.1.5): the
// u32 GRUB jumps to in 32-bit protected mode — a *physical* address.
// Our kernel is linked higher-half (VMA KB=0xFFFFFFFF80000000) but
// loaded low (LMA KP=0x200000 via the link script's AT()); a kernel
// symbol's physical address is therefore `sym - KB + KP`.
//
// Address-space layout the boot page tables install (2 MiB pages, all
// arch-baseline — no PDPE1GB requirement):
//   - identity 0..1 GiB          : so the trampoline keeps executing at
//                                  its ~2 MiB physical address the
//                                  instant CR0.PG flips.
//   - higher-half 0xFFFFFFFF8000_0000.. -> phys 0x20_0000.. (== LMA):
//                                  the kernel's linked VMAs. The +2 MiB
//                                  offset is the crux — GRUB loaded us
//                                  at KP, so VMA must map to LMA, NOT
//                                  phys 0.
//   - HHDM 0xFFFF8000_0000_0000.. -> phys 0..1 GiB (identity direct
//                                  map; matches the BootInfo.hhdm the
//                                  MB2-info parsing will report).

#![allow(dead_code)]

// GRUB entry state (MB2 spec §3.3): 32-bit protected mode, paging off,
// A20 on, EFLAGS.IF=0, EAX=0x36d76289 (bootloader magic), EBX=physical
// address of the MB2 info struct, flat 4 GiB CS/DS/ES/SS (base 0).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    r#"
    .set MB2_MAGIC,     0xE85250D6
    .set MB2_ARCH_I386, 0
    .set KB,            0xFFFFFFFF80000000   /* kernel VMA base */
    .set KP,            0x200000             /* kernel LMA base */

    /* ---- Multiboot2 header ------------------------------------------ */
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
    .long _mb2_entry - KB + KP
    /* end tag (type 0, size 8). */
    .align 8
    .short 0
    .short 0
    .long 8
mb2_hdr_end:

    /* ---- temporary 64-bit GDT --------------------------------------- */
    .section .rodata
    .align 8
mb2_gdt:
    .quad 0                       /* null */
    .quad 0x00209A0000000000      /* 0x08: 64-bit code (L=1, P, DPL0, exec/read) */
    .quad 0x0000920000000000      /* 0x10: data (P, writable) */
mb2_gdt_end:
mb2_gdt_ptr:
    .short mb2_gdt_end - mb2_gdt - 1
    .long  mb2_gdt - KB + KP       /* base: physical (identity-mapped) */

    /* ---- boot page tables + scratch (zeroed at runtime) ------------- */
    .section .bss
    .align 4096
mb2_pml4:      .skip 4096
mb2_pdpt_low:  .skip 4096
mb2_pdpt_high: .skip 4096
mb2_pdpt_hhdm: .skip 4096
mb2_pd_low:    .skip 4096
mb2_pd_high:   .skip 4096
    .global mb2_saved_magic
    .global mb2_saved_info
mb2_saved_magic: .skip 8
mb2_saved_info:  .skip 8

    /* ---- trampoline ------------------------------------------------- */
    .section .text.boot, "ax"
    .code32
    .global _mb2_entry
_mb2_entry:
    cli
    cld

    /* Stash GRUB's magic (EAX) + MB2-info physical ptr (EBX) for the
       64-bit BootInfo builder. Register-indirect to keep the absolute
       address unambiguous in 32-bit. */
    mov $(mb2_saved_magic - KB + KP), %edi
    mov %eax, (%edi)
    mov $(mb2_saved_info - KB + KP), %edi
    mov %ebx, (%edi)

    /* "MB2\n" — proves GRUB reached our physical entry. */
    mov $0x3F8, %dx
    mov $0x4D, %al
    out %al, %dx
    mov $0x42, %al
    out %al, %dx
    mov $0x32, %al
    out %al, %dx
    mov $0x0A, %al
    out %al, %dx

    /* Zero the 6 contiguous page-table pages (not-present by default). */
    mov $(mb2_pml4 - KB + KP), %edi
    xor %eax, %eax
    mov $(6 * 4096 / 4), %ecx
    rep stosl

    /* pd_low: identity, entry[i] = (i*2MiB) | P|W|PS. */
    mov $(mb2_pd_low - KB + KP), %edi
    xor %eax, %eax
1:
    mov %eax, %edx
    or  $0x83, %edx
    mov %edx, (%edi)
    movl $0, 4(%edi)
    add $0x200000, %eax
    add $8, %edi
    cmp $(mb2_pd_low - KB + KP + 4096), %edi
    jne 1b

    /* pd_high: kernel higher-half, entry[i] = ((i+1)*2MiB) | P|W|PS, so
       VMA base maps to phys KP (2 MiB) == the kernel's LMA. */
    mov $(mb2_pd_high - KB + KP), %edi
    mov $0x200000, %eax
2:
    mov %eax, %edx
    or  $0x83, %edx
    mov %edx, (%edi)
    movl $0, 4(%edi)
    add $0x200000, %eax
    add $8, %edi
    cmp $(mb2_pd_high - KB + KP + 4096), %edi
    jne 2b

    /* pdpt_low[0] = pd_low | P|W; pdpt_hhdm[0] = pd_low | P|W. */
    mov $(mb2_pd_low - KB + KP), %eax
    or  $3, %eax
    mov $(mb2_pdpt_low - KB + KP), %edi
    mov %eax, (%edi)
    mov $(mb2_pdpt_hhdm - KB + KP), %edi
    mov %eax, (%edi)

    /* pdpt_high[510] = pd_high | P|W  (0xFFFFFFFF80000000 >> 30 & 511 = 510). */
    mov $(mb2_pd_high - KB + KP), %eax
    or  $3, %eax
    mov $(mb2_pdpt_high - KB + KP), %edi
    mov %eax, 0xFF0(%edi)

    /* pml4: [0]=pdpt_low, [256]=pdpt_hhdm, [511]=pdpt_high (all | P|W). */
    mov $(mb2_pml4 - KB + KP), %edi
    mov $(mb2_pdpt_low - KB + KP), %eax
    or  $3, %eax
    mov %eax, (%edi)
    mov $(mb2_pdpt_hhdm - KB + KP), %eax
    or  $3, %eax
    mov %eax, 0x800(%edi)
    mov $(mb2_pdpt_high - KB + KP), %eax
    or  $3, %eax
    mov %eax, 0xFF8(%edi)

    /* CR3 = pml4 physical. */
    mov $(mb2_pml4 - KB + KP), %eax
    mov %eax, %cr3

    /* CR4.PAE (bit 5). */
    mov %cr4, %eax
    or  $(1 << 5), %eax
    mov %eax, %cr4

    /* EFER.LME (MSR 0xC0000080, bit 8). */
    mov $0xC0000080, %ecx
    rdmsr
    or  $(1 << 8), %eax
    wrmsr

    /* Load the 64-bit GDT (physical base, identity-mapped). */
    mov $(mb2_gdt_ptr - KB + KP), %eax
    lgdt (%eax)

    /* CR0.PG|PE -> long mode (compatibility submode; CS still 32-bit). */
    mov %cr0, %eax
    or  $0x80000001, %eax
    mov %eax, %cr0

    /* Far jump into the 64-bit code segment at its physical (identity)
       address — leaves compatibility mode for 64-bit mode. */
    ljmp $0x08, $(_mb2_long - KB + KP)

    .code64
_mb2_long:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs
    /* Jump to the kernel's higher-half virtual address. */
    movabs $_mb2_high, %rax
    jmp *%rax

_mb2_high:
    /* Running at higher-half VMA now (mapped to LMA via pd_high). */
    mov $0x3F8, %dx
    mov $0x4C, %al      /* 'L' */
    out %al, %dx
    mov $0x36, %al      /* '6' */
    out %al, %dx
    mov $0x34, %al      /* '4' */
    out %al, %dx
    mov $0x0A, %al
    out %al, %dx
3:
    hlt
    jmp 3b

    /* Restore 64-bit assembler mode + .text so subsequent crate asm
       (the real _start, fault stubs) assembles correctly. */
    .code64
    .text
    "#,
    options(att_syntax)
);
