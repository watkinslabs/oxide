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
    /* Trampoline boot stack. GRUB hands off with no usable stack (rsp is
       its own low-memory leftover); once the low identity map is torn
       down, _start's Rust prologue would fault on its first push. Give
       _start a valid higher-half stack here; _start then swaps to the
       kernel's KERNEL_STACK. */
    .align 16
mb2_boot_stack:     .skip 16384
mb2_boot_stack_top:

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
    movl $0, 4(%edi)
    mov $(mb2_saved_info - KB + KP), %edi
    mov %ebx, (%edi)
    movl $0, 4(%edi)

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

    /* EFER.LME (bit 8) + EFER.NXE (bit 11), MSR 0xC0000080. NXE is
       mandatory: the kernel's device/user/rodata leaves set the NX bit
       (63); without NXE that bit is reserved and the first access to an
       NX page faults RSVD (this is what Limine enables for us). */
    mov $0xC0000080, %ecx
    rdmsr
    or  $((1 << 8) | (1 << 11)), %eax
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
    /* Running at higher-half VMA now (mapped to LMA via pd_high). Tear
       down the low 0..1GiB identity map (PML4[0]): it was only needed so
       the 32-bit trampoline kept executing at its ~2MiB physical address
       across the CR0.PG flip. Leaving a 2MiB-block identity map in the
       kernel-active tables collides with the kernel mapping low/user VAs
       (HitHugeOrBlock at e.g. VA 0x400000 in the user_map smoke). The
       kernel reaches ACPI/firmware via HHDM (rsdp reported as an HHDM
       VA), not identity, so no early path needs this map. Clear the
       entry only — walkers read it from memory (=0) and allocate fresh,
       and per-VA map()s flush their own TLB entry; a global CR3 reload
       here wedges boot (see bootswap.md #5) and is unnecessary. */
    movabs $mb2_pml4, %rax
    movq $0, (%rax)

    /* 'L64' breadcrumb, then hand off to the bootloader-agnostic _start
       (it swaps to KERNEL_STACK and tail-calls _start_rust). The Limine-
       vs-MB2 split happens in build_boot_info / capture_cmdline, keyed on
       the saved bootloader magic. */
    mov $0x3F8, %dx
    mov $0x4C, %al      /* 'L' */
    out %al, %dx
    mov $0x36, %al      /* '6' */
    out %al, %dx
    mov $0x34, %al      /* '4' */
    out %al, %dx
    mov $0x0A, %al
    out %al, %dx

    /* Install a valid higher-half stack before entering _start (GRUB
       left none, and the low identity map is now gone). */
    movabs $mb2_boot_stack_top, %rsp
    jmp _start

    /* Restore 64-bit assembler mode + .text so subsequent crate asm
       (the real _start, fault stubs) assembles correctly. */
    .code64
    .text
    "#,
    options(att_syntax)
);

// MB2 info-struct parsing. The trampoline stashed GRUB's bootloader
// magic + the physical address of the MB2 info struct; this module
// turns the info tags into the uniform `BootInfo` the kernel consumes,
// reachable via the HHDM the trampoline installed (`MB2_HHDM`).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub mod info {
    use boot_info::{BootMemKind, BootMemRegion};

    /// Value a multiboot2-compliant loader leaves in EAX at handoff.
    pub const MB2_BOOTLOADER_MAGIC: u32 = 0x36d7_6289;
    /// HHDM offset the trampoline's page tables install (0xFFFF_8000…
    /// → phys 0, 1 GiB direct map). Reported as `BootInfo.hhdm_offset`.
    pub const MB2_HHDM: u64 = 0xFFFF_8000_0000_0000;

    const KB: u64 = 0xFFFF_FFFF_8000_0000; // kernel VMA base
    const KP: u64 = 0x20_0000; // kernel LMA base (link script KERNEL_PHYS)

    // Filled by the 32-bit trampoline before long-mode handoff.
    extern "C" {
        static mb2_saved_magic: u64;
        static mb2_saved_info: u64;
        static __kernel_end: u8;
    }

    /// True when GRUB (any MB2 loader) booted us rather than Limine.
    /// # C: O(1)
    pub fn is_mb2_boot() -> bool {
        // SAFETY: mb2_saved_magic is a 'static BSS u64 the trampoline
        // wrote once before any other CPU/path runs; volatile read avoids
        // the compiler assuming it never changed from its zero init.
        let m = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(mb2_saved_magic)) };
        (m as u32) == MB2_BOOTLOADER_MAGIC
    }

    fn info_va() -> u64 {
        // SAFETY: 'static BSS slot written once by the trampoline.
        let phys = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(mb2_saved_info)) };
        MB2_HHDM.wrapping_add(phys)
    }

    /// Page-aligned-up physical end of the loaded kernel image. GRUB's
    /// e820 marks this RAM available (it doesn't know our extent), so the
    /// memmap builder carves [KP, here) out as `KernelImage`.
    fn kernel_end_phys() -> u64 {
        let v = core::ptr::addr_of!(__kernel_end) as u64;
        let p = v - KB + KP;
        (p + 0xFFF) & !0xFFF
    }

    // Volatile reads at a HHDM virtual address. Internal helpers; the
    // module-level contract (valid MB2 info ptr, HHDM-mapped) makes the
    // deref sound, so callers need no per-call unsafe.
    fn rd32(va: u64) -> u32 {
        // SAFETY: `va` is a HHDM-mapped address in the trampoline's HHDM range (phys < 1 GiB); the MB2 info struct is live reclaimable RAM during boot parsing.
        unsafe { core::ptr::read_volatile(va as *const u32) }
    }
    fn rd64(va: u64) -> u64 {
        // SAFETY: `va` is a HHDM-mapped address in the trampoline's HHDM range (phys < 1 GiB); the MB2 info struct is live reclaimable RAM during boot parsing.
        unsafe { core::ptr::read_volatile(va as *const u64) }
    }

    fn align8(x: u64) -> u64 { (x + 7) & !7 }

    /// MB2 mmap entry type → `BootMemKind` (spec §3.6.7).
    fn map_kind(ty: u32) -> BootMemKind {
        match ty {
            1 => BootMemKind::Usable,
            3 => BootMemKind::AcpiReclaim,
            4 => BootMemKind::AcpiNvs, // "reserved, preserve on hibernation"
            5 => BootMemKind::BadMem,
            _ => BootMemKind::Reserved,
        }
    }

    /// Push a region, splitting around the kernel image so its pages are
    /// never handed to the PMM. Only `Usable` regions get carved; others
    /// pass through. Returns the next free slot index.
    fn push_carved(
        storage: &mut [BootMemRegion],
        mut n: usize,
        base: u64,
        len: u64,
        kind: BootMemKind,
    ) -> usize {
        let push = |storage: &mut [BootMemRegion], n: &mut usize, b: u64, l: u64, k: BootMemKind| {
            if l == 0 || *n >= storage.len() { return; }
            storage[*n] = BootMemRegion { base_pa: b, len: l, kind: k };
            *n += 1;
        };
        if kind != BootMemKind::Usable {
            push(storage, &mut n, base, len, kind);
            return n;
        }
        let ks = KP;
        let ke = kernel_end_phys();
        let end = base.saturating_add(len);
        // No overlap with [ks, ke): emit whole region usable.
        if end <= ks || base >= ke {
            push(storage, &mut n, base, len, BootMemKind::Usable);
            return n;
        }
        // Overlap: usable head, kernel-image middle, usable tail.
        if base < ks {
            push(storage, &mut n, base, ks - base, BootMemKind::Usable);
        }
        let mid_lo = core::cmp::max(base, ks);
        let mid_hi = core::cmp::min(end, ke);
        push(storage, &mut n, mid_lo, mid_hi - mid_lo, BootMemKind::KernelImage);
        if end > ke {
            push(storage, &mut n, ke, end - ke, BootMemKind::Usable);
        }
        n
    }

    /// Walk MB2 tags, fill `storage` with the (carved) memory map, and
    /// return `(region_count, rsdp_pa)`. `rsdp_pa` is the physical
    /// address of the RSDP copy MB2 embeds in its ACPI tag (0 if absent).
    ///
    /// # SAFETY: the trampoline wrote a valid MB2-info physical pointer;
    /// the struct lives in HHDM-mapped reclaimable RAM and is parsed here
    /// before the PMM can recycle it.
    /// # C: O(tags + mmap entries)
    pub unsafe fn build_memmap(storage: &mut [BootMemRegion]) -> (usize, u64) {
        let base = info_va();
        // total_size at +0; tags start at +8.
        let total = rd32(base) as u64;
        let end = base + total;
        let mut p = base + 8;
        let mut n = 0usize;
        // Despite the `rsdp_pa` field name, kernel_main treats this as a
        // directly-dereferenceable kernel VA (firmware::acpi derefs it,
        // acpi.rs:182) — Limine reports an HHDM VA here, not a raw
        // physical. We mirror that: the RSDP copy GRUB embeds in the MB2
        // ACPI tag is already HHDM-mapped, so its VA is what we return.
        let mut rsdp_va = 0u64;
        while p + 8 <= end {
            let ty = rd32(p);
            let size = rd32(p + 4) as u64;
            if size < 8 { break; }
            if ty == 0 { break; } // end tag
            match ty {
                6 => {
                    // memory map: entry_size@+8, entry_version@+12, entries@+16.
                    let esz = rd32(p + 8) as u64;
                    if esz >= 24 {
                        let mut e = p + 16;
                        while e + esz <= p + size {
                            let b = rd64(e);
                            let l = rd64(e + 8);
                            let mty = rd32(e + 16);
                            n = push_carved(storage, n, b, l, map_kind(mty));
                            e += esz;
                        }
                    }
                }
                14 | 15 => {
                    // ACPI RSDP — the bytes start at +8, already HHDM-
                    // mapped; hand the kernel that VA directly. Prefer the
                    // ACPI 2.0+ RSDP (tag 15: revision≥2, carries the
                    // 64-bit XSDT the kernel actually walks) over the 1.0
                    // RSDP (tag 14: RSDT-only). Taking tag 14 left the
                    // kernel with no XSDT → the MADT never decoded → no
                    // I/O APIC → serial IRQ couldn't be wired.
                    if ty == 15 {
                        rsdp_va = p + 8;
                    } else if rsdp_va == 0 {
                        rsdp_va = p + 8;
                    }
                }
                _ => {}
            }
            p += align8(size);
        }
        (n, rsdp_va)
    }

    /// HHDM virtual pointer to GRUB's NUL-terminated boot cmdline (tag
    /// type 1), or `None` if absent. `capture_cmdline` copies from it.
    ///
    /// # SAFETY: as `build_memmap` — valid MB2 info ptr, HHDM-mapped.
    /// # C: O(tags)
    pub unsafe fn cmdline_va() -> Option<*const u8> {
        let base = info_va();
        let total = rd32(base) as u64;
        let end = base + total;
        let mut p = base + 8;
        while p + 8 <= end {
            let ty = rd32(p);
            let size = rd32(p + 4) as u64;
            if size < 8 { break; }
            if ty == 0 { break; }
            if ty == 1 && size > 8 {
                return Some((p + 8) as *const u8);
            }
            p += align8(size);
        }
        None
    }
}
