use boot_info::{BootFramebuffer, BootMemKind, BootMemRegion};

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
    /// True when a multiboot2 loader (GRUB) entered through the
    /// trampoline, which is the only supported x86_64 handoff (`36§3`).
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
    fn rd8(va: u64) -> u8 {
        // SAFETY: same HHDM-mapped MB2-info lifetime as rd32/rd64.
        unsafe { core::ptr::read_volatile(va as *const u8) }
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
    /// return `(region_count, rsdp_pa, framebuffer)`. `rsdp_pa` is the physical
    /// address of the RSDP copy MB2 embeds in its ACPI tag (0 if absent).
    ///
    /// # SAFETY: the trampoline wrote a valid MB2-info physical pointer;
    /// the struct lives in HHDM-mapped reclaimable RAM and is parsed here
    /// before the PMM can recycle it.
    /// # C: O(tags + mmap entries)
    pub unsafe fn build_memmap(storage: &mut [BootMemRegion]) -> (usize, u64, BootFramebuffer) {
        let base = info_va();
        // total_size at +0; tags start at +8.
        let total = rd32(base) as u64;
        let end = base + total;
        let mut p = base + 8;
        let mut n = 0usize;
        // Despite the `rsdp_pa` field name, kernel_main treats this as a
        // directly-dereferenceable kernel VA (firmware::acpi derefs it),
        // not a raw physical address. The RSDP copy GRUB embeds in the
        // MB2 ACPI tag is already HHDM-mapped, so its VA is what we
        // return.
        let mut rsdp_va = 0u64;
        let mut framebuffer = BootFramebuffer::EMPTY;
        while p + 8 <= end {
            let ty = rd32(p);
            let size = rd32(p + 4) as u64;
            if size < 8 { break; }
            let Some(tag_end) = p.checked_add(size) else { break };
            if tag_end > end { break; }
            if ty == 0 { break; } // end tag
            match ty {
                6 => {
                    // memory map: entry_size@+8, entry_version@+12, entries@+16.
                    let esz = rd32(p + 8) as u64;
                    if esz >= 24 {
                        let mut e = p + 16;
                        while e + esz <= tag_end {
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
                8 if framebuffer == BootFramebuffer::EMPTY && size >= 38 => {
                    let mut tag = [0u8; 38];
                    for (i, byte) in tag.iter_mut().enumerate() {
                        *byte = rd8(p + i as u64);
                    }
                    framebuffer = super::framebuffer::parse_tag(&tag).unwrap_or(BootFramebuffer::EMPTY);
                }
                _ => {}
            }
            p += align8(size);
        }
        (n, rsdp_va, framebuffer)
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
