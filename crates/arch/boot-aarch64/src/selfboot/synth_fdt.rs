// Synthesizing a device tree when the firmware published none.
//
// An arm64 UEFI machine that describes itself with ACPI installs no FDT
// configuration table (measured on this firmware: the config-table walk finds
// the ACPI 2.0 RSDP and no device-tree entry). An arm64 kernel is still
// expected to have a device tree, and userspace depends on it: the kexec
// loader reads the raw blob and refuses an image without one.
//
// The blob lands in a page-aligned BSS block inside the kernel image, so it is
// covered by the image's own memmap carve-out and needs no separate
// reservation. The stub runs on the firmware's flat map, which is why taking
// the buffer's address there yields the physical address the rest of boot
// expects.

use core::cell::UnsafeCell;

use super::{EFI_CMDLINE, EFI_CMDLINE_LEN, EFI_CMDLINE_MAX,
            EFI_RAM_BASE, EFI_RAM_COUNT, EFI_RAM_MAX, EFI_RAM_PAGES};

/// Bytes reserved for the synthesized blob. The tree is a root, a `/memory`
/// node holding one 16-byte entry per RAM block, and `/chosen` with the command
/// line — two pages cover the largest map this stub records, and the alignment
/// is what makes the extent describable in whole pages.
const SYNTH_FDT_LEN: usize = 8192;

/// Page size the EFI memory map counts in.
const EFI_PAGE_BYTES: u64 = 4096;

#[repr(C, align(4096))]
struct SynthFdt(UnsafeCell<[u8; SYNTH_FDT_LEN]>);
// SAFETY: written once by the boot CPU inside `efi_stub_setup`, before any
// other context exists; every later access is a read of a finished blob.
unsafe impl Sync for SynthFdt {}
static SYNTH_FDT: SynthFdt = SynthFdt(UnsafeCell::new([0; SYNTH_FDT_LEN]));

/// Staging for the command line, so building the tree costs no boot stack.
#[repr(C, align(8))]
struct ArgsBuf(UnsafeCell<[u8; EFI_CMDLINE_MAX]>);
// SAFETY: same single-writer boot-path discipline as `SYNTH_FDT`.
unsafe impl Sync for ArgsBuf {}
static ARGS: ArgsBuf = ArgsBuf(UnsafeCell::new([0; EFI_CMDLINE_MAX]));

/// Build the fallback device tree and return its physical address, or 0 if it
/// could not be built.
///
/// The tree describes RAM only when it has no firmware handoff to offer: the
/// EFI conventional-memory blocks captured moments earlier become the
/// `/memory` node. With a handoff it carries `/chosen` and nothing else, and
/// the firmware map is the memory description — one answer rather than two
/// that can disagree, and the only shape a kernel will read the firmware
/// tables from.
///
/// It also carries the firmware handoff — the system table's address and the
/// retained EFI memory map — which is what makes the tree a description of a
/// machine rather than of its RAM alone. This firmware puts processors, the
/// interrupt controller, the timer and the console in ACPI, reachable only
/// through the system table; a kernel handed the tree without it finds no
/// processor node, leaves its boot CPU assigned to no memory node, and faults
/// dereferencing that non-node while building its zone lists. The handoff is
/// written only when BOTH halves are known, since naming the table without the
/// map sends the next kernel down the firmware path with nothing to walk.
///
/// # SAFETY: called once from `efi_stub_setup` on the boot CPU while the
/// firmware's flat map is live, so the returned address is physical and the
/// BSS blocks have no other observer.
/// # C: O(cmdline_len + n_ram_regions)
pub unsafe fn build() -> u64 {
    // SAFETY: boot-path single writer; no other context can observe these yet.
    let out = unsafe { &mut *SYNTH_FDT.0.get() };
    // SAFETY: boot-path single writer of the ARGS staging block; no other
    // context exists yet to observe or race it.
    let args = unsafe { &mut *ARGS.0.get() };
    let n = (EFI_CMDLINE_LEN.load(core::sync::atomic::Ordering::Acquire) as usize)
        .min(EFI_CMDLINE_MAX);
    for i in 0..n { args[i] = EFI_CMDLINE[i].load(core::sync::atomic::Ordering::Acquire); }
    let mut ram = [(0u64, 0u64); EFI_RAM_MAX];
    let nr = (EFI_RAM_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize).min(EFI_RAM_MAX);
    let mut k = 0usize;
    for i in 0..nr {
        let base = EFI_RAM_BASE[i].load(core::sync::atomic::Ordering::Acquire);
        let pages = EFI_RAM_PAGES[i].load(core::sync::atomic::Ordering::Acquire);
        let size = pages.saturating_mul(EFI_PAGE_BYTES);
        if size == 0 { continue; }
        ram[k] = (base, size);
        k += 1;
    }
    // The firmware handoff, all of it or none of it. A tree naming the system
    // table without the memory map that goes with it makes the next kernel
    // take the firmware path and then find nothing to describe memory with.
    let systab = super::EFI_SYSTAB_PA.load(core::sync::atomic::Ordering::Acquire);
    let firmware = match (systab, super::efi_memmap::retained()) {
        (0, _) | (_, None) => None,
        (systab_pa, Some((mmap_pa, mmap_size, desc_size, desc_ver))) =>
            Some(fdt::EfiFirmware { systab_pa, mmap_pa, mmap_size, desc_size, desc_ver }),
    };
    let handoff = fdt::UefiHandoff { bootargs: &args[..n], memory: &ram[..k], firmware };
    match fdt::uefi_stub_tree(out, &handoff) {
        Some(_) => out.as_ptr() as u64,
        None => 0,
    }
}
