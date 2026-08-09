// aarch64 `machine_kexec_post_load` + `arm64_relocate_new_kernel`.
//
// ENTRY CONTRACT the trampoline is called under (AAPCS64, three arguments):
//   x0 = image->head, the first relocation entry
//   x1 = image->start, the new kernel's entry point
//   x2 = the device-tree address to hand the new kernel
// It is CALLED at its OWN PHYSICAL address, after the identity tables have
// been installed in `TTBR0_EL1`, and never returns. The reference does exactly
// that — its `kern_reloc` is the physical address of the copied code and it is
// entered after `cpu_install_ttbr0`.
//
// WHAT DIFFERS FROM x86_64 AND WHY.
//
// 1. There is no transition mapping and no page-table switch inside the
//    trampoline. The identity map is installed in `TTBR0_EL1` BEFORE the
//    branch, so the code is already running at an address the tables describe.
//    The reference reaches the same place by copying the linear map into a
//    fresh `TTBR1`; a `TTBR0` identity map needs no copy because the walk
//    never consults a kernel address, and it cannot be invalidated by the
//    relocation because the tables live in control pages.
// 2. The relocation is followed by cache maintenance the other architecture
//    does not need. The new kernel starts with the MMU and caches OFF, so
//    every byte it will fetch has to be visible at the point of coherency:
//    each destination page is cleaned and invalidated to PoC as it is written,
//    and the instruction cache is invalidated before the branch. Skipping
//    either hands the new kernel stale lines from this one.
// 3. `SCTLR_EL1` is written with the MMU, caches and alignment checking off
//    and every RES1 field still set (`plan::SCTLR_EL1_MMU_OFF`) — a bare zero
//    would clear fields the architecture requires to read as one.
//
// The entry state is the arm64 boot protocol (`docs/36 §4`): x0 = DTB
// physical address, x1..x3 zero, EL1 with all of DAIF masked, MMU off, caches
// off. `kexec_load(2)` carries no device tree — the reference sets
// `arch.dtb_mem` only in the file-load path — so x0 is zero and the purgatory
// the caller staged is what supplies one.

#![cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]

extern crate alloc;
use alloc::vec::Vec;

use hal::pt_walker::WalkErr;
use hal_aarch64::vmm::PtWalkerArm;

use crate::frames::{clear_page, Frames};
use crate::image::KImage;
use crate::machine::{idmap, plan, quiesce};
use crate::uapi::PAGE_SIZE;
use crate::validate::{Error, KResult};

core::arch::global_asm!(
    ".section .text.kexec_relocate,\"ax\",@progbits",
    ".globl oxide_kexec_arm_relocate_start",
    ".type  oxide_kexec_arm_relocate_start, @function",
    "oxide_kexec_arm_relocate_start:",
    // x0 = head, x1 = start, x2 = dtb.
    "    mov  x28, x1",                       // entry point, read before anything moves
    "    mov  x26, x2",                       // dtb
    "    mov  x16, x0",                       // entry word
    "    mov  x14, xzr",                      // ptr
    "    mov  x13, xzr",                      // running destination
    // Data-cache line size from CTR_EL0.DminLine, in bytes.
    "    mrs  x15, ctr_el0",
    "    ubfx x15, x15, #16, #4",
    "    mov  x9, #4",
    "    lsl  x15, x9, x15",
    "1:",
    "    and  x12, x16, {page_mask}",
    "    tbz  x16, {ind_source_bit}, 2f",
    "    mov  x19, x13",                      // destination page base
    "    mov  x20, {page_size}",
    "10:",
    "    ldp  x9, x10, [x12], #16",
    "    stp  x9, x10, [x13], #16",
    "    subs x20, x20, #16",
    "    b.ne 10b",
    // Clean and invalidate the page just written to the point of coherency:
    // the new kernel reads it with the caches off.
    "    mov  x21, x19",
    "    add  x22, x19, {page_size}",
    "11:",
    "    dc   civac, x21",
    "    add  x21, x21, x15",
    "    cmp  x21, x22",
    "    b.lo 11b",
    "    dsb  sy",
    "    b    4f",
    "2:",
    "    tbz  x16, {ind_indirection_bit}, 3f",
    "    mov  x14, x12",
    "    b    4f",
    "3:",
    "    tbz  x16, {ind_destination_bit}, 4f",
    "    mov  x13, x12",
    "4:",
    "    ldr  x16, [x14], #8",
    "    tbz  x16, {ind_done_bit}, 1b",
    // Make every copied byte and this code's own view of memory coherent
    // before anything is fetched with the caches off.
    "    dsb  nsh",
    "    ic   iallu",
    "    dsb  nsh",
    "    isb",
    "    mov  x0, {sctlr_lo}",
    "    movk x0, {sctlr_hi}, lsl #16",
    "    msr  sctlr_el1, x0",
    "    isb",
    "    mov  x0, x26",
    "    mov  x1, xzr",
    "    mov  x2, xzr",
    "    mov  x3, xzr",
    "    br   x28",
    ".size oxide_kexec_arm_relocate_start, . - oxide_kexec_arm_relocate_start",
    page_mask = const crate::uapi::PAGE_MASK,
    page_size = const PAGE_SIZE as u32,
    ind_source_bit = const plan::IND_SOURCE_BIT,
    ind_indirection_bit = const plan::IND_INDIRECTION_BIT,
    ind_destination_bit = const plan::IND_DESTINATION_BIT,
    ind_done_bit = const plan::IND_DONE_BIT,
    sctlr_lo = const (plan::SCTLR_EL1_MMU_OFF & 0xffff) as u32,
    sctlr_hi = const (plan::SCTLR_EL1_MMU_OFF >> 16) as u32,
);

// Bounds from the LINKER, as the reference takes `__relocate_new_kernel_start`
// / `_end` from `vmlinux.lds.S` — including its assertion that the section
// begins with the entry point, since the blob is copied to offset 0 of the
// control page and branched to there.
extern "C" {
    static __relocate_kernel_start: u8;
    static __relocate_kernel_end: u8;
}

/// The trampoline's entry signature. Never returns.
type RelocateFn = unsafe extern "C" fn(head: u64, start: u64, dtb: u64) -> !;

fn sym(s: &'static u8) -> usize { s as *const u8 as usize }

fn trampoline() -> &'static [u8] {
    // SAFETY: the linker places `.text.kexec_relocate` between the two bound
    // symbols; the range is kernel text, mapped for the kernel's whole life.
    let (start, end) = unsafe { (sym(&__relocate_kernel_start), sym(&__relocate_kernel_end)) };
    // SAFETY: that range is byte-addressable kernel text.
    unsafe { core::slice::from_raw_parts(start as *const u8, end - start) }
}

fn walk_err(e: WalkErr) -> Error {
    match e { WalkErr::AllocFailed => Error::Nomem, _ => Error::Inval }
}

/// Clean `va..va + len` to the point of unification and invalidate the
/// instruction cache, so the copied trampoline is fetchable.
/// # SAFETY: `va` names `len` bytes of kernel-mapped memory.
unsafe fn publish_code(va: u64, len: u64) {
    // SAFETY: CTR_EL0 is readable at EL1; the maintenance ops act on
    // caller-owned kernel memory and are legal at EL1.
    unsafe {
        let ctr: u64;
        core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        let line = 4u64 << ((ctr >> 16) & 0xf);
        let mut p = va & !(line - 1);
        let end = va + len;
        while p < end {
            core::arch::asm!("dc cvau, {0}", in(reg) p, options(nostack, preserves_flags));
            p += line;
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb",
                         options(nostack, preserves_flags));
    }
}

/// `machine_kexec_post_load`: the identity tables and the trampoline copy,
/// built while a failure is still an errno.
/// # C: O(RAM / 2 MiB)
pub fn prepare<F: Frames>(image: &mut KImage, f: &mut F) -> KResult<()> {
    let code = trampoline();

    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return Err(Error::Nomem); }

    let mut ram: Vec<(u64, u64)> = Vec::new();
    for i in 0..f.ram_range_count() {
        if let Some(r) = f.ram_range(i) { ram.push(r); }
    }
    let ranges = plan::ranges_for(&ram, &image.segments);
    if ranges.is_empty() { return Err(Error::Inval); }
    // The kernel's `TCR_EL1.T0SZ` fixes how much address space `TTBR0` can
    // describe. A plan reaching past it has no identity map, and saying so
    // here is the difference between an errno and a machine that stops.
    if plan::max_address(&ranges) > plan::ARM_MAX_IDMAP_PA { return Err(Error::Inval); }

    let mut pool: Vec<u64> = Vec::new();
    // No transition mapping on this architecture — the trampoline is entered
    // at an address the identity map already describes — so only the identity
    // map's own tables are needed.
    for _ in 0..plan::table_pages(&ranges) {
        let p = image.alloc_control_page(f)?;
        clear_page(f, p);
        pool.push(p);
    }
    let root = pool.pop().ok_or(Error::Nomem)?;
    let mut take = || pool.pop();

    // SAFETY: `root` and every page `take` yields are image-owned control
    // pages, freshly zeroed, reachable through the HHDM the PMM published.
    unsafe { idmap::build::<PtWalkerArm, _>(root, &ranges, hhdm, &mut take).map_err(walk_err)? };

    let dst = f.ptr(image.control_code_page).ok_or(Error::Nomem)?;
    // SAFETY: `control_code_page` is an image-owned control page of PAGE_SIZE
    // bytes and `code.len()` was checked against the page's usable half above.
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), dst, code.len()) };
    // SAFETY: `dst` names `code.len()` bytes of kernel-mapped control page.
    unsafe { publish_code(dst as u64, code.len() as u64) };

    image.arch_pgt = root;
    image.arch_entry_off = 0;
    klog::kinfo!("kexec: relocation tables built");
    Ok(())
}

/// `machine_kexec`. Allocates nothing.
/// # C: O(image size)
pub fn kexec(image: &KImage) -> KResult<()> {
    if image.arch_pgt == 0 || image.control_code_page == 0 { return Err(Error::Inval); }
    quiesce::stop_other_cpus();
    klog::kinfo!("kexec: starting new kernel");
    // SAFETY: the machine is committed. DAIF is masked so nothing can be
    // delivered once the vector table's translation stops being valid; the
    // identity map goes into TTBR0 and the branch target is a physical address
    // that map describes. Does not return.
    unsafe {
        core::arch::asm!("msr daifset, #0xf", options(nomem, nostack, preserves_flags));
        core::arch::asm!(
            "msr ttbr0_el1, {0}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            in(reg) image.arch_pgt,
            options(nostack, preserves_flags),
        );
        let f: RelocateFn = core::mem::transmute(image.control_code_page as usize);
        f(image.head, image.start, 0)
    }
}
