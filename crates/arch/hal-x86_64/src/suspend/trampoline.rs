// Real-mode → long-mode resume stub.
//
// Firmware ends a deep sleep by entering the physical address in the FACS
// firmware waking vector, in real mode, with paging off, no GDT of ours, no
// IDT and no long mode. This blob is what lives at that address: it takes the
// CPU 16 → 32 → 64 on its own four-entry GDT, loads the kernel master page
// tables, and jumps to the kernel-virtual wakeup entry, which is where the
// magic check and the state restore happen.
//
// Same shape as the AP startup trampoline, and for the same reason: absolute
// references inside the 16- and 32-bit stages cannot carry symbol arithmetic,
// so the blob lives at a FIXED low physical page and the stages address their
// own data block by literal. The page must be reserved from the physical
// allocator at boot — see [`WAKEUP_TRAMP_PA`].

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

/// Physical page the resume stub is copied to. Below the first mebibyte
/// because firmware enters it in real mode, page-aligned because that is
/// what a startup vector addresses, and FIXED because the 16-bit stage
/// addresses its own data block by literal.
///
/// The physical allocator must never hand this page out. Nothing here can
/// arrange that — the reservation belongs to the boot path, right after PMM
/// init and before the first allocation — so the stub refuses to install
/// until the boot path has declared the page reserved.
pub const WAKEUP_TRAMP_PA: u64 = 0x9000;

/// Data-block offsets inside the page. Chosen clear of the code and quoted
/// as literals by the 16- and 32-bit stages.
const OFF_CR3: u64 = 0xf00;
const OFF_ENTRY: u64 = 0xf08;
const OFF_GDT: u64 = 0xf40;
const OFF_GDTPTR: u64 = 0xf60;
/// Whole page; nothing past this belongs to the stub.
const TRAMP_BYTES: usize = 4096;

const _: () = {
    assert!(super::state::resume_vector_placeable(WAKEUP_TRAMP_PA));
    // The data block is addressed by literal in the 16- and 32-bit stages,
    // so it must lie inside the page, in order, and clear of the code.
    assert!(OFF_CR3 < OFF_ENTRY);
    assert!(OFF_ENTRY < OFF_GDT);
    assert!(OFF_GDT < OFF_GDTPTR);
    assert!(OFF_GDTPTR + 8 < TRAMP_BYTES as u64);
};

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text.oxide_wakeup_tramp,\"ax\",@progbits",
    ".code16",
    ".globl oxide_wakeup_tramp",
    "oxide_wakeup_tramp:",
    "    cli",
    "    cld",
    // A real-mode segment load resets base and limit, so this also repairs
    // whatever firmware left in the data-segment descriptor caches.
    "    xor   ax, ax",
    "    mov   ds, ax",
    "    mov   es, ax",
    "    mov   ss, ax",
    "    lgdt  [0x9f60]",
    "    mov   eax, cr0",
    "    or    eax, 1",                 // CR0.PE
    "    mov   cr0, eax",
    // Far jump to 32-bit protected mode: 0x66 (opsize) 0xEA off32 sel16.
    "    .byte 0x66, 0xea",
    "    .long oxide_wakeup_tramp_32 - oxide_wakeup_tramp + 0x9000",
    "    .word 0x08",
    ".code32",
    "oxide_wakeup_tramp_32:",
    "    mov   ax, 0x10",
    "    mov   ds, ax",
    "    mov   es, ax",
    "    mov   ss, ax",
    "    mov   eax, cr4",
    "    or    eax, 0x20",              // CR4.PAE — required before CR0.PG
    "    mov   cr4, eax",
    "    mov   eax, [0x9f00]",          // kernel master CR3
    "    mov   cr3, eax",
    "    mov   ecx, 0xc0000080",        // IA32_EFER
    "    rdmsr",
    "    or    eax, 0x900",             // EFER.LME | EFER.NXE
    "    wrmsr",                        // NXE: kernel PTEs set the NX bit,
    //                                     which is reserved while NXE is off
    "    mov   eax, cr0",
    "    or    eax, 0x80000001",        // CR0.PG | CR0.PE → long mode
    "    mov   cr0, eax",
    // Far jump to 64-bit: 0xEA off32 sel16, 64-bit code selector 0x18.
    "    .byte 0xea",
    "    .long oxide_wakeup_tramp_64 - oxide_wakeup_tramp + 0x9000",
    "    .word 0x18",
    ".code64",
    "oxide_wakeup_tramp_64:",
    // The kernel entry is a 64-bit address no far jump can encode, so it is
    // patched into the data block and loaded from there.
    "    mov   rax, [rip + oxide_wakeup_tramp_entry]",
    "    jmp   rax",
    "    .org  0xf00",
    ".globl oxide_wakeup_tramp_cr3",
    "oxide_wakeup_tramp_cr3:   .quad 0",   // 0xf00
    ".globl oxide_wakeup_tramp_entry",
    "oxide_wakeup_tramp_entry: .quad 0",   // 0xf08
    "    .org  0xf40",
    "oxide_wakeup_tramp_gdt:",             // 0xf40
    "    .quad 0x0000000000000000",        // null
    "    .quad 0x00cf9a000000ffff",        // 0x08: 32-bit code
    "    .quad 0x00cf92000000ffff",        // 0x10: 32-bit data
    "    .quad 0x00209a0000000000",        // 0x18: 64-bit code (L=1)
    "    .org  0xf60",
    "oxide_wakeup_tramp_gdtptr:",          // 0xf60
    "    .word 0x1f",                      // limit = 4*8 - 1
    "    .long oxide_wakeup_tramp_gdt - oxide_wakeup_tramp + 0x9000",
    "    .org  0x1000",
    ".globl oxide_wakeup_tramp_end",
    "oxide_wakeup_tramp_end:",
    ".code64",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    static oxide_wakeup_tramp: u8;
    static oxide_wakeup_tramp_end: u8;
}

static PAGE_RESERVED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Declare that [`WAKEUP_TRAMP_PA`] has been withheld from the physical
/// allocator and is the resume stub's to write.
///
/// Called from the boot path, right after PMM init and before the first
/// allocation. Until it is, no resume vector can be published, and a sleep
/// state that needs one is not admitted — a stub copied over a page the
/// allocator already handed out is a silent memory corruption, so this fails
/// closed rather than hoping.
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub fn set_wakeup_page_reserved() { PAGE_RESERVED.store(true, core::sync::atomic::Ordering::Release); }

/// Whether the boot path reserved the resume stub's page. # C: O(1)
pub fn wakeup_page_reserved() -> bool { PAGE_RESERVED.load(core::sync::atomic::Ordering::Acquire) }

/// Copy the resume stub to its low page, patch the kernel page-table root
/// and the 64-bit entry into it, and identity-map the page in the kernel
/// master tables so it keeps executing once the stub turns paging on.
///
/// Returns the physical address to publish in the firmware waking vector, or
/// `None` when the stub cannot be placed — no reserved page, no HHDM, or no
/// captured master page-table root. Every `None` is a reason `mem` must not
/// be admitted (`32a§2` invariant 7).
///
/// # SAFETY: single-CPU boot or suspend path at CPL=0. Writes the reserved
/// low page named by [`WAKEUP_TRAMP_PA`] and adds one identity mapping to
/// the kernel master page tables.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn install_wakeup_trampoline() -> Option<u64> {
    if !wakeup_page_reserved() { return None; }
    let hhdm = crate::mmu_ops::hhdm_offset();
    if hhdm == 0 { return None; }
    let master = crate::mmu_ops::kernel_master();
    if master == 0 { return None; }
    // SAFETY: the two symbols bound the linked blob; the subtraction is
    // within one object and the length is the blob's own size.
    let (blob, len) = unsafe {
        let s = &oxide_wakeup_tramp as *const u8;
        let e = &oxide_wakeup_tramp_end as *const u8;
        (s, e as usize - s as usize)
    };
    if len > TRAMP_BYTES { return None; }
    let page = (hhdm + WAKEUP_TRAMP_PA) as *mut u8;
    // SAFETY: `page` is the HHDM alias of the boot-reserved low page, non-overlapping with the blob, and `len` is at most one page.
    unsafe { core::ptr::copy_nonoverlapping(blob, page, len); }
    // SAFETY: both offsets are 8-byte-aligned slots inside the copied blob.
    unsafe {
        core::ptr::write_volatile(page.add(OFF_CR3 as usize) as *mut u64, master);
        core::ptr::write_volatile(page.add(OFF_ENTRY as usize) as *mut u64, super::lowlevel::wakeup_entry());
    }
    // SAFETY: the low page is reserved from the allocator and owned by this
    // stub; the identity mapping is what keeps it executing across the
    // paging-on transition, and it goes only in the master tables the stub
    // itself loads.
    unsafe {
        <crate::mmu_ops::X86Mmu as MmuOps>::map_at(master, Va(WAKEUP_TRAMP_PA), Pa(WAKEUP_TRAMP_PA),
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC, PageSize::P4K);
    }
    Some(WAKEUP_TRAMP_PA)
}

/// Hosted build: there is no low physical memory to place a stub in.
/// # SAFETY: no-op. # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub unsafe fn install_wakeup_trampoline() -> Option<u64> { None }

#[cfg(test)]
#[path = "trampoline/tests.rs"]
mod tests;
