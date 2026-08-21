// Relocated, stack-independent x86 collision copy and final image entry.

use super::{PlanError, PAGE_BYTES};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use super::TerminalControl;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const CR4_PGE: u64 = 1 << 7;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const QWORDS_PER_PAGE: u64 = PAGE_BYTES / core::mem::size_of::<u64>() as u64;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_HEAD: usize = core::mem::offset_of!(TerminalControl, collision_head_pa);
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_HHDM: usize = core::mem::offset_of!(TerminalControl, hhdm_offset);
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_IMAGE_CR3: usize = core::mem::offset_of!(TerminalControl, image_cr3_pa);
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_RESTORE_ENTRY: usize = core::mem::offset_of!(TerminalControl, restore_entry_va);
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_CONTINUATION: usize = core::mem::offset_of!(TerminalControl, continuation_va);
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const OFF_CPU_STATE: usize = core::mem::offset_of!(TerminalControl, cpu_state_va);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text.hibernate_restore,\"ax\",@progbits",
    ".globl oxide_hibernate_terminal_start",
    ".type  oxide_hibernate_terminal_start, @function",
    "oxide_hibernate_terminal_start:",
    // rdi = HHDM address of TerminalControl, rsi = temporary CR3 PA.
    // Load every nonlocal before changing tables. No stack access follows.
    "    cli",
    "    cld",
    "    mov  rdx, [rdi + {off_head}]",
    "    mov  r12, [rdi + {off_hhdm}]",
    "    mov  r8,  [rdi + {off_image_cr3}]",
    "    mov  r11, [rdi + {off_restore_entry}]",
    "    mov  r9,  [rdi + {off_continuation}]",
    "    mov  r10, [rdi + {off_cpu_state}]",
    "    mov  cr3, rsi",
    // A CR3 reload does not invalidate global translations. Toggle PGE so no
    // old-kernel global entry can survive into the temporary map.
    "    mov  rax, cr4",
    "    mov  rbx, rax",
    "    and  rax, {cr4_no_pge}",
    "    mov  cr4, rax",
    "    mov  rax, cr3",
    "    mov  cr3, rax",
    "    mov  cr4, rbx",
    "2:",
    "    test rdx, rdx",
    "    jz   6f",
    "    lea  r13, [r12 + rdx]",
    "    mov  r14, [r13 + 8]",
    "    lea  r15, [r13 + 16]",
    "3:",
    "    test r14, r14",
    "    jz   5f",
    "    mov  rsi, [r15]",
    "    mov  rdi, [r15 + 8]",
    "    add  rsi, r12",
    "    add  rdi, r12",
    "    mov  ecx, {qwords_per_page}",
    "    rep  movsq",
    "    add  r15, 16",
    "    dec  r14",
    "    jmp  3b",
    "5:",
    "    mov  rdx, [r13]",
    "    jmp  2b",
    "6:",
    // This page is mapped at the same VA by the temporary and image tables.
    // It owns the final CR3 write so execution never continues in relocated
    // code whose virtual address the image is not required to map.
    "    jmp  r11",
    ".globl oxide_hibernate_terminal_end",
    "oxide_hibernate_terminal_end:",
    ".size oxide_hibernate_terminal_start, . - oxide_hibernate_terminal_start",

    ".section .text",
    ".globl oxide_hibernate_restore_entry",
    ".type  oxide_hibernate_restore_entry, @function",
    "oxide_hibernate_restore_entry:",
    // r8 = image CR3, r9 = continuation, r10 = SavedCpuState address.
    "    mov  cr3, r8",
    "    mov  rax, cr4",
    "    mov  rbx, rax",
    "    and  rax, {cr4_no_pge}",
    "    mov  cr4, rax",
    "    mov  rax, cr3",
    "    mov  cr3, rax",
    "    mov  cr4, rbx",
    // Re-publish the canonical suspend record in restored memory. The saved
    // continuation then restores CR4/CR3/descriptors/MSRs from that record.
    "    mov  [rip + oxide_suspend_record], r10",
    "    jmp  r9",
    ".size oxide_hibernate_restore_entry, . - oxide_hibernate_restore_entry",
    off_head = const OFF_HEAD,
    off_hhdm = const OFF_HHDM,
    off_image_cr3 = const OFF_IMAGE_CR3,
    off_restore_entry = const OFF_RESTORE_ENTRY,
    off_continuation = const OFF_CONTINUATION,
    off_cpu_state = const OFF_CPU_STATE,
    cr4_no_pge = const !(CR4_PGE as i64),
    qwords_per_page = const QWORDS_PER_PAGE as u32,
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    static oxide_hibernate_terminal_start: u8;
    static oxide_hibernate_terminal_end: u8;
    static oxide_hibernate_restore_entry: u8;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TerminalEntry { pub va: u64, pub pa: u64 }

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn sym(s: &'static u8) -> usize { s as *const u8 as usize }

/// Bytes copied into the destination-safe trampoline page. # C: O(1)
pub fn terminal_blob_len() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: both linker-visible labels bound one assembler-emitted range.
    unsafe { return sym(&oxide_hibernate_terminal_end) - sym(&oxide_hibernate_terminal_start); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Image virtual address of the final restored-text entry. # C: O(1)
pub fn restore_entry_va() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: taking the address of a linked text symbol does not access it.
    unsafe { return sym(&oxide_hibernate_restore_entry) as u64; }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Translate the final restored-text entry through the live kernel tables.
/// # C: O(page-table depth)
pub fn restore_entry_pa() -> Option<u64> {
    let va = restore_entry_va();
    if va == 0 { return None; }
    let hhdm = crate::mmu_ops::hhdm_offset();
    if hhdm == 0 { return None; }
    // SAFETY: kernel text and the master root are immutable after boot; HHDM
    // is the canonical table-page mapping published by `mmu_ops`.
    unsafe { hal::pt_walker::translate_at_va::<crate::vmm::PtWalkerX86>(va, hhdm) }
        .map(|(pa, _, _)| pa)
}

/// Copy the allocation-free terminal blob into its destination-safe page.
///
/// # SAFETY: `dst` points to one writable page excluded from every image
/// destination and remains live until [`enter_terminal`].
/// # C: O(blob bytes)
pub unsafe fn install_terminal(dst: *mut u8, dst_va: u64, dst_pa: u64)
    -> Result<TerminalEntry, PlanError>
{
    let len = terminal_blob_len();
    if len == 0 || len > PAGE_BYTES as usize || dst.is_null()
        || dst_va == 0 || dst_pa == 0 || dst_pa % PAGE_BYTES != 0
    { return Err(PlanError::Alignment); }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: fn contract provides a full writable page and the bounded source is linked text.
        unsafe { core::ptr::copy_nonoverlapping(&oxide_hibernate_terminal_start, dst, len); }
    }
    Ok(TerminalEntry { va: dst_va, pa: dst_pa })
}

/// Enter the copied terminal path. It never allocates, locks, calls or returns.
///
/// # SAFETY: the machine is single-CPU with interrupts disabled; `entry.va`
/// and `control_va` remain executable/readable under both the live and
/// temporary tables; all plan pages are destination-safe; terminal admission
/// has checked the complete collision chain.
/// # C: O(number of collision pages)
pub unsafe fn enter_terminal(entry: TerminalEntry, control_va: u64, temporary_cr3_pa: u64) -> ! {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: fn contract establishes the assembly entry ABI and irreversible machine state.
    unsafe {
        core::arch::asm!(
            "jmp {entry}",
            entry = in(reg) entry.va,
            in("rdi") control_va,
            in("rsi") temporary_cr3_pa,
            options(noreturn),
        )
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = (entry, control_va, temporary_cr3_pa); panic!("host terminal entry") }
}
