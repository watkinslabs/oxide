use core::sync::atomic::Ordering;

use super::regs::{
    CBASER_IC_NC, CBASER_INNER_SH, CBASER_PS_4K, CBASER_SIZE_1PG, CBASER_VALID, CMDQ_PA,
    GITS_CBASER, GITS_CREADR, GITS_CWRITER, GITS_TABLE_PAGE_BYTES, ITS_VA,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CmdqStatus {
    /// `enable` has not been called yet, or no ITS is present.
    NoIts,
    /// PMM declined the 4 KiB frame.
    AllocFailed,
    /// Already programmed earlier in this boot.
    AlreadyOn,
    /// Programmed. `cbaser_rd` reflects the value the ITS latched
    /// after the write (some bits are RO/RES0). `creadr` should be
    /// 0 immediately after init.
    Ready { cmdq_pa: u64, cbaser_wr: u64, cbaser_rd: u64, creadr: u64 },
}

/// Allocate a 4 KiB command-queue frame, zero it, and program
/// GITS_CBASER + zero CWRITER. Reads back CBASER + CREADR for
/// observation. Does NOT enable the ITS yet (GITS_CTLR untouched).
///
/// Composition follows ARM IHI 0069 §11.5.4: Valid=1, Inner-NC,
/// Inner-Shareable, 4 KiB page, Size=0 (1 page = 128 commands).
///
/// # SAFETY: caller asserts `enable` already published `ITS_VA`,
/// runs single-CPU pre-init IRQ-off, and that PMM is up. The cmd
/// queue frame is owned by the ITS until poweroff (never freed).
/// # C: O(page-zero) ≈ O(4096B)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn cmdq_setup(hhdm: u64) -> CmdqStatus {
    let its_va = ITS_VA.load(Ordering::Acquire);
    if its_va == 0 {
        return CmdqStatus::NoIts;
    }
    if CMDQ_PA.load(Ordering::Acquire) != 0 {
        return CmdqStatus::AlreadyOn;
    }
    let pa = match pmm::setup::alloc_raw_frame() {
        Some(p) => p,
        None    => return CmdqStatus::AllocFailed,
    };
    // Zero the frame via HHDM — PMM does not guarantee zero-init,
    // and the ITS treats stale bytes as legitimate command opcodes
    // once GITS_CTLR.Enabled flips on in F56-04.
    if hhdm != 0 {
        let va = hhdm.wrapping_add(pa) as *mut u64;
        // SAFETY: HHDM covers freshly-allocated PMM frame; aligned u64 stores within the 4 KiB page.
        unsafe {
            for i in 0..(GITS_TABLE_PAGE_BYTES / 8) {
                core::ptr::write_volatile(va.add(i), 0);
            }
        }
        crate::cache::clean_to_poc(hhdm.wrapping_add(pa), GITS_TABLE_PAGE_BYTES);
    }
    let cbaser_wr = CBASER_VALID
        | CBASER_IC_NC
        | CBASER_INNER_SH
        | CBASER_PS_4K
        | CBASER_SIZE_1PG
        | (pa & 0x0000_FFFF_FFFF_F000);
    // SAFETY: ITS control frame Device-attr mapped; offsets within the 64 KiB region; 64-bit access widths per spec.
    let (cbaser_rd, creadr) = unsafe {
        core::ptr::write_volatile((its_va + GITS_CBASER  as u64) as *mut u64, cbaser_wr);
        core::ptr::write_volatile((its_va + GITS_CWRITER as u64) as *mut u64, 0);
        (
            core::ptr::read_volatile((its_va + GITS_CBASER as u64) as *const u64),
            core::ptr::read_volatile((its_va + GITS_CREADR as u64) as *const u64),
        )
    };
    CMDQ_PA.store(pa, Ordering::Release);
    CmdqStatus::Ready { cmdq_pa: pa, cbaser_wr, cbaser_rd, creadr }
}

/// PA of the command queue, or 0 if `cmdq_setup` has not run.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmdq_pa() -> u64 { CMDQ_PA.load(Ordering::Acquire) }
