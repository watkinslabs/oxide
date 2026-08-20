use core::sync::atomic::Ordering;

use super::regs::{CMDQ_PA, GITS_CTLR, GITS_CREADR, GITS_CWRITER, ITS_VA};

/// GITS_CTLR.Enabled = bit 0. Once flipped, the ITS begins consuming
/// commands posted via GITS_CWRITER advances. ARM IHI 0069 §11.5.5
/// (RAO/WI for some bits; bit 0 is the only one we touch).
#[cfg(target_arch = "aarch64")]
const GITS_CTLR_ENABLED: u32 = 1 << 0;

// ---- Command-post protocol (F56-06) ---------------------------------------

/// Per-command size on GICv3 ITS (ARM IHI 0069 §5.13).
#[cfg(target_arch = "aarch64")]
const CMD_SIZE: u64 = 32;

/// Command-queue size in bytes (F56-02 allocates 1 page → 128 cmds).
#[cfg(target_arch = "aarch64")]
const CMDQ_SIZE: u64 = 0x1000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CmdStatus {
    /// `cmdq_setup` / `enable` haven't run yet.
    NotReady,
    /// CREADR caught up to the new CWRITER. `polls` records spin
    /// iterations consumed (0 ≈ ITS drained synchronously).
    Posted { cwriter: u64, creadr: u64, polls: u32 },
    /// CREADR did not catch up within `polls` iterations — likely
    /// a malformed command or stuck queue. `creadr` is the last
    /// observed value.
    Timeout { cwriter: u64, creadr: u64 },
}

/// Post a 32-byte command at `CWRITER`, advance the write index,
/// then poll `CREADR` until it catches up. CREADR's bit[0]
/// (Stalled) is masked out of the comparison.
///
/// # SAFETY: caller asserts cmdq + BASERs programmed and
/// GITS_CTLR.Enabled latched; HHDM covers the queue PMM frame; and the
/// caller serializes this ITS command queue against every other poster.
/// # C: O(polls) — typically tens of cycles on QEMU.
/// # Ctx: pre-init or caller-held ITS command lock
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn cmd_post(hhdm: u64, cmd: [u64; 4]) -> CmdStatus {
    let its_va = ITS_VA.load(Ordering::Acquire);
    let q_pa   = CMDQ_PA.load(Ordering::Acquire);
    if its_va == 0 || q_pa == 0 || hhdm == 0 {
        return CmdStatus::NotReady;
    }
    // SAFETY: ITS frame Device-attr mapped; HHDM-mapped cmdq frame; widths per spec.
    unsafe {
        let cwriter_pre = core::ptr::read_volatile(
            (its_va + GITS_CWRITER as u64) as *const u64,
        );
        let off = cwriter_pre & (CMDQ_SIZE - 1);
        let dst = hhdm.wrapping_add(q_pa + off) as *mut u64;
        for i in 0..4 {
            core::ptr::write_volatile(dst.add(i), cmd[i]);
        }
        crate::cache::clean_to_poc(hhdm.wrapping_add(q_pa + off), CMD_SIZE as usize);
        let new_cwriter = (cwriter_pre + CMD_SIZE) & (CMDQ_SIZE - 1);
        core::ptr::write_volatile(
            (its_va + GITS_CWRITER as u64) as *mut u64,
            new_cwriter,
        );
        let mut polls = 0u32;
        loop {
            let creadr = core::ptr::read_volatile(
                (its_va + GITS_CREADR as u64) as *const u64,
            );
            if (creadr & !1) == new_cwriter {
                return CmdStatus::Posted { cwriter: new_cwriter, creadr, polls };
            }
            polls = polls.wrapping_add(1);
            if polls > 1_000_000 {
                return CmdStatus::Timeout { cwriter: new_cwriter, creadr };
            }
            core::hint::spin_loop();
        }
    }
}

/// Set `GITS_CTLR.Enabled`. Must be called only after `cmdq_setup`
/// + `baser_setup` have programmed the queue and tables.
///
/// # SAFETY: caller asserts cmdq + BASERs programmed; LPIs enabled
/// at the RD; single-CPU pre-init IRQ-off.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn ctlr_enable() -> u32 {
    let its_va = ITS_VA.load(Ordering::Acquire);
    if its_va == 0 { return 0; }
    // SAFETY: ITS frame Device-attr mapped; CTLR is RW at offset 0.
    unsafe {
        let p = (its_va + GITS_CTLR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(p);
        core::ptr::write_volatile(p, cur | GITS_CTLR_ENABLED);
        core::ptr::read_volatile(p)
    }
}
