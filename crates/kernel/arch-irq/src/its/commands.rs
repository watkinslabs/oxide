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

/// MAPC opcode (ICID → Collection-table entry → target RD).
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_MAPC: u8 = 0x09;
/// MAPD opcode (DeviceID → ITT base + size).
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_MAPD: u8 = 0x08;
/// MAPTI opcode (Device+EventID → LPI INTID + ICID, full ITT entry).
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_MAPTI: u8 = 0x0a;
/// INV opcode (invalidate cached LPI config for one Device+Event).
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_INV: u8 = 0x0c;
/// SYNC opcode (barrier — wait for prior commands targeting RDbase).
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_SYNC: u8 = 0x05;
/// INT opcode (synthesise an LPI from (DeviceID, EventID) without a
/// PCI requester write). Used as a kernel-side self-test of the
/// ITS → RD pending-table → CPU dispatch path.
#[cfg(target_arch = "aarch64")]
pub const ITS_CMD_INT: u8 = 0x03;

/// Build a MAPD command (ARM IHI 0069 §5.13.4).
/// `size` = number-of-EventID-bits - 1; ITT must be 256-byte aligned.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_mapd(device_id: u32, itt_pa: u64, size: u32) -> [u64; 4] {
    let dw0 = ITS_CMD_MAPD as u64 | ((device_id as u64) << 32);
    let dw1 = (size & 0x1f) as u64;
    let dw2 = (1u64 << 63) | (itt_pa & 0x000F_FFFF_FFFF_FF00);
    [dw0, dw1, dw2, 0]
}

/// Build a MAPTI command (ARM IHI 0069 §5.13.6). Maps
/// (DeviceID, EventID) → (LPI pINTID, ICID).
/// `lpi_intid` must be ≥ 8192 (LPI base) and < 8192+(1 << ID_BITS).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_mapti(device_id: u32, event_id: u32, lpi_intid: u32, icid: u16) -> [u64; 4] {
    let dw0 = ITS_CMD_MAPTI as u64 | ((device_id as u64) << 32);
    let dw1 = (event_id as u64) | ((lpi_intid as u64) << 32);
    let dw2 = icid as u64 & 0xFFFF;
    [dw0, dw1, dw2, 0]
}

/// Build an INV command (ARM IHI 0069 §5.13.2). Invalidates the
/// ITS's cached LPI configuration for one (DeviceID, EventID) so a
/// subsequent PROPBASER-table edit takes effect.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_inv(device_id: u32, event_id: u32) -> [u64; 4] {
    let dw0 = ITS_CMD_INV as u64 | ((device_id as u64) << 32);
    let dw1 = event_id as u64;
    [dw0, dw1, 0, 0]
}

/// Build an INT command (ARM IHI 0069 §5.13.3). Causes the ITS to
/// internally synthesise the LPI mapped to (DeviceID, EventID) —
/// equivalent to a device writing EventID to GITS_TRANSLATER, but
/// triggered by the kernel posting a command. Used to self-test
/// the ITS delivery path independent of any PCI requester.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_int(device_id: u32, event_id: u32) -> [u64; 4] {
    let dw0 = ITS_CMD_INT as u64 | ((device_id as u64) << 32);
    let dw1 = event_id as u64;
    [dw0, dw1, 0, 0]
}

/// Build a SYNC command (ARM IHI 0069 §5.13.13). Waits for prior
/// commands targeting `rdbase` (processor number when PTA=0) to
/// complete before subsequent commands proceed.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_sync(rdbase: u32) -> [u64; 4] {
    let dw2 = (rdbase as u64 & 0x7_FFFF_FFFF) << 16;
    [ITS_CMD_SYNC as u64, 0, dw2, 0]
}

/// Build a MAPC command (ARM IHI 0069 §5.13.5).
/// `rdbase` = processor number when GITS_TYPER.PTA=0, else the
/// 64 KiB-aligned RD PA. QEMU virt + GICv3 has PTA=0 → use 0 for
/// the boot CPU.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmd_mapc(icid: u16, rdbase: u32) -> [u64; 4] {
    let dw0 = ITS_CMD_MAPC as u64;
    let dw2 = (1u64 << 63)
            | ((rdbase as u64 & 0x7_FFFF_FFFF) << 16)
            | (icid as u64 & 0xFFFF);
    [dw0, 0, dw2, 0]
}

/// Post a 32-byte command at `CWRITER`, advance the write index,
/// then poll `CREADR` until it catches up. CREADR's bit[0]
/// (Stalled) is masked out of the comparison.
///
/// # SAFETY: caller asserts cmdq + BASERs programmed and
/// GITS_CTLR.Enabled latched; HHDM covers the queue PMM frame;
/// runs single-CPU pre-init IRQ-off.
/// # C: O(polls) — typically tens of cycles on QEMU.
/// # Ctx: pre-init, IRQ-off, single-CPU
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
