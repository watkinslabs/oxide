// The GIC's core callbacks (`32a§7`), bound to the real distributor,
// redistributor and CPU-interface registers. A shim by design (`53`): what is
// saved and in what order lives in `super::gic_state`.

use core::arch::asm;
use core::sync::atomic::Ordering;

use alloc::boxed::Box;
use power::decide::{Error, KResult};
use power::suspend::syscore::{register_syscore, SyscoreOps};
use sync::{Spinlock, TaskList as PmListClass};

use super::gic_state::{self, CpuIfReg, GicCpuIf, GicDistState, GicRedistState, GicRegs,
                       CPUIF_RESTORE_ORDER};
use crate::gicdef::GICR_SGI_OFFSET;

/// Redistributor sleep/wake acknowledgement budget. The acknowledgement is a
/// handful of cycles on hardware that implements it; a redistributor that
/// never answers has no power management, and the reference treats that as a
/// diagnostic rather than a failure.
const WAKER_SPINS: u32 = 1_000_000;

/// A memory-mapped GIC window at `va`.
struct Window { va: u64 }

impl GicRegs for Window {
    fn read(&self, off: usize) -> u32 {
        // SAFETY: `va` is the live device mapping of a GIC frame and `off` is
        // an architectural offset inside it; the core-callback contract leaves
        // one CPU online with interrupts disabled.
        unsafe { core::ptr::read_volatile((self.va + off as u64) as *const u32) }
    }
    fn write(&mut self, off: usize, v: u32) {
        // SAFETY: as the read above; this CPU exclusively owns the controller
        // for the duration of the core callback.
        unsafe { core::ptr::write_volatile((self.va + off as u64) as *mut u32, v) }
    }
    fn read64(&self, off: usize) -> u64 {
        // SAFETY: the affinity-routing registers are eight bytes wide and
        // eight-byte aligned within the live distributor mapping.
        unsafe { core::ptr::read_volatile((self.va + off as u64) as *const u64) }
    }
    fn write64(&mut self, off: usize, v: u64) {
        // SAFETY: as the 64-bit read above; the distributor is disabled by the
        // restore walk before any routing register is written.
        unsafe { core::ptr::write_volatile((self.va + off as u64) as *mut u64, v) }
    }
}

fn dist() -> Option<Window> {
    let va = crate::gic::regs::GICD_VA.load(Ordering::Acquire);
    if va == 0 { None } else { Some(Window { va }) }
}

fn redist_rd() -> Option<Window> {
    let va = crate::gic::regs::GICR_VA.load(Ordering::Acquire);
    if va == 0 { None } else { Some(Window { va }) }
}

fn redist_sgi() -> Option<Window> {
    redist_rd().map(|w| Window { va: w.va + GICR_SGI_OFFSET })
}

fn cpuif_save() -> GicCpuIf {
    let (pmr, ctlr, grpen1): (u64, u64, u64);
    // SAFETY: reads of this PE's own GIC CPU-interface system registers; legal
    // at EL1 once the system-register interface is enabled, which GIC bring-up
    // did, and they have no side effects.
    unsafe {
        asm!("mrs {0}, s3_0_c4_c6_0",    out(reg) pmr,    options(nomem, nostack));
        asm!("mrs {0}, s3_0_c12_c12_4",  out(reg) ctlr,   options(nomem, nostack));
        asm!("mrs {0}, s3_0_c12_c12_7",  out(reg) grpen1, options(nomem, nostack));
    }
    GicCpuIf { pmr: pmr as u32, ctlr: ctlr as u32, grpen1: grpen1 as u32 }
}

fn cpuif_write(reg: CpuIfReg, v: u32) {
    let v = v as u64;
    // SAFETY: writes to this PE's own GIC CPU-interface system registers,
    // legal at EL1 with the system-register interface enabled. The core
    // callback owns interrupt delivery on this CPU for the duration, and the
    // Group-1 enable is written last so nothing is delivered through a
    // half-restored interface.
    unsafe {
        match reg {
            CpuIfReg::Pmr    => asm!("msr s3_0_c4_c6_0, {0}",   in(reg) v, options(nomem, nostack)),
            CpuIfReg::Ctlr   => asm!("msr s3_0_c12_c12_4, {0}", in(reg) v, options(nomem, nostack)),
            CpuIfReg::Grpen1 => asm!("msr s3_0_c12_c12_7, {0}", in(reg) v, options(nomem, nostack)),
        }
        asm!("isb", options(nomem, nostack));
    }
}

/// Boxed because the distributor state is sized by the implemented interrupt
/// count, which is a firmware property rather than a constant.
static SAVED: Spinlock<Option<Box<(GicDistState, GicRedistState, GicCpuIf)>>, PmListClass> =
    Spinlock::new(None);

fn gic_suspend() -> KResult<()> {
    let (Some(d), Some(r)) = (dist(), redist_sgi()) else { return Err(Error::Nodata) };
    let saved = (gic_state::dist_save(&d), gic_state::redist_save(&r), cpuif_save());
    *SAVED.lock() = Some(Box::new(saved));
    // Group-1 delivery off before the redistributor is told to sleep, so no
    // interrupt is presented to a CPU interface on its way down.
    cpuif_write(CpuIfReg::Grpen1, 0);
    let mut d = d;
    gic_state::dist_quiesce(&mut d);
    if let Some(mut rd) = redist_rd() { gic_state::redist_sleep(&mut rd, WAKER_SPINS); }
    Ok(())
}

fn gic_resume() {
    let saved = SAVED.lock().take();
    let Some(saved) = saved else { return };
    let (ds, rs, cs) = *saved;
    if let Some(mut rd) = redist_rd() { gic_state::redist_wake(&mut rd, WAKER_SPINS); }
    if let Some(mut d) = dist() { gic_state::dist_restore(&mut d, &ds); }
    if let Some(mut r) = redist_sgi() { gic_state::redist_restore(&mut r, &rs); }
    for reg in CPUIF_RESTORE_ORDER { cpuif_write(reg, cs.value(reg)); }
}

static GIC_OPS: SyscoreOps = SyscoreOps {
    name: "gic", suspend: Some(gic_suspend), resume: Some(gic_resume), shutdown: None,
};

/// Register the GIC's core callbacks. # C: O(1)
/// # Ctx: pre-init, single-CPU
pub fn register() { register_syscore(&GIC_OPS); }
