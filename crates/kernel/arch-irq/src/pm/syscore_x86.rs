// The x86 interrupt controllers' core callbacks (`32a§7`), bound to the real
// register windows. A shim by design (`53`): every decision — what is saved,
// in what order, what a resume writes first — lives in the ungated state
// modules this calls.

use core::sync::atomic::{AtomicBool, Ordering};

use power::decide::{Error, KResult};
use power::suspend::syscore::{register_syscore, SyscoreOps};
use sync::{Spinlock, TaskList as PmListClass};

use super::ioapic_state::{self, IoapicState, IoapicRegs};
use super::lapic_state::{self, ApicRegs, LapicState};
use crate::apicdef::{IOAPIC_IOREGSEL, IOAPIC_IOWIN};

/// The local-APIC register window, through whichever architectural interface
/// this CPU's APIC is addressed by.
struct Lapic;

impl ApicRegs for Lapic {
    fn read(&self, off: usize) -> u32 {
        // SAFETY: `read_register` validates the offset and selects the MMIO or
        // MSR interface; it is called here at CPL 0 with interrupts disabled
        // and one CPU online, which is the core-callback contract.
        unsafe { crate::lapic::regs::read_register(off) }.unwrap_or(0)
    }
    fn write(&mut self, off: usize, v: u32) {
        // SAFETY: `write_register` validates the offset and selects the MMIO
        // or MSR interface; the core-callback contract gives this exclusive
        // ownership of the local APIC — interrupts off, one CPU online.
        unsafe { crate::lapic::regs::write_register(off, v) };
    }
}

/// One I/O APIC's indirect register file at `va`.
struct Ioapic { va: u64 }

impl IoapicRegs for Ioapic {
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: `va` is the live device mapping of this controller's window;
        // the index-then-data pair is atomic because the core-callback
        // contract leaves one CPU online with interrupts disabled.
        unsafe {
            core::ptr::write_volatile((self.va + IOAPIC_IOREGSEL as u64) as *mut u32, reg);
            core::ptr::read_volatile((self.va + IOAPIC_IOWIN as u64) as *const u32)
        }
    }
    fn write(&mut self, reg: u32, v: u32) {
        // SAFETY: as the read above; `va` is the live mapping and this CPU is
        // the only one that can touch the index register right now.
        unsafe {
            core::ptr::write_volatile((self.va + IOAPIC_IOREGSEL as u64) as *mut u32, reg);
            core::ptr::write_volatile((self.va + IOAPIC_IOWIN as u64) as *mut u32, v);
        }
    }
}

static LAPIC_SAVED: Spinlock<LapicState, PmListClass> =
    Spinlock::new(LapicState { maxlvt: 0, id: 0, taskpri: 0, ldr: 0, dfr: 0, spiv: 0,
        lvt_timer: 0, lvt_perf: 0, lvt_lint0: 0, lvt_lint1: 0, lvt_error: 0,
        timer_init: 0, timer_div: 0, lvt_thermal: 0, lvt_cmci: 0 });
/// Whether a save has run, so a resume with no matching suspend writes nothing.
static LAPIC_VALID: AtomicBool = AtomicBool::new(false);

static IOAPIC_SAVED: Spinlock<Option<IoapicState>, PmListClass> = Spinlock::new(None);

fn lapic_suspend() -> KResult<()> {
    if crate::lapic::regs::LAPIC_BASE_VA.load(Ordering::Acquire) == 0
        && !crate::lapic::regs::x2apic_active() { return Err(Error::Nodata); }
    let mut w = Lapic;
    let s = lapic_state::save(&w);
    *LAPIC_SAVED.lock() = s;
    LAPIC_VALID.store(true, Ordering::Release);
    lapic_state::quiesce(&mut w, &s);
    Ok(())
}

fn lapic_resume() {
    if !LAPIC_VALID.load(Ordering::Acquire) { return; }
    let s = *LAPIC_SAVED.lock();
    lapic_state::restore(&mut Lapic, &s);
}

fn ioapic_window() -> Option<Ioapic> {
    let va = hal_x86_64::ioapic::base_va();
    if va == 0 { None } else { Some(Ioapic { va }) }
}

fn ioapic_suspend() -> KResult<()> {
    let Some(mut w) = ioapic_window() else { return Err(Error::Nodata) };
    let s = ioapic_state::save(&w);
    ioapic_state::mask_all(&mut w, &s);
    *IOAPIC_SAVED.lock() = Some(s);
    Ok(())
}

fn ioapic_resume() {
    let saved = IOAPIC_SAVED.lock().clone();
    let (Some(s), Some(mut w)) = (saved, ioapic_window()) else { return };
    ioapic_state::restore(&mut w, &s);
}

/// The I/O APIC registers first so the local APIC's table is the one that
/// suspends last and resumes first: a redirection entry pointed at a local
/// APIC that is not yet back is an interrupt with nowhere to land.
static IOAPIC_OPS: SyscoreOps = SyscoreOps {
    name: "ioapic", suspend: Some(ioapic_suspend), resume: Some(ioapic_resume), shutdown: None,
};
static LAPIC_OPS: SyscoreOps = SyscoreOps {
    name: "lapic", suspend: Some(lapic_suspend), resume: Some(lapic_resume), shutdown: None,
};

/// Register both x86 interrupt controllers. # C: O(1)
/// # Ctx: pre-init, single-CPU
pub fn register() {
    register_syscore(&IOAPIC_OPS);
    register_syscore(&LAPIC_OPS);
}
