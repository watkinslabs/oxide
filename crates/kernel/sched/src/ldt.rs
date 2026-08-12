// Linux `switch_ldt` / `load_mm_ldt` / `flush_ldt` / `install_ldt`
// equivalents: the point where a per-mm Local Descriptor Table becomes the
// LDTR the CPU uses.
//
// The state lives on the address space (`vmm::ldt`), the descriptor
// programming lives in the HAL (`hal_x86_64::ldt`), and the cross-CPU call
// lives behind `hal::smp_call`; this module is the only place that joins
// them, so there is one answer to "when does LDTR change" rather than one
// per call site.
//
// Module manifest:
//   this file      — switch / reload / clear / install, and the remote
//                    handler the cross-CPU call runs on a peer.
//   ldt/converge.rs — the publish → converge → free ORDERING, ungated so it
//                    has tests that can fail.
//
// IRQ DISCIPLINE (`docs/54`). The `view()` read and the `lldt` that consumes
// it happen inside ONE interrupts-off window. Splitting them lets a converge
// IPI land in between: this CPU would service the IPI, load the NEW table,
// then finish its interrupted switch by loading the STALE base it read
// earlier — after the installing CPU already concluded that every target had
// converged and freed the old table. The reference makes the same demand and
// for the same reason.
//
// Every entry point is gated on `vmm::any_ldt_in_use()`, a global that no
// system sets unless something actually called `modify_ldt`. On the
// overwhelming majority of machines that makes each of these one relaxed
// atomic load in the switch path and nothing more.
//
// aarch64 has no LDT and no `modify_ldt` slot; everything here compiles to a
// no-op there rather than being absent, so callers in shared scheduler code
// need no `cfg` of their own.

pub mod converge;

use vmm::address_space::AddressSpace;
use vmm::ldt::LdtError;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use vmm::ldt::LdtView;

pub use converge::{install_and_converge, LdtInstallOps};

/// Reload LDTR for the address space this CPU is switching to.
///
/// Called with `prev`/`next` as the outgoing and incoming mms — either may be
/// absent for a kernel thread. Following the reference, the reload happens
/// when EITHER side has a table: leaving an LDT behind without clearing it
/// would let the incoming context load a selector into a table it does not
/// own, and an mm never loses a table once it has one, so the test is a pair
/// of loads with no lock.
/// # C: O(1)
/// # Ctx: context switch, preempt-off
pub fn switch_ldt(prev: Option<&AddressSpace>, next: Option<&AddressSpace>) {
    if !vmm::any_ldt_in_use() { return; }
    let prev_loaded = prev.map(|m| m.ldt_view().is_loaded()).unwrap_or(false);
    if !prev_loaded && !next.map(|m| m.ldt_view().is_loaded()).unwrap_or(false) { return; }
    apply(next);
}

/// Point this CPU's LDTR at `mm`'s table now, skipping the hardware writes
/// when it already holds that exact table generation.
///
/// This is what makes an entry usable on the thread that installed it before
/// it ever reschedules, and what a sibling thread's return-to-user runs if it
/// somehow missed the converge call.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub fn reload_current(mm: &AddressSpace) {
    if !vmm::any_ldt_in_use() { return; }
    apply(Some(mm));
}

/// Drop this CPU's LDT. Used where an address space is replaced outright
/// (`execve`) or borrowed by a kernel thread: the table the LDTR still names
/// is about to be freed with the old mm.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub fn clear_local() {
    if !vmm::any_ldt_in_use() { return; }
    apply(None);
}

/// True when this CPU's LDTR is behind `mm` and a return to user mode would
/// run with descriptors a peer thread has already replaced.
///
/// With the converge call in place this is expected to be false on every
/// return to user mode; it stays as the belt-and-braces check the
/// return-to-user path consults, and as the assertion a test can make.
/// # C: O(1)
pub fn needs_reload(mm: &AddressSpace) -> bool {
    if !vmm::any_ldt_in_use() { return false; }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v = mm.ldt_view();
        let want = if v.is_loaded() { hal_x86_64::ldt::load_token(v.generation) } else { 0 };
        return hal_x86_64::ldt::current_token(cpu_index()) != want;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = mm; false }
}

/// Install one descriptor into `mm`'s table and make it live everywhere
/// before returning (the reference's `write_ldt` tail: `install_ldt` then
/// free the displaced table).
///
/// The entry is usable on the calling thread's very next instruction and on
/// every sibling thread already running, because the converge waits.
/// # C: O(new table) + one IPI round-trip
/// # Ctx: syscall, preemptible
pub fn install_entry(mm: &AddressSpace, entry: u32, desc: u64) -> Result<(), LdtError> {
    let mut ops = Install { mm, entry, desc, err: None };
    install_and_converge(&mut ops);
    match ops.err { Some(e) => Err(e), None => Ok(()) }
}

/// `install_entry`'s binding of the ordering trait to this kernel's types.
struct Install<'a> {
    mm: &'a AddressSpace,
    entry: u32,
    desc: u64,
    err: Option<LdtError>,
}

impl LdtInstallOps for Install<'_> {
    type Old = Option<vmm::ldt::LdtSwap>;

    fn publish(&mut self) -> Self::Old {
        match self.mm.ldt().install(self.entry, self.desc) {
            Ok(swap) => Some(swap),
            Err(e) => { self.err = Some(e); None }
        }
    }

    fn cpumask(&mut self) -> cpu::CpuMask {
        if self.err.is_some() { return cpu::CpuMask::empty(); }
        self.mm.cpumask_full()
    }

    fn converge(&mut self, targets: cpu::CpuMask) {
        if self.err.is_some() { return; }
        // This CPU runs the reload directly (the reference's SCF_RUN_LOCAL):
        // it is excluded from the target set, and the installing thread may
        // load the new selector on its next instruction.
        reload_current(self.mm);
        hal::smp_call::call_function_many(
            targets.as_words(),
            hal::smp_call::CallKind::LdtReload,
            self.mm.root_pa(),
            true,
        );
    }

    fn free_old(&mut self, old: Self::Old) {
        if let Some(swap) = old { swap.release_after_converge(); }
    }
}

/// The cross-CPU call handler: reload LDTR if this CPU is running the
/// address space whose page-table root is `root_pa`, otherwise do nothing.
///
/// The reference's `flush_ldt` makes the same test against the mm the CPU has
/// loaded and returns without touching LDTR when it does not match — a CPU
/// that left the mm since the mask was read has nothing to reload.
/// # C: O(1)
/// # Ctx: IRQ context or a spin-relax drain; takes no lock, never sleeps
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn flush_ldt_remote(root_pa: u64) {
    if !vmm::any_ldt_in_use() { return; }
    let Some(cur) = crate::live::current() else { return };
    // SAFETY: runs on this CPU with interrupts masked (IRQ dispatch) or
    // inside a lock spin on this CPU; neither can race an `execve` replacing
    // this task's mm, which only the task itself performs.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return };
    if mm.root_pa() != root_pa { return; }
    apply(Some(&**mm));
}

/// Same entry point where the runqueue is not compiled in (a hosted build
/// without the `hosted` feature): there is no current task to consult, so a
/// remote reload has nothing to reload.
/// # C: O(1)
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
pub fn flush_ldt_remote(root_pa: u64) { let _ = root_pa; }

/// Program LDTR for `mm` (or clear it when `None`). The one place `lldt` is
/// reached from.
///
/// The `view()` load, the GDT descriptor write and the `lldt` all happen with
/// interrupts masked: the GDT slot written and the `lldt` that consumes it
/// must belong to the same processor, and the view must not go stale between
/// being read and being loaded (see the module header).
#[allow(unused_variables)]
fn apply(mm: Option<&AddressSpace>) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        use sync::IrqGate;
        // SAFETY: paired 1:1 with the `restore` below; the section contains no
        // sleeping call and no lock acquisition, so no spin-relax drain can
        // run inside it and reorder against the `lldt`.
        let flags = unsafe { hal_x86_64::X86IrqGate::save_disable() };
        apply_locked(mm.map(|m| m.ldt_view()).unwrap_or(LdtView::NONE));
        // SAFETY: restores the interrupt state saved immediately above.
        unsafe { hal_x86_64::X86IrqGate::restore(flags); }
    }
}

/// The descriptor write and `lldt`, with migration and IPI-interleaving
/// already excluded by the caller.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn apply_locked(view: LdtView) {
    let cpu = cpu_index();
    let want = if view.is_loaded() { hal_x86_64::ldt::load_token(view.generation) } else { 0 };
    if hal_x86_64::ldt::current_token(cpu) == want { return; }
    if view.is_loaded() {
        // SAFETY: `view` came from a live `AddressSpace` whose table is freed
        // only after every CPU in its cpumask has run this same reload, so it
        // is still mapped here. The entry count is the count that table was
        // allocated with, published as one unit with the base.
        unsafe { hal_x86_64::ldt::load(cpu, view.base, view.nr_entries, view.generation); }
    } else {
        // SAFETY: clearing LDTR is always defined; the incoming context has
        // no LDT and therefore no selector that could name one.
        unsafe { hal_x86_64::ldt::clear(cpu); }
    }
    // The reference refreshes DS/ES after a table change so a segment
    // register still holding an LDT selector picks up the new descriptor
    // rather than the cached one it loaded from the old table.
    // SAFETY: reloads only segment registers that already hold an LDT
    // selector, from the table just installed at CPL 0.
    unsafe { hal_x86_64::ldt::refresh_segments(); }
}

/// This CPU's logical index, clamped exactly as the switch path clamps it so
/// the LDT slot a CPU programs is the slot it later reads back.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn cpu_index() -> usize {
    use hal::CpuOps;
    (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1)
}
