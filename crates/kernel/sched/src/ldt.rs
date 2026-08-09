// Linux `switch_ldt` / `load_mm_ldt` / `flush_ldt` equivalents: the point
// where a per-mm Local Descriptor Table becomes the LDTR the CPU uses.
//
// The state lives on the address space (`vmm::ldt`) and the descriptor
// programming lives in the HAL (`hal_x86_64::ldt`); this module is the only
// place that joins them, so there is one answer to "when does LDTR change"
// rather than one per call site.
//
// Every entry point is gated on `vmm::any_ldt_in_use()`, a global that no
// system sets unless something actually called `modify_ldt`. On the
// overwhelming majority of machines that makes each of these one relaxed
// atomic load in the switch path and nothing more.
//
// aarch64 has no LDT and no `modify_ldt` slot; everything here compiles to a
// no-op there rather than being absent, so callers in shared scheduler code
// need no `cfg` of their own.

use vmm::address_space::AddressSpace;

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
    let next_view = next.map(|m| m.ldt_view()).unwrap_or(vmm::LdtView::NONE);
    if !prev_loaded && !next_view.is_loaded() { return; }
    apply(next_view);
}

/// Point this CPU's LDTR at `mm`'s table now, skipping the hardware writes
/// when it already holds that exact table generation.
///
/// This is what makes an entry usable on the thread that installed it before
/// it ever reschedules, and what a sibling thread's return-to-user runs to
/// pick up an entry a peer installed.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub fn reload_current(mm: &AddressSpace) {
    if !vmm::any_ldt_in_use() { return; }
    apply(mm.ldt_view());
}

/// Drop this CPU's LDT. Used where an address space is replaced outright
/// (`execve`) or borrowed by a kernel thread: the table the LDTR still names
/// is about to be freed with the old mm.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub fn clear_local() {
    if !vmm::any_ldt_in_use() { return; }
    apply(vmm::LdtView::NONE);
}

/// True when this CPU's LDTR is behind `mm` and a return to user mode would
/// run with descriptors a peer thread has already replaced.
///
/// The reference closes this window with an IPI to every CPU in the mm's
/// cpumask. This port has no general cross-CPU call, so the peer notices at
/// its next return to user mode instead — see `scratch/known_issues.md`.
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

/// Program LDTR from a view. The one place `lldt` is reached from.
///
/// Runs with interrupts masked. The GDT slot written and the `lldt` that
/// consumes it must belong to the SAME processor: a migration between the two
/// would program one CPU's descriptor and load another's, which is a stale
/// descriptor table pointer rather than a missed update.
#[allow(unused_variables)]
fn apply(view: vmm::LdtView) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        use sync::IrqGate;
        // SAFETY: paired 1:1 with the `restore` below; the section contains no
        // sleeping call and no lock acquisition.
        let flags = unsafe { hal_x86_64::X86IrqGate::save_disable() };
        apply_locked(view);
        // SAFETY: restores the interrupt state saved immediately above.
        unsafe { hal_x86_64::X86IrqGate::restore(flags); }
    }
}

/// The descriptor write and `lldt`, with migration already excluded.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn apply_locked(view: vmm::LdtView) {
    {
        let cpu = cpu_index();
        let want = if view.is_loaded() { hal_x86_64::ldt::load_token(view.generation) } else { 0 };
        if hal_x86_64::ldt::current_token(cpu) == want { return; }
        if view.is_loaded() {
            // SAFETY: `view` came from a live `AddressSpace` whose table is
            // owned by that mm and freed only when the mm drops — which
            // cannot happen while this CPU is running or lazy-TLB on it. The
            // entry count is bounded by the table size by construction.
            unsafe { hal_x86_64::ldt::load(cpu, view.base, view.nr_entries, view.generation); }
        } else {
            // SAFETY: clearing LDTR is always defined; the incoming context
            // has no LDT and therefore no selector that could name one.
            unsafe { hal_x86_64::ldt::clear(cpu); }
        }
    }
}

/// This CPU's logical index, clamped exactly as the switch path clamps it so
/// the LDT slot a CPU programs is the slot it later reads back.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn cpu_index() -> usize {
    use hal::CpuOps;
    (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1)
}
