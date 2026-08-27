use super::{pt_walker, Nanos, PageFlags, Pa, PageSize, Va};

// ---------------------------------------------------------------------------
// Context (14§4)
// ---------------------------------------------------------------------------

/// Per-task saved register set; the unit `switch` operates on.
///
/// # C: O(1)
/// # Ctx: kernel internal
///
/// All trait methods are unsafe-by-construction (raw pointers, asm). See
/// `14§4` for the SAFETY contract.
pub trait Context: Sized {
    /// # C: O(1)
    fn new_kernel(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self;

    /// Build a kernel-thread context whose saved stack carries a synthetic
    /// IRQ frame (saved scratch GPs + vec/err pad + iretq/eret frame), with
    /// `Context.{rsp,sp}` pointing at a saved RIP/LR equal to the per-arch
    /// `oxide_irq_resume_user` resume label. Lets the IRQ epilogue of one
    /// task `Context::switch` directly into a fresh task and `iretq`/`eret`
    /// from there. Frame layout pinned in `14§5.6`/`14§6.5`.
    /// # C: O(1)
    fn new_kernel_with_irq_frame(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self;

    /// # C: O(1)
    fn new_user(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self;

    /// # SAFETY: `prev` and `next` reference valid `Context` records, `next`'s
    /// saved stack is a valid kernel stack with valid return frame, preempt
    /// disabled, runqueue lock held by caller (released by next thread
    /// post-switch). See 14§4.
    /// # C: O(1)
    /// # Ctx: process|irq-return path; preempt-off
    unsafe fn switch(prev: *mut Self, next: *const Self);
}

// ---------------------------------------------------------------------------
// MmuOps (20§5 / 21§5)
// ---------------------------------------------------------------------------

/// Local `kassert!` per `07§5` — bridges to `crates/err`'s real
/// implementation once that crate ships per `38`. Form: `kassert!(cond,
/// "literal")` only; no `panic!(fmt)` per CLAUDE.md hard rules.
/// Re-exported `#[macro_export]` so per-arch HAL crates can use it.
#[macro_export]
macro_rules! kassert {
    ($cond:expr, $msg:literal) => {{
        if !($cond) { panic!($msg); }
    }};
}


/// Page-table operations. Owns the active address space.
///
/// # C: see method-level annotations
pub trait MmuOps {
    /// Map `va -> pa` with `flags` at `size`. Returns `Some(old_pa)` iff a
    /// *different* present frame was torn down to make room (the displaced
    /// leaf the caller must `dec_ref`/`put_page` per `11§8`); `None` when the
    /// slot was empty or already mapped the SAME `pa` (a pure permission
    /// rewrite, e.g. fork's W-strip or a shmem RO→RW upgrade — no PTE-count
    /// change). F157-A1: replaces the old silent-replace that leaked the
    /// displaced frame's refcount.
    /// # SAFETY: `va` and `pa` aligned to `size`; the mapping does not alias
    /// existing kernel mappings; caller holds the relevant PT lock per 06.
    /// Displaced-frame accounting is the mm layer's responsibility
    /// (`vmm::AddressSpace` install sites); device/identity/SMP maps that
    /// never run over a PMM-tracked user frame may ignore the result.
    /// # C: O(1) for 4 KiB; O(1) for 2 MiB / 1 GiB
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa>;

    /// Tear down the mapping at `va` of `size`.
    /// # SAFETY: caller holds the relevant PT lock; `va` aligned to `size`.
    /// # C: O(1)
    unsafe fn unmap(va: Va, size: PageSize);

    /// Translate `va` to (`pa`, flags) if mapped.
    /// # C: O(1)
    fn translate(va: Va) -> Option<(Pa, PageFlags)>;

    /// Translate `va` and report the GRANULE of the leaf that resolved it.
    /// A zap loop that clears a block leaf believing it holds a 4 KiB page
    /// retires the whole block while accounting one page, so every teardown
    /// walk learns the installed size from the tables instead of assuming it.
    /// `pa` carries the in-leaf offset exactly as [`MmuOps::translate`] does.
    ///
    /// The default answers `P4K` for every present leaf, which is correct only
    /// for an implementation that installs nothing else. Every MMU whose `map`
    /// accepts `P2M`/`P1G` MUST override this — both shipped arches do, and
    /// `hal::tests::block_granule_is_reported` pins that they do not fall back
    /// to the default.
    /// # C: O(walk depth)
    fn translate_sized(va: Va) -> Option<(Pa, PageFlags, PageSize)> {
        Self::translate(va).map(|(pa, f)| (pa, f, PageSize::P4K))
    }

    /// Issue a TLB shootdown for `va` (size = single page).
    /// # SAFETY: caller ensures cross-CPU IPI delivery as needed per 22.
    /// # C: O(1) local; O(N_cpus) cross-CPU
    unsafe fn flush_va(va: Va);

    /// Flush the entire TLB on this CPU.
    /// # C: O(1) local
    fn flush_all_local();

    /// Like `map` but installs into the page-table tree rooted at
    /// `root_pa` instead of the active CR3 / TTBR0. Used by
    /// `AddressSpace::fork` per docs/11§7 to populate child page
    /// tables without temporarily activating them.
    /// Returns the displaced frame like [`MmuOps::map`] (`Some(old_pa)` iff a
    /// different present leaf was torn down). Fork populates a FRESH child
    /// root, so in practice this is always `None`; the return keeps the two
    /// installers symmetric for callers that account displaced frames.
    /// # SAFETY: caller asserts `root_pa` is a valid kernel-owned
    /// PT root frame; `va` and `pa` aligned per `size`; per-AS PT
    /// lock held.
    /// # C: O(1)
    /// # Ctx: under PT lock per `06§3.6`
    unsafe fn map_at(root_pa: u64, va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa>;

    /// Move one raw 4 KiB leaf within an explicit user root. The leaf is not
    /// decoded: present, swap, migration, and marker state all move exactly
    /// as encoded. `false` means the source is a sparse hole; the destination
    /// remains empty. Huge/block leaves are reported as `HitHugeOrBlock` so
    /// the PMM owner cannot silently turn a large mapping into base pages.
    /// # SAFETY: caller owns both ranges, holds the address-space PT lock,
    /// proves they do not overlap, and performs the required TLB invalidation.
    /// # C: O(walk depth)
    unsafe fn move_leaf_4k_at(
        _root_pa: u64, _old: Va, _new: Va,
    ) -> Result<bool, pt_walker::WalkErr> {
        Err(pt_walker::WalkErr::AllocFailed)
    }

    /// Move the native leaf covering `old` and return its granule. Sparse
    /// holes return `Ok(None)`; present, swap, migration, marker, and huge
    /// leaves retain their architecture-encoded raw entry.
    /// # SAFETY: same ownership and TLB contract as `move_leaf_4k_at`.
    unsafe fn move_leaf_at(
        _root_pa: u64, _old: Va, _new: Va,
    ) -> Result<Option<PageSize>, pt_walker::WalkErr> {
        Err(pt_walker::WalkErr::AllocFailed)
    }

    /// Split the present native leaf covering `va` into the next smaller
    /// page-table level. The PMM owner retries a move after this when the
    /// destination is not aligned to the source huge leaf.
    /// # SAFETY: caller owns the root, holds its PT lock, and invalidates the
    /// affected range after the enclosing move transaction.
    unsafe fn split_leaf_at(
        _root_pa: u64, _va: Va,
    ) -> Result<(), pt_walker::WalkErr> {
        Err(pt_walker::WalkErr::AllocFailed)
    }

    /// Read the architecture-encoded non-present swap leaf at `va` in an
    /// explicit user root.  Default is appropriate only for hosted MMU mocks
    /// that do not model swap leaves.
    /// # C: O(walk depth)
    fn swap_entry_at(_root_pa: u64, _va: Va) -> Option<pt_walker::SwapEntry> { None }

    /// Read a non-present migration marker from an explicit root.  It is
    /// deliberately distinct from [`Self::swap_entry_at`]: callers must wait
    /// and restart rather than retain/free a swap slot.
    /// # C: O(walk depth)
    fn migration_entry_at(_root_pa: u64, _va: Va) -> Option<pt_walker::MigrationEntry> { None }

    /// Read a non-present MARKER leaf from an explicit root — per-page facts
    /// that name no page and no swap slot. Deliberately distinct from the two
    /// above: a marker is inherited as-is, with no reference to retain and
    /// nothing to wait for.
    /// # C: O(walk depth)
    fn pte_marker_at(_root_pa: u64, _va: Va) -> Option<pt_walker::PteMarker> { None }

    /// Whether the NON-PRESENT leaf at `va` carries userfaultfd write-protect
    /// state — the barrier riding on a reference to a page that is elsewhere.
    /// Asked separately from the entry's identity because the two are separate
    /// facts: the slot or token says WHERE the page is, this says whether a
    /// monitor is still watching writes to it.
    /// # C: O(walk depth)
    fn nonpresent_uffd_wp_at(_root_pa: u64, _va: Va) -> bool { false }

    /// Install a non-present marker leaf in a fresh child root, at an address
    /// that holds nothing.
    /// # SAFETY: caller owns `root_pa` and holds its page-table lock.
    /// # C: O(walk depth)
    unsafe fn map_marker_at(
        _root_pa: u64, _va: Va, _m: pt_walker::PteMarker,
    ) -> Result<(), pt_walker::WalkErr> { Err(pt_walker::WalkErr::AllocFailed) }

    /// Install a non-present swap leaf in a fresh child root.  The operation
    /// never overwrites a present or another non-present leaf, so the caller
    /// can roll back the slot reference on any error.
    ///
    /// `uffd_wp` arms the child's copy of the barrier. It is decided by the
    /// caller rather than copied from the parent leaf because a child inherits
    /// a monitor's protection only when it inherits the monitor.
    /// # SAFETY: caller owns `root_pa` and holds its page-table lock.
    /// # C: O(walk depth)
    unsafe fn map_swap_at(
        _root_pa: u64, _va: Va, _entry: pt_walker::SwapEntry, _uffd_wp: bool,
    ) -> Result<(), pt_walker::WalkErr> { Err(pt_walker::WalkErr::AllocFailed) }

    /// Remove this exact non-present swap leaf from an unpublished child root.
    /// Used only by fork rollback after its corresponding slot reference was
    /// released.
    /// # SAFETY: caller owns `root_pa` and holds its page-table lock.
    /// # C: O(walk depth)
    unsafe fn clear_swap_at(
        _root_pa: u64, _va: Va, _entry: pt_walker::SwapEntry,
    ) -> bool { false }

    /// Install `root_pa` as this CPU's active user-half page-table root.
    ///
    /// On x86_64 writes `CR3` (single tree covering both halves; the
    /// caller is expected to have populated kernel-half entries from
    /// the kernel master PML4 before calling). On aarch64 writes
    /// `TTBR0_EL1` and invalidates EL1 TLB; `TTBR1_EL1` (kernel half)
    /// is untouched. Per `13§8` (`schedule()` AS-swap).
    ///
    /// # SAFETY: caller is the kernel scheduler or boot path; `root_pa`
    /// references a valid 4 KiB-aligned root frame whose kernel-half
    /// mappings are coherent with the active kernel PT (else the very
    /// next instruction may fault). Single-CPU pre-SMP; preempt-off.
    /// # C: O(1)
    /// # Ctx: schedule path; preempt-off
    unsafe fn activate(root_pa: u64);
}

// ---------------------------------------------------------------------------
// CpuOps (20§* / 21§*)
// ---------------------------------------------------------------------------

/// Per-CPU primitives.
pub trait CpuOps {
    /// Index of the current CPU.
    /// # C: O(1)
    fn current_cpu() -> u32;

    /// Number of online CPUs.
    /// # C: O(1)
    fn cpu_count() -> u32;

    /// Halt this CPU until the next interrupt, WITHOUT touching the interrupt
    /// mask. Only for a park nothing is expected to return from — the panic
    /// stop and the offline park. The idle loop must use [`CpuOps::safe_halt`]:
    /// the idle path is reached with interrupts masked, and halting a core in
    /// that state parks it where no interrupt can reach it.
    /// # C: O(1)
    /// # Ctx: panic / offline park
    fn halt();

    /// Enable interrupts and halt, inseparably — Linux `raw_safe_halt`.
    ///
    /// The two halves cannot be separate statements. Enabling first leaves a
    /// window in which the wakeup arrives, is handled, and the core then halts
    /// with nothing left to wake it; halting first parks a core whose mask is
    /// still closed. Each architecture has one instruction pair that closes the
    /// window, and this is the only place either is written.
    /// # C: O(1)
    /// # Ctx: idle path, entered with interrupts masked
    /// # Sleeps: parks until an interrupt
    fn safe_halt();

    /// Memory barrier sufficient to order MMIO writes per 06.
    /// # C: O(1)
    fn mmio_barrier();

    /// Set per-CPU base register (`GS_BASE` on x86, `TPIDR_EL1` on arm).
    /// # SAFETY: `base` points to a valid per-CPU area for this CPU.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8);

    /// ELF `AT_HWCAP` advertised to userspace in the initial auxv (Linux
    /// `ELF_HWCAP`). Userspace (musl, OpenSSL) selects SIMD/crypto code
    /// paths from it. Only bits for features the CPU is GUARANTEED to have
    /// are set, so a program can never pick an instruction the hardware
    /// lacks (→ SIGILL). # C: O(1)
    fn cpu_hwcap() -> u64;

    /// ELF `AT_HWCAP2` advertised to userspace in the initial auxiliary
    /// vector. A capability belongs here only when the kernel enabled the
    /// matching userspace ABI. # C: O(1)
    fn cpu_hwcap2() -> u64;

    /// ELF `AT_MINSIGSTKSZ` (Linux `get_sigframe_size()` on x86_64,
    /// `signal_minsigstksz` on arm64): bytes of stack ONE signal delivery
    /// needs, worst case. Dynamic because the frame carries the CPU's
    /// FPU/SIMD save area, whose size varies with XCR0 — which is exactly why
    /// Linux exports it in the auxv instead of leaving userspace with the
    /// frozen `MINSIGSTKSZ`. glibc 2.34+ answers `sysconf(_SC_MINSIGSTKSZ)`
    /// from it and sizes every `sigaltstack(2)` accordingly.
    /// # C: O(1)
    fn cpu_min_sigstksz() -> u64;
}

// ---------------------------------------------------------------------------
// MachineOps (32§4)
// ---------------------------------------------------------------------------

/// Irreversible machine-terminal primitives.
///
/// The kernel power owner supplies policy and firmware/reset callbacks; this
/// trait owns only the architecture instructions and calling convention at
/// the final machine boundary. Keeping that split means no kernel subsystem
/// carries an architecture-selected `asm!` block of its own.
pub trait MachineOps {
    /// Mask local interrupts before stopping peer CPUs.
    /// # SAFETY: caller owns an irreversible machine transition.
    unsafe fn mask_local_irqs();

    /// Park this CPU forever.
    /// # SAFETY: caller owns an irreversible machine transition.
    unsafe fn halt() -> !;

    /// Invoke the architecture reset endpoint, or the supplied policy reset
    /// ladder where the architecture has one.
    /// # SAFETY: caller owns an irreversible machine transition; `reset` is
    /// the kernel's validated reset callback.
    unsafe fn restart(reset: unsafe fn() -> !) -> !;

    /// Invoke the architecture power-off endpoint, or the supplied firmware
    /// callback where the platform's power controller is kernel-owned.
    /// # SAFETY: caller owns an irreversible machine transition; `power_off`
    /// is the kernel's validated firmware callback.
    unsafe fn power_off(power_off: fn()) -> !;
}

// ---------------------------------------------------------------------------
// IrqOps (20§11 / 21§11)
// ---------------------------------------------------------------------------

/// Interrupt controller (APIC on x86_64; GICv3 on aarch64 per 21).
pub trait IrqOps {
    /// # C: O(1)
    fn enable_line(line: u32);

    /// # C: O(1)
    fn disable_line(line: u32);

    /// End-of-interrupt acknowledge.
    /// # C: O(1)
    fn eoi(line: u32);

    /// Set CPU affinity for `line`.
    /// # SAFETY: `mask` references valid CPU set; controller-specific routing
    /// table reprogrammed atomically per 22.
    /// # C: O(1)
    unsafe fn set_affinity(line: u32, mask: u64);

    /// Allocate an MSI/MSI-X vector + program address/data per 20§11.
    /// Returns `(addr, data)` to write into the device's MSI table.
    /// # C: O(1) amortized; allocates vector range via 22 vector allocator
    fn alloc_msi() -> (u64, u32);

    /// Send IPI to `target_cpu` with `vector`.
    /// # SAFETY: `vector` is a valid IPI vector per 22 vector map.
    /// # C: O(1)
    unsafe fn send_ipi(target_cpu: u32, vector: u8);

    /// Acknowledge a spurious IRQ; returns `Some(vec)` if a real one is
    /// pending in service register.
    /// # C: O(1)
    fn ack() -> Option<u8>;
}

// ---------------------------------------------------------------------------
// TimerOps (20§12 / 21§12)
// ---------------------------------------------------------------------------

/// Per-CPU monotonic timer (TSC-deadline on x86_64; CNTV on aarch64).
pub trait TimerOps {
    /// Monotonic timestamp from boot.
    /// # C: O(1) (single TSC/CNTV read)
    fn monotonic_ns() -> Nanos;

    /// Arm the local one-shot for an absolute deadline in the timer's
    /// monotonic-nanosecond domain. Returns false when the device cannot be
    /// armed, so callers do not publish a scheduler deadline that hardware
    /// will never deliver.
    /// # SAFETY: caller manages the LVT/CNTV registers per 23.
    /// # C: O(1)
    unsafe fn set_oneshot(deadline_ns: Nanos) -> bool;

    /// Counter frequency in kHz (cached at boot).
    /// # C: O(1)
    fn freq_khz() -> u32;
}
