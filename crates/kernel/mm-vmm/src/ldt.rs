// Per-`mm` Local Descriptor Table (Linux `mm_context_t::ldt`).
//
// The table belongs to the ADDRESS SPACE, not the task: `CLONE_VM` threads
// share one `AddressSpace` and therefore one LDT, which is what makes an
// entry installed by one thread visible to its siblings. `fork` gives the
// child a COPY (`dup`), `execve` builds a fresh `AddressSpace` and so starts
// with no table at all, and teardown is the `Box` dropping with the mm.
//
// ALLOCATION — sized to the highest entry in use, grown by swapping the
// whole table, exactly as the reference does. An install allocates a table
// large enough for the new highest entry, copies the old descriptors in,
// writes the new one, and publishes the pair (base, nr_entries) atomically.
// The OLD table is NOT freed here: `install` hands it back in an `LdtSwap`
// that the caller may only release once every CPU running this mm has
// reloaded LDTR. Freeing before that point leaves a sibling CPU's LDTR
// pointing at recycled memory — a descriptor-table use-after-free — which is
// why the swap and the cross-CPU call landed together.
//
// PUBLICATION — `base` and `nr_entries` must be read as a PAIR. A reader
// that pairs the new base with the old count would program a limit that does
// not match the table, so the two are published under a sequence counter and
// `view()` retries across a concurrent install. The reader must additionally
// hold interrupts off from the `view()` until the `lldt` that consumes it
// (see `sched::ldt`): otherwise a converge IPI can land between them and the
// stale base would be loaded AFTER the sender concluded everyone had
// converged.

use alloc::boxed::Box;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{AddressSpace as AddressSpaceClass, Spinlock};

/// Architectural maximum entries: the selector index field is 13 bits.
pub const LDT_ENTRIES: u32 = 8192;
/// Bytes per entry — one 8-byte segment descriptor.
pub const LDT_ENTRY_SIZE: u32 = 8;
/// Bytes in the full table.
pub const LDT_TABLE_BYTES: u32 = LDT_ENTRIES * LDT_ENTRY_SIZE;

/// Set the first time any address space installs an LDT, never cleared.
///
/// Every return-to-user and every context switch consults this before doing
/// any LDT work, so a system where nothing uses `modify_ldt` — which is
/// nearly all of them — pays one relaxed load and nothing else.
static ANY_LDT_IN_USE: AtomicBool = AtomicBool::new(false);

/// True once some address space has an LDT. The gate on every hot path.
/// # C: O(1)
pub fn any_ldt_in_use() -> bool { ANY_LDT_IN_USE.load(Ordering::Relaxed) }

/// What a CPU needs to point LDTR at this mm's table: base address and the
/// entry count the limit is computed from. `nr_entries == 0` means "no
/// table"; the CPU is told to load a null LDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdtView {
    pub base: u64,
    pub nr_entries: u32,
    /// Bumped on every install. A CPU records the value it loaded so a later
    /// return-to-user can tell whether the table changed under it.
    pub generation: u64,
}

impl LdtView {
    /// The empty view — a CPU holding this has no LDT loaded.
    pub const NONE: LdtView = LdtView { base: 0, nr_entries: 0, generation: 0 };

    /// True when there is a table to load.
    /// # C: O(1)
    pub fn is_loaded(self) -> bool { self.nr_entries != 0 }
}

/// The old table an install displaced, plus the view that replaced it.
///
/// Freeing the old table is the caller's job and its ORDERING is the whole
/// contract: not until every CPU in the mm's `cpumask` has reloaded LDTR.
/// `#[must_use]` because dropping this value on the floor at the wrong point
/// is precisely the use-after-free the type exists to prevent — the drop is
/// the free.
#[must_use = "the displaced table may only be freed after every CPU running this mm has reloaded LDTR"]
pub struct LdtSwap {
    old: Option<Box<[u64]>>,
    view: LdtView,
}

impl LdtSwap {
    /// The view now published — what a converging CPU will load.
    /// # C: O(1)
    pub fn view(&self) -> LdtView { self.view }

    /// True when this install actually displaced a table. A first install
    /// has nothing to free and needs no converge for SAFETY (only for
    /// visibility).
    /// # C: O(1)
    pub fn displaced_a_table(&self) -> bool { self.old.is_some() }

    /// Free the displaced table. Call only after the cross-CPU reload has
    /// completed on every target.
    /// # C: O(1)
    pub fn release_after_converge(self) { drop(self.old); }
}

/// Per-mm LDT. Zero-sized in effect until the first write.
pub struct LdtState {
    /// Owns the backing table. Taken only across a swap; never held across
    /// an allocation and never held across the cross-CPU converge.
    table: Spinlock<Option<Box<[u64]>>, AddressSpaceClass>,
    /// Publication sequence: even = stable, odd = an install is mid-publish.
    seq: AtomicU64,
    /// Kernel VA of the table's first entry, 0 while unallocated.
    base: AtomicU64,
    /// Entries the process has claimed. Only ever grows.
    nr_entries: AtomicU32,
    /// Install counter; see `LdtView::generation`.
    generation: AtomicU64,
}

/// Why an entry could not be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdtError {
    /// The backing table could not be allocated.
    NoMem,
    /// Entry index outside the architectural table.
    Range,
}

impl Default for LdtState {
    fn default() -> Self { Self::new() }
}

/// Allocate a zeroed table of `n` descriptors without aborting on OOM.
fn alloc_table(n: usize) -> Result<Box<[u64]>, LdtError> {
    let mut v = vec::Vec::new();
    v.try_reserve_exact(n).map_err(|_| LdtError::NoMem)?;
    v.resize(n, 0u64);
    Ok(v.into_boxed_slice())
}

impl LdtState {
    /// A process that has not called `modify_ldt`.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            table: Spinlock::new(None),
            seq: AtomicU64::new(0),
            base: AtomicU64::new(0),
            nr_entries: AtomicU32::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// Lock-free snapshot for the context-switch and return-to-user paths.
    ///
    /// Retries while an install is mid-publish, so `base` and `nr_entries`
    /// are always the pair one install wrote. Lock-free rather than
    /// lock-taking because it runs from the switch path with interrupts
    /// masked, where blocking on the install's spinlock would deadlock
    /// against an installer waiting for this CPU to converge.
    /// # C: O(1) uncontended
    pub fn view(&self) -> LdtView {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 { sync::spin_relax::relax(); continue; }
            let nr = self.nr_entries.load(Ordering::Acquire);
            let base = self.base.load(Ordering::Acquire);
            let generation = self.generation.load(Ordering::Acquire);
            if self.seq.load(Ordering::Acquire) != s1 { sync::spin_relax::relax(); continue; }
            if nr == 0 { return LdtView::NONE; }
            return LdtView { base, nr_entries: nr, generation };
        }
    }

    /// Entries the process has claimed — the size `modify_ldt(0, …)` reads
    /// back.
    /// # C: O(1)
    pub fn nr_entries(&self) -> u32 { self.nr_entries.load(Ordering::Acquire) }

    /// Bytes the live table occupies. The allocation is sized to this, so it
    /// is also what a full read-back copies.
    /// # C: O(1)
    pub fn table_bytes(&self) -> u64 { self.nr_entries() as u64 * LDT_ENTRY_SIZE as u64 }

    /// Copy `dst.len()` bytes of the table out, starting at entry 0. Bytes
    /// beyond the live table are left untouched — the caller has already
    /// sized `dst` to `nr_entries * 8`.
    /// # C: O(dst.len())
    pub fn read_bytes(&self, dst: &mut [u8]) {
        let g = self.table.lock();
        let Some(t) = g.as_ref() else { return; };
        // SAFETY: `t` is a live `[u64]` allocation held under this lock; the
        // byte view aliases exactly its own storage and both are readable for
        // the whole slice.
        let src = unsafe {
            core::slice::from_raw_parts(t.as_ptr() as *const u8, t.len() * LDT_ENTRY_SIZE as usize)
        };
        let n = dst.len().min(src.len());
        dst[..n].copy_from_slice(&src[..n]);
    }

    /// Install one packed descriptor at `entry`, growing the table to cover
    /// it and returning the table the grow displaced.
    ///
    /// The reference reallocates on every write rather than patching in
    /// place, and so does this: a table whose base never moves would have to
    /// be allocated at the architectural maximum up front, and an in-place
    /// patch of a descriptor a sibling CPU has loaded relies on the CPU's
    /// descriptor read being an atomic aligned quadword — true, but it
    /// leaves the sibling running the OLD descriptor for an unbounded time,
    /// which is the visibility defect the converge exists to close.
    /// # C: O(new table)
    /// # Lk: AddressSpace acquired (never held across the allocation)
    pub fn install(&self, entry: u32, desc: u64) -> Result<LdtSwap, LdtError> {
        if entry >= LDT_ENTRIES { return Err(LdtError::Range); }
        let mut want = (entry + 1).max(self.nr_entries.load(Ordering::Acquire)) as usize;
        loop {
            let mut fresh = alloc_table(want)?;
            let mut g = self.table.lock();
            let have = g.as_ref().map(|t| t.len()).unwrap_or(0);
            if have > fresh.len() {
                // A concurrent install grew the table past our allocation
                // while the lock was free. Retry with the size it now needs.
                drop(g);
                want = have.max(entry as usize + 1);
                continue;
            }
            if let Some(src) = g.as_ref() { fresh[..have].copy_from_slice(src); }
            fresh[entry as usize] = desc;
            let base = fresh.as_ptr() as u64;
            let nr = fresh.len() as u32;
            let generation = self.generation.load(Ordering::Relaxed).wrapping_add(1);
            // Publish base/nr/generation as one unit. `view()` refuses to
            // read between the two sequence bumps.
            self.seq.fetch_add(1, Ordering::AcqRel);
            self.base.store(base, Ordering::Release);
            self.nr_entries.store(nr, Ordering::Release);
            self.generation.store(generation, Ordering::Release);
            self.seq.fetch_add(1, Ordering::AcqRel);
            let old = g.replace(fresh);
            drop(g);
            ANY_LDT_IN_USE.store(true, Ordering::Relaxed);
            return Ok(LdtSwap { old, view: LdtView { base, nr_entries: nr, generation } });
        }
    }

    /// Build the child's LDT for `fork`: a private copy, not a share. Two
    /// address spaces never share a table, so a child rewriting an entry can
    /// never alter its parent's descriptors.
    /// # C: O(table) when the parent has an LDT, O(1) otherwise
    pub fn dup(&self) -> Result<Self, LdtError> {
        let child = Self::new();
        let nr = self.nr_entries.load(Ordering::Acquire);
        if nr == 0 { return Ok(child); }
        let mut t = alloc_table(nr as usize)?;
        {
            let g = self.table.lock();
            if let Some(src) = g.as_ref() {
                let n = src.len().min(t.len());
                t[..n].copy_from_slice(&src[..n]);
            }
        }
        child.base.store(t.as_ptr() as u64, Ordering::Release);
        *child.table.lock() = Some(t);
        child.nr_entries.store(nr, Ordering::Release);
        child.generation.store(1, Ordering::Release);
        ANY_LDT_IN_USE.store(true, Ordering::Relaxed);
        Ok(child)
    }
}

#[cfg(test)]
mod tests;
