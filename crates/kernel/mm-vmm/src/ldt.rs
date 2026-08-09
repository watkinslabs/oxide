// Per-`mm` Local Descriptor Table (Linux `mm_context_t::ldt`).
//
// The table belongs to the ADDRESS SPACE, not the task: `CLONE_VM` threads
// share one `AddressSpace` and therefore one LDT, which is what makes an
// entry installed by one thread visible to its siblings. `fork` gives the
// child a COPY (`dup`), `execve` builds a fresh `AddressSpace` and so starts
// with no table at all, and teardown is the `Box` dropping with the mm.
//
// Allocation strategy, and where it deviates from the reference:
//
// The reference sizes the allocation to the highest entry in use and swaps
// the whole table on every grow, freeing the old one only after an IPI has
// made every CPU running the mm reload LDTR. This port has no general
// cross-CPU call — the only IPI is the TLB shootdown's single-slot vector —
// so a swap-and-free would leave a sibling CPU's LDTR pointing at freed
// memory, which is a descriptor-table use-after-free and strictly worse than
// the memory it saves. Instead the table is allocated ONCE at full size and
// entries are written in place. The base address is then immutable for the
// life of the mm, an 8-byte aligned descriptor store is atomic against the
// CPU's own descriptor read, and nothing is ever freed while loaded.
//
// Cost: 64 KiB per address space that ever calls `modify_ldt`, against the
// reference's 4 KiB for a small table. Nothing else observes the difference —
// `nr_entries` still tracks what the process claimed, so read-back size and
// the LDTR limit are unchanged.

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
    /// return-to-user can tell whether the table grew under it.
    pub generation: u64,
}

impl LdtView {
    /// The empty view — a CPU holding this has no LDT loaded.
    pub const NONE: LdtView = LdtView { base: 0, nr_entries: 0, generation: 0 };

    /// True when there is a table to load.
    /// # C: O(1)
    pub fn is_loaded(self) -> bool { self.nr_entries != 0 }
}

/// Per-mm LDT. Zero-sized in effect until the first write: the 64 KiB
/// backing allocation is made on demand.
pub struct LdtState {
    /// Owns the backing table. Taken only to publish an entry; never held
    /// across an allocation.
    table: Spinlock<Option<Box<[u64]>>, AddressSpaceClass>,
    /// Kernel VA of the table's first entry, 0 while unallocated. Immutable
    /// once non-zero, which is what lets the switch path read it without a
    /// lock.
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

impl LdtState {
    /// A process that has not called `modify_ldt`.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            table: Spinlock::new(None),
            base: AtomicU64::new(0),
            nr_entries: AtomicU32::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// Lock-free snapshot for the context-switch and return-to-user paths.
    ///
    /// Safe without the lock because the base is immutable once published and
    /// the table outlives every CPU that can be running this mm: it is freed
    /// only when the `AddressSpace` itself drops, at which point no CPU holds
    /// the mm.
    /// # C: O(1)
    pub fn view(&self) -> LdtView {
        let nr = self.nr_entries.load(Ordering::Acquire);
        if nr == 0 { return LdtView::NONE; }
        LdtView {
            base: self.base.load(Ordering::Acquire),
            nr_entries: nr,
            generation: self.generation.load(Ordering::Acquire),
        }
    }

    /// Entries the process has claimed — the size `modify_ldt(0, …)` reads
    /// back.
    /// # C: O(1)
    pub fn nr_entries(&self) -> u32 { self.nr_entries.load(Ordering::Acquire) }

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

    /// Install one packed descriptor at `entry`, growing the claimed entry
    /// count to cover it.
    ///
    /// The store itself is an aligned 8-byte write into a table a sibling CPU
    /// may have loaded. That is deliberate and is the reason the table is
    /// never reallocated: the CPU's descriptor read of an aligned quadword
    /// cannot tear, so a sibling sees either the old descriptor or the new
    /// one, never a mixture.
    /// # C: O(1) amortised; O(table) on the first call
    /// # Lk: AddressSpace acquired
    pub fn install(&self, entry: u32, desc: u64) -> Result<(), LdtError> {
        if entry >= LDT_ENTRIES { return Err(LdtError::Range); }
        // Allocate outside the lock; the common case is that the table
        // already exists and this never runs.
        let mut fresh = if self.base.load(Ordering::Acquire) == 0 {
            let mut v = vec::Vec::new();
            v.try_reserve_exact(LDT_ENTRIES as usize).map_err(|_| LdtError::NoMem)?;
            v.resize(LDT_ENTRIES as usize, 0u64);
            Some(v.into_boxed_slice())
        } else {
            None
        };

        let mut g = self.table.lock();
        if g.is_none() {
            let t = fresh.take().ok_or(LdtError::NoMem)?;
            self.base.store(t.as_ptr() as u64, Ordering::Release);
            *g = Some(t);
        }
        let t = g.as_mut().ok_or(LdtError::NoMem)?;
        t[entry as usize] = desc;
        // Publish the descriptor before the count that makes it reachable:
        // a CPU that sees the larger limit must already see the entry.
        let want = entry + 1;
        if self.nr_entries.load(Ordering::Relaxed) < want {
            self.nr_entries.store(want, Ordering::Release);
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        drop(g);
        ANY_LDT_IN_USE.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Build the child's LDT for `fork`: a private copy, not a share. Two
    /// address spaces never share a table, so a child rewriting an entry can
    /// never alter its parent's descriptors.
    /// # C: O(table) when the parent has an LDT, O(1) otherwise
    pub fn dup(&self) -> Result<Self, LdtError> {
        let child = Self::new();
        let nr = self.nr_entries.load(Ordering::Acquire);
        if nr == 0 { return Ok(child); }
        let mut v = vec::Vec::new();
        v.try_reserve_exact(LDT_ENTRIES as usize).map_err(|_| LdtError::NoMem)?;
        v.resize(LDT_ENTRIES as usize, 0u64);
        let mut t = v.into_boxed_slice();
        {
            let g = self.table.lock();
            if let Some(src) = g.as_ref() { t.copy_from_slice(src); }
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
