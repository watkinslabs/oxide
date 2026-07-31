// mlock-family VMA transitions (Linux `apply_vma_lock_flags` /
// `apply_mlockall_flags` / `mlock_fixup`). The VMA-flag half of mlock(2),
// mlock2(2), munlock(2), mlockall(2) and munlockall(2) lives here because VMA
// state is VMM-owned; the syscall shim only rounds arguments, runs the
// RLIMIT_MEMLOCK ladder and populates what this reports back (docs/53).

use alloc::vec::Vec;

use hal::UserVirtAddr;

use crate::vma::{Vma, VmaBacking, VmaFlags};
use crate::Error;

use super::AddressSpace;

/// One VMA subrange that ended the transition holding `VM_LOCKED`. The caller
/// prefaults each range whose `onfault` is false; an `onfault` range is left to
/// pin its pages as they arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockedSpan {
    pub start:   UserVirtAddr,
    pub len:     usize,
    pub onfault: bool,
}

/// Outcome of an mlock-family VMA walk. Linux applies the flag change VMA by
/// VMA and stops at the first hole WITHOUT undoing the VMAs it already
/// changed, so a partially-applied range plus an error is a legitimate — and
/// observable — result: the caller reports the errno while the earlier VMAs
/// stay locked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MlockOutcome {
    pub spans: Vec<LockedSpan>,
    pub error: Option<Error>,
}

/// Linux `vma_supports_mlock`: `VM_SPECIAL` mappings (raw PFN / device ranges)
/// never take `VM_LOCKED` and are silently skipped rather than rejected, so an
/// `mlock()` spanning a framebuffer mapping still succeeds for the rest.
/// # C: O(1)
fn supports_mlock(vma: &Vma) -> bool {
    !matches!(vma.backing, VmaBacking::PhysRange { .. } | VmaBacking::Special)
}

impl AddressSpace {
    /// Linux `apply_vma_lock_flags(start, len, flags)`: replace `VM_LOCKED_MASK`
    /// with `add` across `[start, start+len)`, splitting VMAs at the range
    /// boundaries and merging back where the flags now agree.
    ///
    /// `add` must be a subset of [`VmaFlags::LOCKED_MASK`]; `VmaFlags::empty()`
    /// is the munlock/munlockall direction. The range must already be
    /// page-aligned — the syscall shim owns the rounding, exactly as Linux
    /// asserts here rather than re-rounding.
    ///
    /// A hole anywhere in the range is `NoMem`, reported only AFTER the VMAs
    /// preceding the hole have been changed.
    /// # C: O(K log N)
    pub fn apply_vma_lock_flags(&self, start: UserVirtAddr, len: usize, add: VmaFlags)
        -> MlockOutcome
    {
        let mut out = MlockOutcome::default();
        let s = start.as_u64();
        let Some(end) = s.checked_add(len as u64) else {
            out.error = Some(Error::Inval);
            return out;
        };
        if end == s { return out; }
        // Snapshot first: the walk mutates the tree, which would invalidate a
        // live iterator, and the snapshot is the same VMA order Linux walks.
        let vmas = self.snapshot_vmas();
        let mut tmp = s;
        for vma in vmas.iter().filter(|v| v.end.as_u64() > s && v.start.as_u64() < end) {
            if vma.start.as_u64() > tmp { out.error = Some(Error::NoMem); return out; }
            let seg_s = core::cmp::max(s, vma.start.as_u64());
            let seg_e = core::cmp::min(end, vma.end.as_u64());
            tmp = vma.end.as_u64();
            if !supports_mlock(vma) { continue; }
            let newflags = (vma.flags & !VmaFlags::LOCKED_MASK) | add;
            if newflags != vma.flags {
                let (Some(ss), Some(_)) = (UserVirtAddr::new(seg_s), UserVirtAddr::new(seg_e)) else { continue };
                self.update_flags_range(ss, (seg_e - seg_s) as usize,
                                        add, VmaFlags::LOCKED_MASK & !add);
            }
            if add.contains(VmaFlags::LOCKED) {
                if let Some(ss) = UserVirtAddr::new(seg_s) {
                    out.spans.push(LockedSpan {
                        start: ss, len: (seg_e - seg_s) as usize,
                        onfault: add.contains(VmaFlags::LOCKONFAULT),
                    });
                }
            }
        }
        if tmp < end { out.error = Some(Error::NoMem); }
        out
    }

    /// Linux `apply_mlockall_flags`: reset `mm->def_flags`' lock bits to the
    /// requested MCL_FUTURE policy — unconditionally, so an `mlockall` without
    /// `MCL_FUTURE` CLEARS a policy an earlier call installed — then, for
    /// `MCL_CURRENT`, drive every VMA to the same lock state.
    ///
    /// `add` is `VmaFlags::empty()` for munlockall(2), which is exactly Linux
    /// calling this with flags `0`. Per-VMA failures are ignored (there is no
    /// hole to trip over when the walk IS the VMA list), matching mlockall's
    /// unconditional success once admission passed.
    /// # C: O(N log N)
    pub fn apply_mlockall_flags(&self, future: bool, current: bool, onfault: bool)
        -> Vec<LockedSpan>
    {
        self.set_mlock_future(future, onfault);
        if !current { return Vec::new(); }
        let add = if onfault { VmaFlags::LOCKED_MASK } else { VmaFlags::LOCKED };
        let mut spans = Vec::new();
        for vma in self.snapshot_vmas() {
            if !supports_mlock(&vma) { continue; }
            let len = (vma.end.as_u64() - vma.start.as_u64()) as usize;
            if (vma.flags & VmaFlags::LOCKED_MASK) != add {
                self.update_flags_range(vma.start, len, add, VmaFlags::LOCKED_MASK & !add);
            }
            spans.push(LockedSpan { start: vma.start, len, onfault });
        }
        spans
    }

    /// munlockall(2) = `apply_mlockall_flags(0)`: drop the future policy and
    /// clear `VM_LOCKED_MASK` from every VMA. # C: O(N log N)
    pub fn munlock_all(&self) -> Vec<LockedSpan> {
        self.set_mlock_future(false, false);
        let mut cleared = Vec::new();
        for vma in self.snapshot_vmas() {
            let len = (vma.end.as_u64() - vma.start.as_u64()) as usize;
            if vma.flags.intersects(VmaFlags::LOCKED_MASK) {
                self.update_flags_range(vma.start, len, VmaFlags::empty(), VmaFlags::LOCKED_MASK);
                cleared.push(LockedSpan { start: vma.start, len, onfault: false });
            }
        }
        cleared
    }

    /// Total mapped bytes (Linux `mm->total_vm` in bytes), the quantity
    /// `mlockall(MCL_CURRENT)` compares against RLIMIT_MEMLOCK — the whole
    /// address space is about to be locked, so the whole address space is what
    /// gets charged. # C: O(N)
    pub fn total_mapped_bytes(&self) -> u64 {
        self.vmas.read().iter()
            .map(|v| v.end.as_u64() - v.start.as_u64())
            .fold(0u64, |a, b| a.saturating_add(b))
    }
}
