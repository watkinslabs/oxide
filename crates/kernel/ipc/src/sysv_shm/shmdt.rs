//! `shmdt(2)` — Linux `ksys_shmdt` (`ipc/shm.c`).
//!
//! Detaching is not "unmap a page at this address". Linux searches the address
//! space for a VMA that belongs to a shm segment AND whose file offset equals
//! its distance from `shmaddr` — i.e. a VMA that is part of an attachment
//! *placed at* `shmaddr`. That anchor names the segment, the segment names the
//! attachment length, and every later fragment of the same attachment inside
//! that length is unmapped too (an attachment can have been split by
//! `mprotect`/`munmap`). No anchor means the address is not the start of an
//! attached segment: `EINVAL`, and nothing is unmapped.
//!
//! The geometry ([`plan_detach`]) is separated from the address-space walk so
//! the placement rule is exercised by hosted tests, which have no `mm`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vmm::VmaBacking;

use super::{lookup_segment_by_backing, page_align_len, release_detached, ShmSegment, PAGE_SIZE};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Identity of a `FileBacking` as a thin data pointer. `Arc::ptr_eq` on a
/// `dyn` Arc compares the vtable half too, which is not guaranteed stable
/// across codegen units; the data pointer alone is the object identity.
/// # C: O(1)
pub(super) fn backing_addr(b: &Arc<dyn vmm::FileBacking>) -> *const () {
    Arc::as_ptr(b) as *const ()
}

/// A candidate VMA reduced to the fields the placement rule needs. `seg` is
/// the shm segment identity the VMA is backed by, `None` for any VMA that is
/// not a shm attachment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct DetachVma {
    pub start: u64,
    pub end: u64,
    /// File offset of the VMA within the segment.
    pub off: u64,
    /// Segment identity; `None` when the VMA is not shm-backed.
    pub seg: Option<usize>,
}

/// What [`plan_detach`] decided: the segment being detached and the index of
/// every VMA to unmap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DetachPlan {
    pub seg: usize,
    pub victims: Vec<usize>,
}

/// Linux's `(vma->vm_start - addr)/PAGE_SIZE == vma->vm_pgoff` test, in bytes:
/// this VMA sits exactly where an attachment based at `addr` would put it.
fn placed_at(v: &DetachVma, addr: u64) -> bool {
    v.start >= addr && v.start - addr == v.off
}

/// Anchor search + fragment sweep. `span_of` yields the page-aligned size of a
/// segment, which is the extent Linux takes from the attached file's `i_size`
/// rather than from the anchor VMA (the anchor may be the surviving fragment
/// of a partially unmapped attach).
/// # C: O(N_VMAs)
pub(super) fn plan_detach(
    vmas: &[DetachVma], addr: u64, span_of: impl Fn(usize) -> Option<u64>,
) -> Option<DetachPlan> {
    let (idx, seg) = vmas.iter().enumerate()
        .find_map(|(i, v)| match v.seg {
            Some(s) if placed_at(v, addr) => Some((i, s)),
            _ => None,
        })?;
    let span = span_of(seg)?;
    let mut victims = Vec::new();
    victims.push(idx);
    for (i, v) in vmas.iter().enumerate().skip(idx + 1) {
        // Stop at the first VMA reaching past the attachment's extent —
        // everything beyond it belongs to some other mapping.
        if v.end.saturating_sub(addr) > span { break; }
        if v.seg == Some(seg) && placed_at(v, addr) { victims.push(i); }
    }
    Some(DetachPlan { seg, victims })
}

/// `shmdt(shmaddr)` — slot NR_SHMDT.
/// # C: O(N_VMAs × N_segments)
pub fn sys_shmdt(args: &syscall::SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    let addr = args.a0;
    // Linux: `if (addr & ~PAGE_MASK) return -EINVAL;`. A zero address is not
    // special-cased — it simply cannot anchor an attachment, so it falls out
    // of the scan below as EINVAL.
    if (addr & (PAGE_SIZE - 1)) != 0 { return err(Errno::Einval); }
    let cur = match sched::current() { Some(c) => c, None => return err(Errno::Einval) };
    // SAFETY: the current task's mm slot has a single mutator per `13§5` and cannot be replaced while that task executes its own shmdt, so cloning the reference observes a live address space.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return err(Errno::Einval) };

    let vmas = mm.snapshot_vmas();
    // Resolve each file-backed VMA to a segment once; `segs[i]` indexes it.
    let mut segs: Vec<Arc<ShmSegment>> = Vec::new();
    let desc: Vec<DetachVma> = vmas.iter().map(|v| {
        let (off, seg) = match &v.backing {
            VmaBacking::File { backing, off } => match lookup_segment_by_backing(backing) {
                Some(s) => {
                    let ident = backing_addr(&s.backing);
                    let at = segs.iter().position(|e| backing_addr(&e.backing) == ident)
                        .unwrap_or_else(|| { segs.push(s); segs.len() - 1 });
                    (*off, Some(at))
                }
                None => (*off, None),
            },
            _ => (0, None),
        };
        DetachVma { start: v.start.as_u64(), end: v.end.as_u64(), off, seg }
    }).collect();

    let plan = match plan_detach(&desc, addr, |s| page_align_len(segs[s].size).map(|l| l as u64)) {
        Some(p) => p, None => return err(Errno::Einval),
    };
    for i in plan.victims {
        let v = &vmas[i];
        let len = (v.end.as_u64() - v.start.as_u64()) as usize;
        if let Some(u) = UserVirtAddr::new(v.start.as_u64()) { let _ = mm.munmap(u, len); }
    }
    // Linux `shm_close`: the attachment count drops, and a segment already
    // marked SHM_DEST by IPC_RMID is destroyed once the last attach goes.
    release_detached(&segs[plan.seg]);
    0
}

#[cfg(test)]
mod tests;
