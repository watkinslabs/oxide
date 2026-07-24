//! Guard-paged kernel-stack allocator — Linux `CONFIG_VMAP_STACK` (C213).
//!
//! Every kernel thread stack is `THREAD_SIZE` (16 KiB = 4 pages, matching Linux
//! x86_64 `CONFIG_THREAD_SIZE_ORDER=2` / aarch64) mapped 4 KiB-granular in a
//! dedicated kernel VA window, with an **unmapped guard page immediately
//! below** the lowest stack byte. A stack overflow writes into the guard and
//! takes an immediate `#PF` at the offending instruction — it can no longer
//! silently scribble the adjacent heap block (the ~90% boot corruptor).
//!
//! Replaces the old scattered `vec![0u8; 16*1024].into_boxed_slice()` stacks
//! (kthread + every spawn path) — one allocator, one shape.
//!
//! `sched` cannot depend on `pmm` (pmm depends on sched), so the physical
//! frames come from a hook kmain installs from pmm. Page-table mapping uses the
//! HAL `MmuOps` (already a sched dependency) and the frame-alloc hook the HAL
//! itself holds for intermediate tables.
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hal::{MmuOps, PageFlags, PageSize, Pa, Va};
use sync::{KStack as KStackLock, Spinlock};

#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu as Mmu;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu as Mmu;

const PAGE: u64 = 4096;
/// 16 KiB usable stack = Linux `THREAD_SIZE`.
const STACK_PAGES: u64 = 4;
pub const KSTACK_BYTES: usize = (STACK_PAGES * PAGE) as usize;
/// One unmapped guard page below each stack. Slot = guard + stack pages.
const SLOT_PAGES: u64 = STACK_PAGES + 1;
const SLOT_BYTES: u64 = SLOT_PAGES * PAGE;
/// Dedicated kernel VA window, disjoint from HHDM, the device-BAR window
/// (`0xffff_fd00_…`) and the debug-efence arena (`0xffff_fc00_…`).
const KSTACK_VA_BASE: u64 = 0xffff_fb00_0000_0000;
/// Max concurrent kernel stacks (slots recycle on task exit). 16384 * 16 KiB =
/// 256 MiB of frames only if every slot is live at once; steady-state is far
/// less because slots recycle.
const MAX_STACKS: usize = 16384;

/// `fn() -> Option<pa>` and `fn(pa)` frame hooks, installed by kmain from pmm.
type FrameAllocFn = fn() -> Option<u64>;
type FrameFreeFn = fn(u64);
static FRAME_ALLOC: AtomicU64 = AtomicU64::new(0);
static FRAME_FREE: AtomicU64 = AtomicU64::new(0);

/// Install the PMM frame hooks + establish the window's top-level page-table
/// entry so every later-forked address space inherits the shared kstack
/// sub-tree. Call once at boot after the MMU + PMM are up, before spawning.
/// # C: O(1)
pub fn init(alloc: FrameAllocFn, free: FrameFreeFn) {
    FRAME_ALLOC.store(alloc as usize as u64, Ordering::Release);
    FRAME_FREE.store(free as usize as u64, Ordering::Release);
    // Establish the L4→…→leaf chain for the window (one sentinel page) so the
    // kernel-half PML4 entry exists in the master before any fork copies it;
    // on-demand stack maps then only add lower tables under the SHARED sub-tree
    // (visible to every AS without a further resync). The sentinel sits in slot
    // 0's guard region and is never handed out as a stack.
    if let Some(pa) = alloc() {
        // SAFETY: fresh frame from the PMM hook; VA is this private window's
        // base, mapped once as an inert sentinel to publish the sub-tree.
        unsafe { <Mmu as MmuOps>::map(Va(KSTACK_VA_BASE), Pa(pa), PageFlags::READ, PageSize::P4K); }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: pure PML4 kernel-half copy active→master after the sentinel map.
        unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }
    }
    NEXT_FRESH.store(1, Ordering::Release); // slot 0 reserved by the sentinel
    klog::write_raw(b"[KSTACK] guard-paged stacks armed va=");
    klog::write_hex_u64(KSTACK_VA_BASE);
    klog::write_raw(b" thread_size=");
    klog::write_dec_u64(KSTACK_BYTES as u64);
    klog::write_raw(b"\n");
}

fn frame_alloc() -> Option<u64> {
    let raw = FRAME_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: stored only by `init` from a valid `FrameAllocFn`.
    let f: FrameAllocFn = unsafe { core::mem::transmute(raw as usize) };
    f()
}
fn frame_free(pa: u64) {
    let raw = FRAME_FREE.load(Ordering::Acquire);
    if raw == 0 { return; }
    // SAFETY: stored only by `init` from a valid `FrameFreeFn`.
    let f: FrameFreeFn = unsafe { core::mem::transmute(raw as usize) };
    f(pa);
}

/// Slot free-list. `NEXT_FRESH` bumps into never-used slots; `FREED` recycles.
static FREED: Spinlock<FreeList, KStackLock> = Spinlock::new(FreeList::new());
static NEXT_FRESH: AtomicUsize = AtomicUsize::new(1);

struct FreeList { slots: [u32; MAX_STACKS], len: usize }
impl FreeList {
    const fn new() -> Self { Self { slots: [0; MAX_STACKS], len: 0 } }
    fn push(&mut self, s: u32) { if self.len < MAX_STACKS { self.slots[self.len] = s; self.len += 1; } }
    fn pop(&mut self) -> Option<u32> { if self.len == 0 { None } else { self.len -= 1; Some(self.slots[self.len]) } }
}

#[inline]
fn slot_guard_va(slot: usize) -> u64 { KSTACK_VA_BASE + slot as u64 * SLOT_BYTES }
#[inline]
fn slot_stack_lo(slot: usize) -> u64 { slot_guard_va(slot) + PAGE }
#[inline]
fn slot_stack_top(slot: usize) -> u64 { slot_stack_lo(slot) + STACK_PAGES * PAGE }

/// An owned guard-paged kernel stack. Exposes the usable 16 KiB region as a
/// slice (drop-in for the old `Box<[u8]>`); frees its frames + recycles its
/// slot on drop.
pub struct GuardedStack {
    slot: u32,
    frames: [u64; STACK_PAGES as usize],
}

impl GuardedStack {
    /// One-past-the-last usable byte (the initial RSP). # C: O(1)
    pub fn top(&self) -> *mut u8 { slot_stack_top(self.slot as usize) as *mut u8 }
    /// Lowest usable byte (the guard page starts one page below). # C: O(1)
    pub fn base(&self) -> *mut u8 { slot_stack_lo(self.slot as usize) as *mut u8 }
    /// Usable length (16 KiB). # C: O(1)
    pub fn len(&self) -> usize { KSTACK_BYTES }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { false }
    /// Usable stack region as a slice.
    /// # SAFETY: exclusive while the owning task is not running on it (spawn
    /// setup / teardown only); the pages are mapped RW for KSTACK_BYTES.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: [stack_lo, stack_lo+KSTACK_BYTES) is mapped RW by `alloc`.
        unsafe { core::slice::from_raw_parts(self.base() as *const u8, KSTACK_BYTES) }
    }
    /// Mutable usable stack region.
    /// # SAFETY: same as `as_slice`; caller ensures no concurrent stack use.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: mapped RW by `alloc`; caller-exclusive per fn contract.
        unsafe { core::slice::from_raw_parts_mut(self.base() as *mut u8, KSTACK_BYTES) }
    }
}

impl Drop for GuardedStack {
    /// Unmap the stack pages, return the frames to the PMM, recycle the slot.
    /// The guard page was never mapped. # C: O(STACK_PAGES)
    fn drop(&mut self) {
        let lo = slot_stack_lo(self.slot as usize);
        for i in 0..STACK_PAGES {
            // SAFETY: this stack owns [lo, lo+16KiB); unmap its own leaf, then
            // free the backing frame. No other mapping aliases these frames.
            unsafe { <Mmu as MmuOps>::unmap(Va(lo + i * PAGE), PageSize::P4K); }
            frame_free(self.frames[i as usize]);
        }
        FREED.lock().push(self.slot);
    }
}

/// Allocate a guard-paged kernel stack, or `None` if frames/slots are
/// exhausted (caller falls back / fails the spawn). # C: O(STACK_PAGES)
pub fn alloc() -> Option<GuardedStack> {
    // Pick a slot WITHOUT holding the lock across frame alloc / mapping (those
    // take Buddy/PageTable-rank locks; KStack is a leaf above them).
    let slot = {
        let mut fl = FREED.lock();
        match fl.pop() {
            Some(s) => s,
            None => {
                let s = NEXT_FRESH.fetch_add(1, Ordering::AcqRel);
                if s >= MAX_STACKS { NEXT_FRESH.fetch_sub(1, Ordering::AcqRel); return None; }
                s as u32
            }
        }
    };
    let lo = slot_stack_lo(slot as usize);
    let mut frames = [0u64; STACK_PAGES as usize];
    let mut got = 0usize;
    while got < STACK_PAGES as usize {
        match frame_alloc() {
            Some(pa) => {
                // SAFETY: fresh frame; VA is this slot's stack page, mapped once
                // RW cacheable so the task can execute on it.
                unsafe { <Mmu as MmuOps>::map(Va(lo + got as u64 * PAGE), Pa(pa), PageFlags::READ | PageFlags::WRITE, PageSize::P4K); }
                frames[got] = pa;
                got += 1;
            }
            None => break,
        }
    }
    if got != STACK_PAGES as usize {
        // Partial: unwind the pages we did map, free frames, recycle the slot.
        for i in 0..got {
            // SAFETY: we just mapped [lo+i*PAGE]; tear it down + free its frame.
            unsafe { <Mmu as MmuOps>::unmap(Va(lo + i as u64 * PAGE), PageSize::P4K); }
            frame_free(frames[i]);
        }
        FREED.lock().push(slot);
        return None;
    }
    // Zero the stack (the old Box was zero-initialized; keep that contract).
    // SAFETY: [lo, lo+16KiB) is now mapped RW and owned by this new stack.
    unsafe { core::ptr::write_bytes(lo as *mut u8, 0, KSTACK_BYTES); }
    Some(GuardedStack { slot, frames })
}
