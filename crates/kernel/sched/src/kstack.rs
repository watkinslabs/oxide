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
#[cfg(feature = "debug-armctx")]
use core::sync::atomic::AtomicU32;
use hal::{MmuOps, PageFlags, PageSize, Pa, Va};
use sync::{KStack as KStackLock, Spinlock};

#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu as Mmu;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu as Mmu;

const PAGE: u64 = 4096;
/// 16 KiB usable stack = Linux `THREAD_SIZE`, on both arches.
///
/// Briefly raised to 32 KiB while chasing the aarch64 `-smp 2` overflows and put
/// back: the overflows were softirq depth landing on the wrong stack, not task
/// frames being too large, and 32 KiB regressed x86 while fixing nothing that
/// the real fixes did not already fix. Measured peaks now: task ~6.7 KiB,
/// per-CPU IRQ stack ~14.5 KiB (dispatcher 13.9 KiB / net-RX softirq 14.5 KiB,
/// no longer summed because the drain cannot nest). Frame de-bloat targets are
/// ranked in `scratch/arm-smp2-fault.md`.
const STACK_PAGES: u64 = 4;
pub const KSTACK_BYTES: usize = (STACK_PAGES * PAGE) as usize;
// The per-CPU IRQ-stack switch in the arch IRQ entry asm hardcodes this size
// as a range bound — hal crates can't see this const (sched depends on hal, not
// vice-versa), so the asm literals are guarded HERE. Sites to update together:
//   x86  `cmp rdx, 0x4000`            hal-x86_64/src/irq.rs
//   arm  `sub x11, x10, #16384`       hal-aarch64/src/vbar/asm.rs (IRQ-stack switch)
//   arm  `sub x1, x1, #16384` x6      hal-aarch64/src/vbar/asm.rs (entry SP guard)
//   both `IRQ_STACK_BYTES`            hal-{x86_64,aarch64} irq.rs / vbar.rs
const _: () = assert!(KSTACK_BYTES == 0x4000);
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

/// debug-armctx slot provenance. `OWNER[slot]` = the tid that installed this
/// stack, tagged `OWNER_LIVE` while its `GuardedStack` is alive; `LAST_FREE[slot]`
/// = the tid whose stack last released the slot. A fatal-fault post-mortem maps
/// the faulting SP to its slot and reports both, so "running on a stack whose
/// slot was recycled under us" is a one-line answer instead of a hypothesis.
#[cfg(feature = "debug-armctx")]
const OWNER_LIVE: u32 = 1 << 31;
#[cfg(feature = "debug-armctx")]
static OWNER: [AtomicU32; MAX_STACKS] = [const { AtomicU32::new(0) }; MAX_STACKS];
#[cfg(feature = "debug-armctx")]
static LAST_FREE: [AtomicU32; MAX_STACKS] = [const { AtomicU32::new(0) }; MAX_STACKS];

/// Record the tid that owns this stack. No-op unless debug-armctx.
/// # C: O(1)
pub fn note_owner(top: *mut u8, tid: u32) {
    #[cfg(feature = "debug-armctx")]
    if let Some(slot) = slot_of_va(top as u64 - 1) {
        OWNER[slot].store(tid | OWNER_LIVE, Ordering::Release);
    }
    #[cfg(not(feature = "debug-armctx"))]
    { let _ = (top, tid); }
}

/// Slot index containing `va`, or `None` when `va` is outside the window.
/// # C: O(1)
#[cfg(feature = "debug-armctx")]
pub fn slot_of_va(va: u64) -> Option<usize> {
    if va < KSTACK_VA_BASE { return None; }
    let slot = ((va - KSTACK_VA_BASE) / SLOT_BYTES) as usize;
    if slot >= MAX_STACKS { None } else { Some(slot) }
}

/// Post-mortem: describe the kstack slot a VA falls in as
/// `(slot, owner_tid, owner_live, last_freed_tid, stack_lo, stack_top)`.
/// Pass the LAST byte of a range, not one-past-the-end: `stack_top` itself
/// belongs to the next slot's guard page.
/// # C: O(1)
#[cfg(feature = "debug-armctx")]
pub fn describe_va(va: u64) -> Option<(usize, u32, bool, u32, u64, u64)> {
    let slot = slot_of_va(va)?;
    let o = OWNER[slot].load(Ordering::Acquire);
    Some((slot, o & !OWNER_LIVE, o & OWNER_LIVE != 0,
          LAST_FREE[slot].load(Ordering::Acquire),
          slot_stack_lo(slot), slot_stack_top(slot)))
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
        #[cfg(feature = "debug-armctx")]
        {
            let prev = OWNER[self.slot as usize].swap(0, Ordering::AcqRel);
            LAST_FREE[self.slot as usize].store(prev & !OWNER_LIVE, Ordering::Release);
        }
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

/// Allocate a guard-paged stack and LEAK it as a permanent per-CPU stack
/// (the hardirq/IRQ stack, F699). Returns the 16-aligned top, or `None` on
/// frame/slot exhaustion. `mem::forget` skips `Drop` so the frames stay mapped
/// for the kernel lifetime — an IRQ stack, like an x86 IST stack, is never
/// freed. # C: O(STACK_PAGES)
pub fn alloc_leaked_top() -> Option<u64> {
    let s = alloc()?;
    let top = s.top() as u64;
    core::mem::forget(s);
    Some(top)
}
