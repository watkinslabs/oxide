//! debug-efence arena: page-per-object OVERFLOW guard allocator (C213).
//!
//! Evidence (three boots) says the boot corruptor is a heap buffer OVERFLOW
//! from a small (<4096) object, not a UAF: fencing every small object on its
//! own page — which puts ~4 KiB of slack after each — MASKS the bug, exactly
//! what per-object slack does to an overflow, and reconciles the offset-0/8
//! victim signature (= the NEXT block's header). So this arena catches the
//! overflow directly: each object is placed flush against the end of its page,
//! immediately followed by a permanent read-only GUARD page. A write past the
//! object's end lands in the guard → kernel #PF whose `rip` = the overflower
//! and `cr2` = a guard VA (odd page of a 2-page slot, in the arena's
//! distinctive `0xffff_fc00_…` window).
//!
//! Overflow detection needs NO retention (the guard fires on a LIVE object as
//! it is written), so slots recycle freely on free — the alloc churn that
//! defeats a use-after-free arena is irrelevant here.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use hal::{MmuOps, PageFlags, PageSize, Pa, Va};
use sync::{Efence as EfenceLock, Spinlock};

#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu as Mmu;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu as Mmu;

/// Dedicated kernel VA window, disjoint from HHDM and the device-BAR window
/// (`0xffff_fd00_…`). Its distinctive high prefix is the "this is an efence
/// overflow hit" signature when it shows up as a fault `cr2`.
const EFENCE_VA_BASE: u64 = 0xffff_fc00_0000_0000;
const PAGE: u64 = 4096;
/// Each slot is [object page][guard page]. The object frame is RW and
/// recycles; the guard page is a single shared RO frame.
const SLOT_BYTES: u64 = 2 * PAGE;
/// Slot count = max SIMULTANEOUS live fenced objects headroom (peak observed
/// ~56k). 131072 slots ⇒ 512 MiB of object frames (boot with `mem=8G`). Slots
/// recycle, so this bounds concurrent-live, not lifetime allocations.
const EFENCE_SLOTS: usize = 131072;
/// Fenced size class (must be ≤ PAGE so the object + guard fit the slot). 4096
/// = exact page fill (ext4 metadata_write's full_buf, the block that surfaced
/// this). Fencing the WHOLE small class — not the incidental victim size — is
/// what catches the overFLOWER: whichever small object writes past its end.
const OBJ_MAX: usize = 4096;
/// Log a running fenced-alloc count every this many allocations (rate diag).
const ALLOC_LOG_STRIDE: u64 = 262144;

const ST_FREE: u8 = 0;
const ST_LIVE: u8 = 1;

struct Arena {
    obj_pa: Vec<u64>,   // obj_pa[i] = physical frame backing slot i's object page
    size: Vec<u32>,     // requested size of slot i's current object
    alloc_ip: Vec<u64>, // caller that allocated slot i's current object
    state: Vec<u8>,
    free_slots: Vec<u32>, // stack of recyclable slot indices
    live: usize,
    total_alloc: u64,
    exhausted_logged: bool,
}

static ARENA: Spinlock<Option<Arena>, EfenceLock> = Spinlock::new(None);
/// Fast-reject bounds for the free path (range-check without the arena lock).
static LO: AtomicU64 = AtomicU64::new(0);
static HI: AtomicU64 = AtomicU64::new(0);

#[inline]
fn slot_obj_base(i: usize) -> u64 { EFENCE_VA_BASE + i as u64 * SLOT_BYTES }
#[inline]
fn slot_guard_va(i: usize) -> u64 { slot_obj_base(i) + PAGE }

/// Build the arena: one RW object frame per slot, all guard pages aliased to a
/// single shared RO frame. Caps early (logs) if the PMM can't back the frames.
pub fn init() {
    let Some(guard_frame) = pmm::setup::alloc_raw_frame() else {
        klog::write_primary_raw(b"[EFENCE] init: no guard frame, disabled\n");
        return;
    };
    let mut obj_pa = Vec::new();
    if obj_pa.try_reserve_exact(EFENCE_SLOTS).is_err() {
        klog::write_primary_raw(b"[EFENCE] init: metadata reserve failed, disabled\n");
        return;
    }
    let mut slots = 0usize;
    while slots < EFENCE_SLOTS {
        let Some(frame) = pmm::setup::alloc_raw_frame() else { break; };
        // SAFETY: fresh raw frame owned here; obj VA from the private arena
        // window, used once; RW cacheable so callers use it as heap memory.
        unsafe {
            <Mmu as MmuOps>::map(Va(slot_obj_base(slots)), Pa(frame), PageFlags::READ | PageFlags::WRITE, PageSize::P4K);
            // Guard page: shared RO frame — a write here (object overflow) #PFs.
            <Mmu as MmuOps>::map(Va(slot_guard_va(slots)), Pa(guard_frame), PageFlags::READ, PageSize::P4K);
        }
        obj_pa.push(frame);
        slots += 1;
    }
    if slots == 0 {
        klog::write_primary_raw(b"[EFENCE] init: no frames, disabled\n");
        return;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: pure PML4 kernel-half copy active→master after a batch of maps.
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }

    let n = slots;
    let mut free_slots = Vec::new();
    let _ = free_slots.try_reserve_exact(n);
    for i in (0..n).rev() { free_slots.push(i as u32); }
    let arena = Arena {
        obj_pa,
        size: vec_zeroed_u32(n),
        alloc_ip: vec_zeroed_u64(n),
        state: { let mut v = Vec::new(); v.resize(n, ST_FREE); v },
        free_slots,
        live: 0,
        total_alloc: 0,
        exhausted_logged: false,
    };
    *ARENA.lock() = Some(arena);
    LO.store(EFENCE_VA_BASE, Ordering::Release);
    HI.store(EFENCE_VA_BASE + n as u64 * SLOT_BYTES, Ordering::Release);
    kalloc::install_efence(ef_alloc, ef_free, EFENCE_VA_BASE, EFENCE_VA_BASE + n as u64 * SLOT_BYTES);

    klog::write_primary_raw(b"[EFENCE] overflow-mode armed slots=");
    klog::write_primary_dec_u64(n as u64);
    klog::write_primary_raw(b" va=");
    klog::write_primary_hex_u64(EFENCE_VA_BASE);
    klog::write_primary_raw(b" obj_max=");
    klog::write_primary_dec_u64(OBJ_MAX as u64);
    klog::write_primary_raw(b"\n");
}

fn vec_zeroed_u32(n: usize) -> Vec<u32> { let mut v = Vec::new(); v.resize(n, 0u32); v }
fn vec_zeroed_u64(n: usize) -> Vec<u64> { let mut v = Vec::new(); v.resize(n, 0u64); v }

/// kalloc alloc hook: place a `size`-class object flush against the end of its
/// slot's object page, immediately before the RO guard. Returns null (kalloc
/// falls back to its normal heap) when not fenceable or the arena is out.
fn ef_alloc(size: usize, align: usize, alloc_ip: u64) -> *mut u8 {
    if size == 0 || size > OBJ_MAX || align as u64 > PAGE { return core::ptr::null_mut(); }
    let mut g = ARENA.lock();
    let Some(a) = g.as_mut() else { return core::ptr::null_mut(); };
    let Some(slot) = a.free_slots.pop() else {
        if !a.exhausted_logged {
            a.exhausted_logged = true;
            klog::write_primary_raw(b"[EFENCE] arena exhausted (live slots); further allocs unfenced\n");
        }
        return core::ptr::null_mut();
    };
    let slot = slot as usize;
    // End-align: largest align-aligned offset with `off + size <= PAGE`, so the
    // object ends within `align-1` bytes of the guard. A ≥`align`-byte overflow
    // (the 16-byte offset-0/8 scribble qualifies) crosses into the guard.
    let off = (((PAGE as usize) - size) / align) * align;
    a.state[slot] = ST_LIVE;
    a.size[slot] = size as u32;
    a.alloc_ip[slot] = alloc_ip;
    a.live += 1;
    a.total_alloc += 1;
    if a.total_alloc % ALLOC_LOG_STRIDE == 0 {
        klog::write_primary_raw(b"[EFENCE] fenced-allocs=");
        klog::write_primary_dec_u64(a.total_alloc);
        klog::write_primary_raw(b" live=");
        klog::write_primary_dec_u64(a.live as u64);
        klog::write_primary_raw(b"\n");
    }
    (slot_obj_base(slot) + off as u64) as *mut u8
}

/// kalloc free hook: recycle the slot (object frame stays mapped RW for reuse;
/// the guard stays RO). Returns true = kalloc must NOT free it.
fn ef_free(ptr: *mut u8, free_ip: u64) -> bool {
    let p = ptr as u64;
    if p < LO.load(Ordering::Acquire) || p >= HI.load(Ordering::Acquire) { return false; }
    let slot = ((p - EFENCE_VA_BASE) / SLOT_BYTES) as usize;
    let mut g = ARENA.lock();
    let Some(a) = g.as_mut() else { return false; };
    if slot >= a.obj_pa.len() { return false; }
    if a.state[slot] != ST_LIVE {
        klog::write_primary_raw(b"[EFENCE] double/invalid free va=");
        klog::write_primary_hex_u64(p);
        klog::write_primary_raw(b" free_ip=");
        klog::write_primary_hex_u64(free_ip);
        klog::write_primary_raw(b"\n");
        return true;
    }
    a.state[slot] = ST_FREE;
    a.live = a.live.saturating_sub(1);
    a.free_slots.push(slot as u32);
    true
}
