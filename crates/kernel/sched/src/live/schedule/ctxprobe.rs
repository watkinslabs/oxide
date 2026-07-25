// F700 ARM IRQs-on register-corruption discriminator.
//
// The blocker: a task busy-polling in `virtio-blk::acquire_turn` with IRQs
// enabled at EL1 resumes with `x27` (its `&self`) == 0 while the faulting PC
// (ELR_EL1) is intact. GPRs and PC therefore came from DIFFERENT places, which
// splits the hypothesis space into exactly three classes:
//
//   1. the task resumed on a kernel stack whose kstack slot was recycled under
//      it (another task's `install_stack` zeroed + reused the pages),
//   2. `Task.arch_ctx` was intact at switch-out but clobbered while parked, so
//      `oxide_context_switch` restored a corrupt x19..x28,
//   3. nothing was saved/restored at all — a live in-stack spill was written
//      by a third party (a frame patcher).
//
// One boot answers which, instead of one boot per theory: this module records
// what `schedule()` SAVED for a task and what it RESTORED into it, and dumps
// that ring — plus the faulting SP's kstack-slot ownership and the task's live
// `arch_ctx` — from the fatal-fault printer via a hal hook.
//   * save x27 valid, restore x27 == 0  → class 2 (arch_ctx clobbered)
//   * save x27 already 0                → corrupted before the switch
//   * SP's slot owner != current tid    → class 1 (slot recycled)
//   * faulting tid absent from the ring → class 3 (live spill written)
//
// The signal that actually cracked it (PR #3901) was none of those three: the
// interrupted SP equalled `kstack_top` EXACTLY with the frame at
// `kstack_top-288`. An empty kernel stack mid-function means control ARRIVED
// there via an exception return, not a call chain — so the defect was the
// eret's PC (a stale ELR_EL1), not the register file. Keep an eye on
// `interrupted_sp` vs `kstack_top` before theorising about corruption.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Ring depth. The corruption lands within a handful of switches of the fault,
/// so 24 records cover the window while staying a fixed BSS cost.
const RING: usize = 24;

/// `kind` tags. `RESTORE` = values `oxide_context_switch` is about to load into
/// the incoming task; `SAVED` = values it stored for a task that just resumed.
const KIND_RESTORE: u64 = 1;
const KIND_SAVED: u64 = 2;

static HEAD: AtomicUsize = AtomicUsize::new(0);
static E_KIND_TID: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];
static E_X27: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];
static E_SP: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];
static E_LR: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];

fn push(kind: u64, tid: u32, x27: u64, sp: u64, lr: u64) {
    let i = HEAD.fetch_add(1, Ordering::Relaxed) % RING;
    E_X27[i].store(x27, Ordering::Relaxed);
    E_SP[i].store(sp, Ordering::Relaxed);
    E_LR[i].store(lr, Ordering::Relaxed);
    // kind|tid published LAST so a reader never sees a half-written record.
    E_KIND_TID[i].store((kind << 32) | tid as u64, Ordering::Release);
}

/// Record the callee-saved state `schedule()` is about to restore into the
/// incoming task. # C: O(1)
pub fn note_restore(tid: u32, ctx: &hal_aarch64::ContextAArch64) {
    push(KIND_RESTORE, tid, ctx.x27, ctx.sp, ctx.lr);
}

/// Record the callee-saved state that was saved for a task that just resumed.
/// # C: O(1)
pub fn note_saved(tid: u32, ctx: &hal_aarch64::ContextAArch64) {
    push(KIND_SAVED, tid, ctx.x27, ctx.sp, ctx.lr);
}

/// Fatal-fault post-mortem, installed into hal-aarch64 as its context-dump
/// hook. `frame` is the 288-byte exception-frame base on the interrupted stack,
/// so `frame + 288` is the interrupted SP.
/// # C: O(RING)
fn dump(frame: u64) {
    let isp = frame.wrapping_add(288);
    klog::write_raw(b"[ARMCTX] frame=");
    klog::write_hex_u64(frame);
    klog::write_raw(b" interrupted_sp=");
    klog::write_hex_u64(isp);
    let tid = match crate::current() {
        Some(t) => {
            klog::write_raw(b" tid=");
            klog::write_dec_u64(t.tid as u64);
            klog::write_raw(b" kstack_top=");
            klog::write_hex_u64(t.kernel_stack.load(Ordering::Acquire) as u64);
            t.tid
        }
        None => { klog::write_raw(b" tid=none"); 0 }
    };
    klog::write_raw(b"\n");

    // Class 1: does the interrupted SP live in a slot this task still owns?
    // Look up `isp - 1`, not `isp`: an empty stack has SP == kstack_top, which
    // is one-past-the-end and belongs to the NEXT slot's guard page — looking up
    // `isp` reports a false OWNER-MISMATCH on exactly the case that matters.
    match crate::kstack::describe_va(isp.saturating_sub(1)) {
        Some((slot, owner, live, last_free, lo, top)) => {
            klog::write_raw(b"[ARMCTX] slot=");
            klog::write_dec_u64(slot as u64);
            klog::write_raw(b" owner_tid=");
            klog::write_dec_u64(owner as u64);
            klog::write_raw(if live { b" LIVE" } else { b" FREED" });
            klog::write_raw(b" last_freed_tid=");
            klog::write_dec_u64(last_free as u64);
            klog::write_raw(b" lo=");
            klog::write_hex_u64(lo);
            klog::write_raw(b" top=");
            klog::write_hex_u64(top);
            klog::write_raw(b" headroom=");
            klog::write_dec_u64(isp.saturating_sub(lo));
            klog::write_raw(if owner == tid { b" OWNER-MATCH\n" } else { b" OWNER-MISMATCH\n" });
        }
        None => klog::write_raw(b"[ARMCTX] slot=none (SP outside the kstack window)\n"),
    }

    // Class 2: the live saved context of the faulting task.
    if let Some(t) = crate::current() {
        // SAFETY: fatal-fault post-mortem on the faulting CPU; the task is
        // `current` so its arch_ctx buffer is live, and we only read it.
        let ctx = unsafe { &*(t.arch_ctx_ptr::<hal_aarch64::ContextAArch64>()) };
        klog::write_raw(b"[ARMCTX] arch_ctx sp=");
        klog::write_hex_u64(ctx.sp);
        klog::write_raw(b" x27=");
        klog::write_hex_u64(ctx.x27);
        klog::write_raw(b" lr=");
        klog::write_hex_u64(ctx.lr);
        klog::write_raw(b"\n");
    }

    // Oldest-first walk of the switch ring.
    let head = HEAD.load(Ordering::Acquire);
    for n in 0..RING {
        let i = (head + n) % RING;
        let kt = E_KIND_TID[i].load(Ordering::Acquire);
        if kt == 0 { continue; }
        klog::write_raw(if (kt >> 32) == KIND_RESTORE { b"[ARMCTX] restore tid=" } else { b"[ARMCTX] saved   tid=" });
        klog::write_dec_u64(kt & 0xffff_ffff);
        klog::write_raw(b" x27=");
        klog::write_hex_u64(E_X27[i].load(Ordering::Relaxed));
        klog::write_raw(b" sp=");
        klog::write_hex_u64(E_SP[i].load(Ordering::Relaxed));
        klog::write_raw(b" lr=");
        klog::write_hex_u64(E_LR[i].load(Ordering::Relaxed));
        klog::write_raw(b"\n");
    }
}

/// Wire the post-mortem into the hal fault printer. Boot-path only.
/// # C: O(1)
pub fn install() {
    // SAFETY: `dump` is a 'static fn with the hook ABI; installed once from the
    // single-CPU boot path before any fault can consult it.
    unsafe { hal_aarch64::install_ctx_dump(dump); }
}
