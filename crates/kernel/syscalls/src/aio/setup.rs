// `io_setup(2)` / `io_destroy(2)`: build the shared completion ring and map it
// into the caller's address space, and tear the pair down again.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::Spinlock;
use syscall::errno::Errno;

use crate::aio_abi::geometry::plan_ring;
use crate::aio::ctx::{self, AioContext, RingMem};
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// `PROT_READ | PROT_WRITE` for the ring mapping: userspace advances
/// `aio_ring.head` itself when it reaps without a syscall.
const RING_PROT: u64 = 0x1 | 0x2;
/// `MAP_SHARED` — the ring is one physical object seen by kernel and user.
const RING_MAP_FLAGS: u64 = 0x1;
/// `aio_context_t` is a `u64` in the user's word.
const CTX_ID_BYTES: u64 = 8;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_io_setup(nr_events, ctxp)` — slot 206.
///
/// Ladder order, which a caller can observe by combining bad arguments:
/// the read of `*ctxp` comes first (so an unreadable pointer is `EFAULT` even
/// when `nr_events` is zero), then the "must be zero, and must be non-zero"
/// pair as one `EINVAL`, then sizing, then the system-wide charge.
/// # C: O(nr_pages)
pub fn sys_io_setup(nr_events: u32, ctxp: u64) -> i64 {
    if validate_user_buf_readable(ctxp, CTX_ID_BYTES, CTX_ID_BYTES).is_err() { return err(Errno::Efault); }
    // SAFETY: ctxp validated readable and 8-byte aligned below USER_VA_END; CPL=0 reads the caller's aio_context_t through its active address space.
    let prev = unsafe { core::ptr::read_volatile(ctxp as *const u64) };
    if prev != 0 || nr_events == 0 { return err(Errno::Einval); }

    let page = hal::PAGE_SIZE_BYTES;
    let cpus = core::cmp::max(cpu::count(), 1);
    let plan = match plan_ring(nr_events, cpus, page, crate::aio_abi::geometry::AIO_MAX_NR_DEFAULT) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    if let Err(e) = ctx::charge_aio_nr(plan.max_reqs) { return err(e); }

    let (base_pa, order, kva) = match ctx::alloc_ring(plan.nr_pages) {
        Some(v) => v,
        None => { ctx::uncharge_aio_nr(plan.max_reqs); return err(Errno::Enomem); }
    };
    // The mapping must cover the whole run, not just the bytes the header and
    // slots occupy: a shorter mapping would leave the tail of the last page
    // unmapped while `nr_events` claims those slots exist.
    let map_bytes = (1u64 << order) * page;
    let mm = match ctx::current_mm() {
        Some(m) => m,
        None => { drop_ring(base_pa, order); ctx::uncharge_aio_nr(plan.max_reqs); return err(Errno::Enomem); }
    };
    let user_base = match pmm::user_as::glue_mmap(
        0, map_bytes, RING_PROT, RING_MAP_FLAGS, -1, 0, None, None, Some(base_pa),
        vmm::VmaProt::READ | vmm::VmaProt::WRITE,
    ) {
        Ok(va) => va,
        Err(rv) => { drop_ring(base_pa, order); ctx::uncharge_aio_nr(plan.max_reqs); return rv; }
    };

    let c = Arc::new(AioContext {
        mem: RingMem { base_pa, order, kva, user_base, map_bytes },
        nr_events: plan.nr_events,
        max_reqs: plan.max_reqs,
        id: AtomicU32::new(0),
        mm: Arc::downgrade(&mm),
        tail: Spinlock::new(0),
        avail: Spinlock::new(plan.nr_events.saturating_sub(1)),
        active: Spinlock::new(Vec::new()),
        waiters: Arc::new(vfs::PollSubscribers::new()),
        waker: Spinlock::new(None),
    });
    // The wait-queue callback holds a Weak back to the context, so it can only
    // be built once the context is behind its Arc.
    *c.waker.lock() = Some(Arc::new(ctx::AioPollWaker { ctx: Arc::downgrade(&c) }));
    let id = ctx::table_insert(c.clone());
    c.id.store(id, Ordering::Release);
    ctx::seed_header(kva, id, plan.nr_events);

    // The context is reachable only through this address, so a write-back
    // failure must not leave it stranded in the table.
    if validate_user_buf_writable(ctxp, CTX_ID_BYTES, CTX_ID_BYTES).is_err() {
        teardown(&c);
        return err(Errno::Efault);
    }
    // SAFETY: ctxp validated writable and 8-byte aligned below USER_VA_END; CPL=0 publishes the ring's user address as the caller's aio_context_t.
    unsafe { core::ptr::write_volatile(ctxp as *mut u64, user_base); }
    0
}

/// Release a run that never became a context. # C: O(2^order)
fn drop_ring(base_pa: u64, order: u8) {
    for i in 0..(1u64 << order) {
        // SAFETY: base_pa came from alloc_contig_object in this call and was never published; release the one object reference each page holds.
        unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(base_pa + i * hal::PAGE_SIZE_BYTES); }
    }
}

/// Drop a context: unregister it, resolve every outstanding request, unmap the
/// ring, and return its charge. Unmapping releases the per-page mapping
/// references; the run itself dies with the last `Arc<AioContext>`.
/// # C: O(N_active + nr_pages)
pub fn teardown(c: &Arc<AioContext>) {
    if ctx::table_remove(c).is_none() { return; }
    // `io_destroy` may not return while a submitted request could still touch
    // the caller's buffers. Read/write/fsync submissions have already
    // completed by the time their `io_submit` returned; the poll requests are
    // the only ones left, and dropping them here is what resolves them.
    // Dropping the wait-queue callback drops the last strong reference to it,
    // so every polled file's subscriber list prunes this context's entry on its
    // next wake — no per-file unsubscribe bookkeeping to get wrong.
    let waker = c.waker.lock().take();
    drop(waker);
    let dropped = { let mut a = c.active.lock(); let n = a.len() as u32; a.clear(); n };
    c.put_reqs(dropped);
    // Wake anything parked in io_getevents on this context so it re-checks and
    // finds the context gone.
    c.waiters.notify();
    let rv = pmm::user_as::glue_munmap(c.mem.user_base, c.mem.map_bytes);
    let _ = rv;
    ctx::uncharge_aio_nr(c.max_reqs);
}

/// `sys_io_destroy(ctx_id)` — slot 207. `EINVAL` for anything that is not a
/// live context of the calling address space.
/// # C: O(N_active + nr_pages)
pub fn sys_io_destroy(ctx_id: u64) -> i64 {
    let c = match ctx::lookup(ctx_id) { Some(c) => c, None => return err(Errno::Einval) };
    teardown(&c);
    0
}
