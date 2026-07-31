// One `io_setup` context: the shared completion ring, the per-address-space
// registry that resolves an `aio_context_t` back to it, and the system-wide
// `fs.aio-max-nr` charge.
//
// `aio_context_t` is NOT an opaque handle — it is the user address the ring is
// mapped at. Userspace libaio dereferences it, checks `aio_ring.magic`, and
// reaps completions straight out of the mapping without entering the kernel;
// a cookie that is not a valid pointer faults the library instead.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as AioLockClass};
use syscall::errno::Errno;
use vfs::File;

use crate::aio_abi::geometry::{admit_aio_nr, order_for_pages, AIO_MAX_NR_DEFAULT};
use crate::aio_abi::ring::advance_tail;
use crate::aio_abi::uapi::*;

/// A completion the kernel has produced but not yet published.
#[derive(Clone, Copy)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

/// A submitted `IOCB_CMD_POLL` that has not become ready yet — the one request
/// kind that outlives its `io_submit`, and therefore the one `io_cancel` can
/// find.
pub struct ActiveReq {
    /// User `struct iocb *`; the key `io_cancel` matches on.
    pub obj: u64,
    pub data: u64,
    pub file: Arc<File>,
    /// Requested mask, already widened with the always-reported error/hangup
    /// bits.
    pub events: u32,
    /// `aio_resfd` eventfd to signal when this request completes.
    pub resfd: Option<Arc<File>>,
}

/// The physically contiguous, refcounted run backing one ring, plus where it
/// is mapped in the owning address space.
pub struct RingMem {
    pub base_pa: u64,
    pub order: u8,
    /// HHDM alias the kernel reads and writes the ring through.
    pub kva: u64,
    /// User address of the mapping — this is the context's `aio_context_t`.
    pub user_base: u64,
    pub map_bytes: u64,
}

impl Drop for RingMem {
    /// Release the run's object references. A live user mapping holds its own
    /// per-page reference (`VmaBacking::KernelFrame`), so the frames outlive
    /// this drop until the last mapping is gone.
    /// # C: O(2^order)
    fn drop(&mut self) {
        for i in 0..(1u64 << self.order) {
            // SAFETY: base_pa came from alloc_contig_object, which seeds one object reference per page in the run; release exactly that reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(self.base_pa + i * hal::PAGE_SIZE_BYTES); }
        }
    }
}

/// One live `io_setup` context.
pub struct AioContext {
    pub mem: RingMem,
    /// Slot count published in `aio_ring.nr`; the kernel's trusted copy.
    pub nr_events: u32,
    /// What the caller asked for, and what is charged against `aio-max-nr`.
    pub max_reqs: u32,
    /// Registry index, published in `aio_ring.id`. Assigned after the context
    /// exists, because the table stores the context itself.
    pub id: core::sync::atomic::AtomicU32,
    /// Owning address space. A dead weak reference means the process exited
    /// or exec'd; the entry is then reclaimed and its charge returned.
    pub mm: Weak<vmm::AddressSpace>,
    /// Producer index. Userspace owns `aio_ring.head` and may write anything
    /// there, so the tail is never read back out of the shared page.
    pub tail: Spinlock<u32, AioLockClass>,
    /// Free ring slots. One slot is structurally reserved so a full ring is
    /// distinguishable from an empty one.
    pub avail: Spinlock<u32, AioLockClass>,
    /// Submitted-but-unfinished requests (`IOCB_CMD_POLL` only).
    pub active: Spinlock<Vec<ActiveReq>, AioLockClass>,
    /// Wakes tasks parked in `io_getevents` on this context.
    pub waiters: Arc<vfs::PollSubscribers>,
}

/// Process-wide context table. The index is what `aio_ring.id` carries, so a
/// lookup costs one user read plus one array index.
static TABLE: Spinlock<Vec<Option<Arc<AioContext>>>, AioLockClass> = Spinlock::new(Vec::new());
/// Sum of every live context's `max_reqs`, bounded by `AIO_MAX_NR_DEFAULT`.
static AIO_NR: AtomicU64 = AtomicU64::new(0);

/// Current address space, or `None` outside a task. # C: O(1)
pub fn current_mm() -> Option<Arc<vmm::AddressSpace>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off through the syscall; the mm slot has a single mutator per `13§5`.
    unsafe { cur.mm_ref() }.cloned()
}

impl AioContext {
    /// Publish one completion into the ring and wake anything waiting on it.
    /// # C: O(1)
    pub fn complete(&self, ev: IoEvent) {
        {
            let mut tail = self.tail.lock();
            let idx = *tail;
            let slot = self.mem.kva + event_byte_off(idx);
            // SAFETY: idx < nr_events by construction of advance_tail, and nr_events was sized to fit the run; the HHDM alias is live for the ring's whole lifetime.
            unsafe {
                core::ptr::write_volatile((slot + IOEV_OFF_DATA) as *mut u64, ev.data);
                core::ptr::write_volatile((slot + IOEV_OFF_OBJ) as *mut u64, ev.obj);
                core::ptr::write_volatile((slot + IOEV_OFF_RES) as *mut i64, ev.res);
                core::ptr::write_volatile((slot + IOEV_OFF_RES2) as *mut i64, ev.res2);
            }
            let next = advance_tail(idx, self.nr_events);
            *tail = next;
            // The event body must be visible before the tail that publishes it,
            // or a userspace reaper reads a slot the kernel has not filled.
            core::sync::atomic::fence(Ordering::Release);
            self.store_hdr(RING_OFF_TAIL, next);
        }
        self.waiters.notify();
    }

    /// Read one `aio_ring` header word. # C: O(1)
    pub fn load_hdr(&self, off: u64) -> u32 {
        // SAFETY: off is one of the header offsets, all inside the first page of the run; the HHDM alias is live for the ring's lifetime.
        unsafe { core::ptr::read_volatile((self.mem.kva + off) as *const u32) }
    }

    /// Write one `aio_ring` header word. # C: O(1)
    pub fn store_hdr(&self, off: u64, v: u32) {
        // SAFETY: same bounded header offsets and live HHDM alias as load_hdr; the tail lock serialises kernel writers.
        unsafe { core::ptr::write_volatile((self.mem.kva + off) as *mut u32, v); }
    }

    /// Address of event slot `idx` in the kernel's alias. # C: O(1)
    pub fn slot_kva(&self, idx: u32) -> u64 { self.mem.kva + event_byte_off(idx) }

    /// Reserve one ring slot for a submission, or report the ring full.
    /// # C: O(1)
    pub fn get_req(&self) -> Result<(), Errno> {
        let mut a = self.avail.lock();
        if *a == 0 { return Err(Errno::Eagain); }
        *a -= 1;
        Ok(())
    }

    /// Return `n` reserved slots — either because a submission failed before
    /// it produced a completion, or because a reaper drained them.
    /// # C: O(1)
    pub fn put_reqs(&self, n: u32) {
        let mut a = self.avail.lock();
        *a = core::cmp::min(a.saturating_add(n), self.nr_events.saturating_sub(1));
    }
}

/// Seed the shared header so userspace can identify the ring. Runs before the
/// mapping is published, so no ordering against a reader is needed.
/// # C: O(1)
pub fn seed_header(kva: u64, id: u32, nr_events: u32) {
    let put = |off: u64, v: u32| {
        // SAFETY: kva is the freshly-zeroed, kernel-owned first page of the ring run, not yet reachable from userspace; off is a header offset within it.
        unsafe { core::ptr::write_volatile((kva + off) as *mut u32, v); }
    };
    put(RING_OFF_ID, id);
    put(RING_OFF_NR, nr_events);
    put(RING_OFF_HEAD, 0);
    put(RING_OFF_TAIL, 0);
    put(RING_OFF_MAGIC, AIO_RING_MAGIC);
    put(RING_OFF_COMPAT_FEATURES, AIO_RING_COMPAT_FEATURES);
    put(RING_OFF_INCOMPAT_FEATURES, AIO_RING_INCOMPAT_FEATURES);
    put(RING_OFF_HEADER_LENGTH, AIO_RING_HDR_SIZE as u32);
}

/// Allocate and zero the contiguous run for a ring of `nr_pages` pages.
/// # C: O(nr_pages)
pub fn alloc_ring(nr_pages: u64) -> Option<(u64, u8, u64)> {
    let order = order_for_pages(nr_pages);
    if order as u16 > pmm::MAX_ORDER as u16 { return None; }
    let base_pa = pmm::setup::alloc_contig_object(pmm::Order(order))?;
    let kva = base_pa + pmm::user_as::hhdm_offset();
    let bytes = (1usize << order) * hal::PAGE_SIZE_BYTES as usize;
    hal::zerotrap::trap(kva as *const u8, bytes);
    // SAFETY: the run was just allocated by this call and is not yet published to userspace or to any other CPU; the HHDM alias covers the whole run.
    unsafe { core::ptr::write_bytes(kva as *mut u8, 0, bytes); }
    Some((base_pa, order, kva))
}

/// Charge `max_reqs` against the system-wide limit. # C: O(1)
pub fn charge_aio_nr(max_reqs: u32) -> Result<(), Errno> {
    loop {
        let cur = AIO_NR.load(Ordering::Acquire);
        let next = admit_aio_nr(cur, max_reqs, AIO_MAX_NR_DEFAULT)?;
        if AIO_NR.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Ok(());
        }
    }
}

/// Return a context's charge. # C: O(1)
pub fn uncharge_aio_nr(max_reqs: u32) {
    AIO_NR.fetch_sub(max_reqs as u64, Ordering::AcqRel);
}

/// Install a context and hand back its table index. Reclaims the slots of
/// contexts whose address space has gone away first, so an exited process's
/// charge does not permanently consume the system limit.
/// # C: O(N_contexts)
pub fn table_insert(ctx: Arc<AioContext>) -> u32 {
    let mut t = TABLE.lock();
    let mut reclaimed: Vec<u32> = Vec::new();
    for slot in t.iter_mut() {
        let dead = slot.as_ref().is_some_and(|c| c.mm.upgrade().is_none());
        if dead {
            if let Some(c) = slot.take() { reclaimed.push(c.max_reqs); }
        }
    }
    let id = match t.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => { t.push(None); t.len() - 1 }
    };
    t[id] = Some(ctx);
    drop(t);
    for n in reclaimed { uncharge_aio_nr(n); }
    id as u32
}

/// Overwrite a table slot's context (used to publish the id the ring already
/// carries). # C: O(1)
pub fn table_set(id: u32, ctx: Option<Arc<AioContext>>) {
    let mut t = TABLE.lock();
    if let Some(slot) = t.get_mut(id as usize) { *slot = ctx; }
}

/// Resolve an `aio_context_t` to its context, in the same two steps the kernel
/// uses: read the table index out of the ring the caller points at, then
/// confirm the entry really is the caller's context. Both checks matter — the
/// index alone is forgeable, and the address alone is reusable across address
/// spaces.
/// # C: O(1)
pub fn lookup(ctx_id: u64) -> Option<Arc<AioContext>> {
    // The read below runs at CPL=0 with no fault fixup, so the address must be
    // proven to lie in a readable mapping — a range check alone would let a
    // garbage `aio_context_t` fault the kernel instead of returning EINVAL.
    if crate::userbuf::validate_user_buf_readable(ctx_id, 4, 4).is_err() { return None; }
    // SAFETY: ctx_id validated readable and 4-byte aligned below USER_VA_END; CPL=0 reads the ring's id word through the caller's active address space.
    let id = unsafe { core::ptr::read_volatile(ctx_id as *const u32) };
    let ctx = { TABLE.lock().get(id as usize).and_then(|s| s.clone()) }?;
    if ctx.mem.user_base != ctx_id { return None; }
    let mm = ctx.mm.upgrade()?;
    let cur = current_mm()?;
    if !Arc::ptr_eq(&mm, &cur) { return None; }
    Some(ctx)
}

/// Remove a context from the table by identity. Returns it when this call is
/// the one that removed it, so exactly one caller runs the teardown.
/// # C: O(1)
pub fn table_remove(ctx: &Arc<AioContext>) -> Option<Arc<AioContext>> {
    let mut t = TABLE.lock();
    let slot = t.get_mut(ctx.id.load(Ordering::Acquire) as usize)?;
    if !slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, ctx)) { return None; }
    slot.take()
}
