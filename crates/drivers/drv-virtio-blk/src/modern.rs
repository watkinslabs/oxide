// Modern virtio-blk runtime engine (arch-neutral). The model driver's
// `probe` in `pci_boot::virtio_drv` brings up cap discovery, BAR mapping,
// queue-0 program, and DRIVER_OK; once that finishes it hands the
// persistent kernel-side addresses + device-cfg here via `init_blk`.
// This module owns the synchronous request engine: build the 3-descriptor chain
// (header IN + data + status WRITE), kick the notify register, wait for
// completion.
//
// Completion wait is ADAPTIVE: a short bounded spin catches the common
// near-instant completion with zero added latency (keeps the boot read
// storm fast), then — only if it hasn't completed — the requesting task
// SLEEPS on `BLK_COMPL` instead of pegging a core. Sleepers are woken by the
// queue completion MSI registered by the virtio-pci transport. A wall-clock
// deadline bounds a genuinely-lost completion to `EIO`.
// Single in-flight is serialised by `RingShadow.busy` + the same wait
// list; the inflight spinlock is NEVER held across a sleep, so the
// completion path can take it.
//
// Arch-neutral because every post-bring-up op is MMIO (notify_cap
// window) + HHDM (ring + bounce frames). HHDM offset comes from the
// per-arch HAL, same split the net driver uses.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

use block::{BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
use virtio::blk;

/// Global wait list every blk sleeper parks on. One shared list (rather
/// than per-device) keeps the tick waker trivial: a wake re-runs all
/// sleepers, each re-checks its own used.idx / busy condition and
/// re-parks if not satisfied (spurious wakes are harmless). Covers both
/// completion waits and the single-in-flight gate.
#[cfg(target_os = "oxide-kernel")]
static BLK_COMPL: WaitList = WaitList::new();

/// Wake every parked blk waiter so it re-checks used.idx. Driven by the
/// per-queue completion MSI registered by the virtio-pci transport. Cheap
/// when no one is parked.
/// # C: O(N_waiters)
#[cfg(target_os = "oxide-kernel")]
pub fn wake_completions() {
    BLK_COMPL.wake_all();
}

/// HHDM base for the running arch.
/// # C: O(1)
#[inline]
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Monotonic wall-clock ns for the running arch (0 if unsupported).
/// Bounds the completion poll by real time instead of a spin count.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// True only when the current context may sleep: the runqueue is installed
/// AND `current` is a real schedulable task — NOT the per-CPU idle task.
/// Boot-smoke block reads run on the idle/boot context (where `current` is
/// the idle task); parking it is illegal (`enqueue` rejects Idle), so those
/// callers spin instead. Real syscall/exec/page-fault tasks park.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
fn can_sleep() -> bool {
    if sched::live::global().is_none() { return false; }
    match sched::live::current() {
        Some(t) => !matches!(t.sched_class(), sched::SchedClass::Idle),
        None => false,
    }
}

/// Sleep the current task on `BLK_COMPL` for one wake cycle (woken by the
/// queue completion MSI or by `release_turn`. Falls back to a CPU relax
/// before the scheduler exists. The caller re-checks its condition after
/// this returns.
/// # C: O(1) park
#[cfg(target_os = "oxide-kernel")]
#[inline]
fn park_blk() {
    if can_sleep() {
        // SAFETY: running task on this CPU, preempt-off; park bumps the Arc
        // + marks Sleeping before schedule; tick/release_turn wakes us and
        // the caller re-checks used.idx. No spinlock held across the park.
        unsafe {
            BLK_COMPL.park();
            sched::live::schedule::schedule();
        }
    } else {
        core::hint::spin_loop();
    }
}

/// Completion timeout. Real wall-clock replaces the old magic spin count:
/// a genuinely-lost completion fails `EIO` after a bounded time instead of
/// after an arbitrary, CPU-speed-dependent number of spins.
#[cfg(target_os = "oxide-kernel")]
const IO_TIMEOUT_NS: u64 = 5_000_000_000; // 5 s
/// Fast-path spin budget before falling back to sleeping. The common
/// completion lands within a few thousand spins (sub-µs on KVM), so this
/// catches it with zero scheduler overhead; only a slow/stuck completion
/// pays the sleep. Tuned well above typical KVM completion latency.
#[cfg(target_os = "oxide-kernel")]
const IO_SPIN_BUDGET: u64 = 200_000;
/// Hosted-fallback re-check budget (no clock, no sleeping). Named, not magic.
#[cfg(not(target_os = "oxide-kernel"))]
const IO_FALLBACK_SPINS: u64 = 50_000_000;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_BLK_F_BLK_SIZE;

/// Feature policy for the modern virtio-blk child driver. The PCI transport
/// executes common-cfg negotiation; this driver owns the block-specific bits
/// that affect its config parsing and runtime geometry.
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Bounce-frame layout. Three disjoint regions inside one contiguous
/// PMM allocation so the device's separate descriptors never alias and
/// the data descriptor addresses one physically-contiguous run:
///   header @0 (16B), status @0x10 (1B), data @0x1000 (page-aligned,
///   `BOUNCE_DATA_BYTES` = 128 KiB).
/// The data region holds up to `BOUNCE_DATA_SECTORS` (256) 512B sectors
/// in ONE virtio request, collapsing an N-sector transfer from N
/// round-trips to `ceil(N/256)`.
const HDR_OFF:    usize = 0x000;  // 16-byte virtio_blk_req header
const STATUS_OFF: usize = 0x010;  // 1-byte device status (after header)
const DATA_OFF:   usize = 0x1000; // 128 KiB data, page-aligned

/// Bytes the bounce frame must span: data region end. Rounded up to a
/// page for the contiguous PMM order below.
const BOUNCE_BYTES: usize = DATA_OFF + blk::BOUNCE_DATA_BYTES;
/// Contiguous PMM buddy order covering `BOUNCE_BYTES`. 0x1000 + 128 KiB
/// = 132 KiB → 33 pages → order 6 (64 pages = 256 KiB). One physically
/// contiguous region; base PA is region-aligned so the data descriptor
/// (one device-contiguous range) is valid.
const BOUNCE_ORDER: u8 = 6;

/// Global registration-order counter for disk naming (vda, vdb, …).
/// Each successfully-registered virtio-blk device claims the next
/// 0-based index; the registry NAME is `vd_name(index)`, unique per
/// device regardless of (possibly duplicate / empty) serials.
static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);

struct BlkRecord {
    bus:      u8,
    device:   u8,
    function: u8,
    name:     String,
    state:    Arc<BlkState>,
}

static DEVICES: Spinlock<Vec<BlkRecord>, DriverLockClass> = Spinlock::new(Vec::new());

fn same_bdf(rec: &BlkRecord, bus: u8, device: u8, function: u8) -> bool {
    rec.bus == bus && rec.device == device && rec.function == function
}

/// Persistent per-device request engine. The PAs/VA reference rings
/// the boot probe already programmed into the device; the bounce frame
/// is allocated once at `init_blk`. A single in-flight request at a
/// time (Stage 1, synchronous) — guarded by `inflight`.
pub struct BlkState {
    cfg_va:       u64,
    requestq:     virtio::VirtQueueResource,
    capacity:     u64,
    blk_size:     u32,
    /// Device serial from `VIRTIO_BLK_T_GET_ID` (trimmed). Identity
    /// label for root/home/tools-disk matching (`-device …,serial=…`);
    /// read by `serial()` — distinct from the registry name.
    serial:       [u8; blk::BLK_SERIAL_LEN],
    /// Contiguous bounce-region base PA (header + status + 128 KiB
    /// data), allocated once at init via the buddy at `BOUNCE_ORDER`.
    bounce_pa:    u64,
    /// Driver-side avail.idx shadow + used.idx last-seen + the single
    /// in-flight `busy` gate, under lock. Held only for brief shadow
    /// mutations — never across a sleep.
    inflight:     Spinlock<RingShadow, DriverLockClass>,
    /// Set when a completion TIMED OUT: the device still owns the fixed
    /// descriptors + the shared bounce frame, so reusing them would race the
    /// late DMA (a previous request's bytes served as another's — silent
    /// wrong-data corruption). Once poisoned every subsequent request fails
    /// EIO; the turn is never released.
    poisoned:     core::sync::atomic::AtomicBool,
}

// Single-in-flight by design (drivers-plan D7c, deliberate — NOT a façade).
// Each request is a real 3-descriptor chain (header IN + data + status WRITE)
// with genuine device completion (used.idx poll, then park on BLK_COMPL); the
// `busy` gate serializes submitters onto fixed descriptors 0..2 + the one
// shared bounce region. Multiple-in-flight (a free-descriptor pool, completion
// matched by used.ring[].id, per-request data buffers) is DEFERRED to the
// phase-17 block-layer/scheduler work: oxide issues NO concurrent block I/O
// today (pagecache + every syscall read/write path serialize above this; no
// async I/O until io_uring lands), so multi-in-flight would be unobservable
// complexity on the ext4-root critical path — high boot risk, zero consumer.
// Correct + serial, not faked.
struct RingShadow {
    avail_idx: u16,
    used_seen: u16,
    /// True while a request owns the single in-flight slot. Other
    /// submitters spin/sleep on `BLK_COMPL` until it clears.
    busy:      bool,
}

// SAFETY justification: BlkState holds raw PAs/VAs into HHDM/MMIO that
// are stable for device lifetime; all mutable ring access is funneled
// through the `inflight` Spinlock, so cross-CPU sharing is sound.
unsafe impl Send for BlkState {}
unsafe impl Sync for BlkState {}

impl BlkState {
    /// Trimmed device serial (from `GET_ID` at init). Identity label
    /// for root-disk matching — NOT the registry name.
    /// # C: O(1)
    pub fn serial(&self) -> &[u8; blk::BLK_SERIAL_LEN] { &self.serial }

    /// Quiesce publication and prevent future I/O. This is the minimal correct
    /// remove boundary for the current synchronous engine: no new request may
    /// reuse the shared descriptors/bounce frame after the device is reset.
    /// Existing holders of the Arc observe EIO through `poisoned`.
    /// # C: O(1)
    fn remove(&self) {
        self.poisoned.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
        if !self.wait_idle_for_remove() {
            if self.cfg_va != 0 {
                // Reset to stop further device DMA, but keep the bounce run
                // quarantined: an in-flight owner still has this request slot.
                unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
            }
            return;
        }
        if self.cfg_va != 0 {
            // Virtio reset: write 0 to device_status (§3.1.1). Use the byte
            // access size for the status field, matching modern virtio-pci.
            unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
        }
        if self.bounce_pa != 0 {
            // SAFETY: remove poisons the request engine first and resets the
            // device before returning the contiguous bounce run. Future holders
            // of this Arc observe EIO before touching the freed DMA buffer.
            unsafe { pmm::setup::free_contig(self.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
        }
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    /// Quiesce for reboot/poweroff. Unlike hot-unplug remove, shutdown keeps
    /// block publication and the per-device record intact because the machine
    /// is entering a terminal state; it only prevents new I/O and resets the
    /// virtio device so DMA stops before firmware/host reset.
    /// # C: O(wait until active request drains, bounded by IO_TIMEOUT_NS)
    fn shutdown(&self) {
        self.poisoned.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
        let idle = self.wait_idle_for_remove();
        if self.cfg_va != 0 {
            // Virtio reset: write 0 to device_status (§3.1.1). If a request
            // is wedged, keep the bounce frame quarantined; terminal shutdown
            // does not return it to the allocator.
            unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
        }
        if !idle {
            klog::write_raw(b"[BLK-SHUTDOWN] reset with busy request quarantined\n");
        }
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    /// Freeze new I/O and wait for the single in-flight request owner to leave
    /// the bounce region before freeing it. A permanently wedged request keeps
    /// the bounce run quarantined rather than freeing memory still reachable
    /// by a live owner.
    /// # C: O(wait until active request drains, bounded by IO_TIMEOUT_NS)
    fn wait_idle_for_remove(&self) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        let mut spun: u64 = 0;
        loop {
            if !self.inflight.lock().busy {
                return true;
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    return false;
                }
                if spun < IO_SPIN_BUDGET {
                    spun += 1;
                    core::hint::spin_loop();
                } else {
                    park_blk();
                }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS {
                    return false;
                }
                core::hint::spin_loop();
            }
        }
    }

    /// Issue one single-transfer request: `type_` ∈ T_IN / T_OUT /
    /// T_FLUSH / T_GET_ID. For device-readable transfers (T_OUT) the
    /// caller's `data` is copied into the bounce frame; for
    /// device-writable transfers (T_IN, T_GET_ID) the device fills the
    /// bounce frame, copied back into `data`. `data.len()` is the
    /// transfer length (must fit the data region; 0 for FLUSH).
    /// # C: O(wait until used.idx advances; sleeps after a short spin)
    fn submit(&self, type_: u32, sector: u64, data: &mut [u8]) -> KResult<()> {
        let h = hhdm();
        if h == 0 || !self.requestq.is_runtime_valid() || self.bounce_pa == 0 {
            return Err(BlockError::Eio);
        }
        let is_flush = type_ == blk::VIRTIO_BLK_T_FLUSH;
        // GET_ID + IN are device-writable (device fills the buffer);
        // OUT is device-readable (driver staged the payload).
        let is_in = type_ == blk::VIRTIO_BLK_T_IN
            || type_ == blk::VIRTIO_BLK_T_GET_ID;
        let data_len: u32 = if is_flush { 0 } else { data.len() as u32 };
        // Data region is BOUNCE_DATA_BYTES wide (128 KiB). One chunk per
        // submit must fit; the caller (submit_sync) splits larger runs.
        if data_len as usize > blk::BOUNCE_DATA_BYTES {
            return Err(BlockError::Einval);
        }

        // Claim the single in-flight slot (spins then sleeps until free),
        // run the request, then release the slot + wake the next submitter
        // on EVERY path so an error never strands the device busy.
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            return Err(BlockError::Eio);
        }
        self.acquire_turn();
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            // Poisoned while we waited: the ring/bounce belong to the wedged
            // request forever. If this task acquired the turn before seeing
            // poison, it has not published DMA, so release the gate.
            self.release_turn();
            return Err(BlockError::Eio);
        }
        let r = self.do_request(h, type_, sector, data, is_in, is_flush, data_len);
        if matches!(r, Err(BlockError::Eio))
            && self.poisoned.load(core::sync::atomic::Ordering::Acquire)
        {
            // Timeout path set `poisoned`: keep the turn held so the late DMA
            // target stays quarantined; wake waiters so they observe poison.
            #[cfg(target_os = "oxide-kernel")]
            BLK_COMPL.wake_all();
            return r;
        }
        self.release_turn();
        r
    }

    /// Build + publish + kick the request, wait for completion, copy
    /// results back. Runs while this task owns the in-flight slot
    /// (`acquire_turn`), so the ring is exclusively ours; the `inflight`
    /// spinlock is taken only for the brief shadow-index mutation and is
    /// never held across the wait (so the completion waker can take it).
    /// # C: O(wait until used.idx advances)
    #[allow(clippy::too_many_arguments)]
    fn do_request(&self, h: u64, type_: u32, sector: u64, data: &mut [u8],
                  is_in: bool, is_flush: bool, data_len: u32) -> KResult<()> {
        let bounce = h.wrapping_add(self.bounce_pa) as *mut u8;
        // Encode the 16-byte header at HDR_OFF.
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, type_, sector);
        // SAFETY: HHDM-mapped bounce frame owned by this device for its
        // lifetime; writes stay within the BOUNCE_BYTES contiguous region
        // (header at 0, status at 0x10, data_len-bounded run at 0x1000);
        // we exclusively own the in-flight slot via acquire_turn.
        unsafe {
            for (i, b) in hdr.iter().enumerate() {
                core::ptr::write_volatile(bounce.add(HDR_OFF + i), *b);
            }
            // For writes (T_OUT), stage the caller's payload into the
            // device-readable data region.
            if !is_in && !is_flush {
                for (i, b) in data.iter().enumerate() {
                    core::ptr::write_volatile(bounce.add(DATA_OFF + i), *b);
                }
            }
            // Sentinel status so a no-completion wait fails closed.
            core::ptr::write_volatile(bounce.add(STATUS_OFF), 0xFFu8);
        }

        // Build the descriptor chain via the shared encoder.
        let hdr_pa    = self.bounce_pa + HDR_OFF as u64;
        let data_pa   = self.bounce_pa + DATA_OFF as u64;
        let status_pa = self.bounce_pa + STATUS_OFF as u64;
        let (descs, n) = blk::build_chain(is_in, hdr_pa, data_pa, data_len, status_pa);

        let desc_tbl = h.wrapping_add(self.requestq.desc_pa) as *mut u64;
        // SAFETY: HHDM-mapped queue-0 descriptor table programmed by
        // the boot probe; `n ≤ 3` descriptors written as the two
        // little-endian words `pack_desc` defines; chain indices 0..n
        // are within the device-declared requestq size; we own the in-flight slot.
        unsafe {
            for (i, d) in descs.iter().take(n).enumerate() {
                let (w0, w1) = blk::pack_desc(d);
                core::ptr::write_volatile(desc_tbl.add(i * 2), w0);
                core::ptr::write_volatile(desc_tbl.add(i * 2 + 1), w1);
            }
        }

        // Publish the chain to the avail ring and capture our completion
        // target (the bumped avail.idx). Hold the inflight lock only for
        // this brief shadow mutation.
        let avail = h.wrapping_add(self.requestq.driver_pa) as *mut u16;
        let qsz = self.requestq.size;
        let target = {
            let mut g = self.inflight.lock();
            let slot = g.avail_idx % qsz;
            // SAFETY: HHDM-mapped queue-0 avail ring; u16 stores at the
            // flags(0)/idx(1)/ring(2+slot) offsets within the frame; slot
            // bounded by requestq.size; the Release fence publishes the chain
            // before idx so the device observes a fully-built request.
            unsafe {
                core::ptr::write_volatile(avail.add(2 + slot as usize), 0u16);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                g.avail_idx = g.avail_idx.wrapping_add(1);
                core::ptr::write_volatile(avail.add(1), g.avail_idx);
            }
            g.avail_idx
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // Kick the device via the notify register.
        if self.requestq.notify_va != 0 {
            // SAFETY: notify VA is the Device-attr MMIO window mapped by
            // the transport probe; an aligned u16 store of the queue index is
            // the spec-defined kick.
            unsafe {
                core::ptr::write_volatile(
                    self.requestq.notify_va as *mut u16,
                    self.requestq.index,
                );
            }
        }

        // Wait for the device to consume our chain (used.idx == target).
        self.wait_for_completion(h, target)?;

        // virtio_rmb (spec §2.7.13.2): a read/acquire barrier AFTER observing
        // used.idx and BEFORE reading the device-written bounce frame (status +
        // data). Without it the device's DMA writes to the bounce region can be
        // read stale/out-of-order vs the used.idx update — intermittently
        // returning a PREVIOUS request's bytes. That silently corrupted extent
        // metadata reads in resolve_pblock (-> wrong physical block -> a file
        // page served another block's content), poisoning libc's cached image
        // and deadlocking glibc on a garbage .bss lock (the boot wedge).
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        // Decode status; copy device-filled data back for reads.
        // SAFETY: HHDM-mapped bounce frame; aligned u8 read of the
        // status byte the device wrote, and the device-filled data
        // region for reads — both within the 4 KiB page.
        let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
        blk::decode_status(status).map_err(|_| BlockError::Eio)?;
        if is_in {
            // SAFETY: as above; copy device-written data bytes out.
            unsafe {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = core::ptr::read_volatile(bounce.add(DATA_OFF + i));
                }
            }
        }
        Ok(())
    }

    /// Wait until the device advances used.idx to `target`. Adaptive: a
    /// short bounded spin catches the common near-instant completion with
    /// zero scheduler overhead; only then does the task SLEEP on
    /// `BLK_COMPL` until the queue completion IRQ wakes it, avoiding a CPU
    /// peg on a slow/stuck completion. A wall-clock deadline bounds a genuinely-lost
    /// completion to `EIO`. Re-checks used.idx after every wake.
    /// # C: O(wait until used.idx advances)
    fn wait_for_completion(&self, h: u64, target: u16) -> KResult<()> {
        let used = h.wrapping_add(self.requestq.device_pa) as *const u16;
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        let mut spun: u64 = 0;
        loop {
            // SAFETY: HHDM-mapped queue-0 used ring; aligned u16 load of
            // the used.idx field at u16 offset 1 within the frame.
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx == target {
                self.inflight.lock().used_seen = uidx;
                return Ok(());
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    // Late completion may still DMA into the bounce frame —
                    // poison the device so no request ever reuses it.
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    klog::write_raw(b"[BLK-TIMEOUT] device poisoned, used stuck\n");
                    return Err(BlockError::Eio);
                }
                if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); }
                else { park_blk(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
    }

    /// Claim the single in-flight slot, spinning then sleeping on
    /// `BLK_COMPL` until it is free. Sets `busy` under the lock.
    /// # C: O(wait until the slot frees)
    fn acquire_turn(&self) {
        #[cfg(target_os = "oxide-kernel")]
        let mut spun: u64 = 0;
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.inflight.lock();
                if !g.busy { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            { if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); } else { park_blk(); } }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    /// Release the in-flight slot and wake waiters (next submitter + any
    /// completion sleeper re-checks; tick also wakes, this is just prompt).
    /// # C: O(N_waiters)
    fn release_turn(&self) {
        self.inflight.lock().busy = false;
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    /// Issue one `VIRTIO_BLK_T_GET_ID` request (spec §5.2.6): a 20-byte
    /// device-WRITABLE data buffer the device fills with the configured
    /// serial string. Returns the raw 20-byte id on success (all-zero
    /// if the device left it untouched). `Err` on transport failure.
    /// # C: O(spin until used.idx advances)
    fn get_id(&self) -> KResult<[u8; blk::BLK_SERIAL_LEN]> {
        let mut id = [0u8; blk::BLK_SERIAL_LEN];
        self.submit(blk::VIRTIO_BLK_T_GET_ID, 0, &mut id)?;
        Ok(id)
    }
}

impl BlockDevice for BlkState {
    fn block_size(&self) -> u32 { self.blk_size }

    fn capacity_blocks(&self) -> u64 {
        // `capacity` is in 512-byte virtio sectors; convert to blk_size.
        blk::capacity_blocks(self.capacity, self.blk_size)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let sec = blk::VIRTIO_BLK_SECTOR_BYTES as usize;
        match req.op {
            BlockOp::Flush => self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut []),
            BlockOp::Read | BlockOp::Write => {
                let bs = self.blk_size as usize;
                let nbytes = (req.len_blocks as usize)
                    .checked_mul(bs).ok_or(BlockError::Einval)?;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                } else if req.buffer.len() < nbytes {
                    return Err(BlockError::Einval);
                }
                // Each fs block spans bs/512 virtio sectors. Plan the
                // 512-byte sector run (shared host-tested helper).
                let (base_sector, total_sectors) =
                    blk::sector_plan(req.start_block, req.len_blocks, self.blk_size)
                        .ok_or(BlockError::Einval)?;
                let type_ = if req.op == BlockOp::Read {
                    blk::VIRTIO_BLK_T_IN
                } else {
                    blk::VIRTIO_BLK_T_OUT
                };
                // Chunk the run into ≤BOUNCE_DATA_SECTORS-sector requests;
                // each chunk = ONE virtio request (header + one data desc
                // of chunk_sectors*512 B + status), ONE used-ring poll.
                // A ≤128 KiB read is a single round-trip.
                let mut tmp: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                let mut chunk_idx = 0u64;
                while let Some((chunk_base, chunk_sectors, off)) = blk::chunk_plan(
                    base_sector, total_sectors, chunk_idx, blk::BOUNCE_DATA_SECTORS,
                ) {
                    let clen = chunk_sectors as usize * sec;
                    tmp.resize(clen, 0);
                    if req.op == BlockOp::Write {
                        tmp.copy_from_slice(&req.buffer[off..off + clen]);
                    }
                    self.submit(type_, chunk_base, &mut tmp[..clen])?;
                    if req.op == BlockOp::Read {
                        req.buffer[off..off + clen].copy_from_slice(&tmp[..clen]);
                    }
                    chunk_idx += 1;
                }
                Ok(())
            }
            BlockOp::Discard => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut [])
    }
}

/// Boot-probe handoff: the persistent ring addresses + device-cfg the
/// transport mapped. This driver reads the block device config itself after
/// DRIVER_OK.
#[derive(Copy, Clone)]
pub struct BlkInit {
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub resources: virtio::VirtioResources,
    pub drv_features: u64,
}

#[derive(Copy, Clone)]
struct BlkDeviceConfig {
    capacity: u64,
    blk_size: u32,
}

fn read_device_config(resources: virtio::VirtioResources, drv_features: u64) -> Option<BlkDeviceConfig> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }

    let mut capb = [0u8; 8];
    for i in 0..8 {
        // SAFETY: `device_cfg_va` is the transport-owned, Device-attr mapped
        // virtio-blk config window kept alive for this device lifetime.
        capb[i] = unsafe { core::ptr::read_volatile((cfg + i as u64) as *const u8) };
    }
    let capacity = u64::from_le_bytes(capb);

    let mut blk_size = blk::VIRTIO_BLK_SECTOR_BYTES;
    if drv_features & virtio::VIRTIO_BLK_F_BLK_SIZE != 0 {
        let mut bsb = [0u8; 4];
        for i in 0..4 {
            // SAFETY: offset 20 is `blk_size` in `virtio_blk_config`; the
            // mapped config page covers this fixed field.
            bsb[i] = unsafe {
                core::ptr::read_volatile(
                    (cfg + virtio::BLK_CFG_OFF_BLK_SIZE + i as u64) as *const u8,
                )
            };
        }
        let bs = u32::from_le_bytes(bsb);
        if bs != 0 {
            blk_size = bs;
        }
    }

    Some(BlkDeviceConfig { capacity, blk_size })
}

/// Linux-style registry name for the `index`-th (0-based) registered
/// virtio-blk device: `vda`, `vdb`, … `vdz`, `vdaa`, … Always unique
/// per device, independent of the (possibly duplicate / empty) serial.
/// # C: O(log26 index)
pub fn disk_name(index: u32) -> String {
    let mut buf = [0u8; 8];
    let n = blk::vd_name(index, &mut buf);
    // SAFETY-free: vd_name writes only ASCII 'v','d','a'..='z'.
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Build a `BlkState`, allocate its bounce frame, read its serial via
/// GET_ID, register it as a `BlockDevice` under a unique
/// registration-order name (`vda`, `vdb`, …), and return the assigned
/// 1-based registry index (0 on bounce-alloc failure).
/// # C: O(1) + GET_ID transfer + registry O(N_disks)
pub fn init_blk(init: BlkInit) -> u32 {
    let Some(requestq) = init.resources.require_queue(0) else {
        return 0;
    };
    if !init.resources.common_cfg_valid() {
        return 0;
    }
    let Some(device_cfg) = read_device_config(init.resources, init.drv_features) else {
        return 0;
    };
    if DEVICES.lock().iter().any(|d| same_bdf(d, init.bus, init.device, init.function)) {
        return 0;
    }
    // Contiguous BOUNCE_ORDER region (256 KiB) so the 128 KiB data
    // descriptor addresses one physically-contiguous, region-aligned run.
    let bounce_pa = match pmm::setup::alloc_contig(pmm::Order(BOUNCE_ORDER)) {
        Some(pa) => pa,
        None => return 0,
    };
    // Zero the bounce region for deterministic header/status state.
    let h = hhdm();
    if h != 0 {
        let va = h.wrapping_add(bounce_pa) as *mut u8;
        // SAFETY: HHDM-mapped freshly-allocated contiguous region we
        // exclusively own for this device's lifetime; aligned u8 stores
        // span only BOUNCE_BYTES (≤ the BOUNCE_ORDER region we allocated),
        // never past the region the buddy returned.
        unsafe {
            for i in 0..BOUNCE_BYTES { core::ptr::write_volatile(va.add(i), 0); }
        }
    }
    // Validate / clamp blk_size: must be ≥512 and a multiple of 512,
    // else the sector-run math (bs/512, capacity conversion) truncates.
    let blk_size = blk::validate_blk_size(device_cfg.blk_size);

    // Seed avail/used shadows from the live used.idx. The boot probe no
    // longer issues a throwaway request, so on QEMU this reads 0 — but
    // seed defensively in case the device or a warm reboot left used.idx
    // advanced, so the first real submit waits for a fresh completion
    // rather than mistaking a stale one for its own.
    let seed = if h != 0 && requestq.device_pa != 0 {
        let used = h.wrapping_add(requestq.device_pa) as *const u16;
        // SAFETY: HHDM-mapped queue-0 used ring programmed by the boot
        // probe; aligned u16 load of the used.idx field at offset 1.
        unsafe { core::ptr::read_volatile(used.add(1)) }
    } else { 0 };

    // Build the engine with an empty serial first, then read the real
    // serial via GET_ID and stamp it before publishing the Arc. The
    // ring fields are all that GET_ID needs.
    let mut state = BlkState {
        cfg_va:       init.resources.cfg_va,
        requestq,
        capacity:     device_cfg.capacity,
        blk_size,
        serial:       [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa,
        inflight:     Spinlock::new(RingShadow { avail_idx: seed, used_seen: seed, busy: false }),
        poisoned:     core::sync::atomic::AtomicBool::new(false),
    };

    // Read the real serial via GET_ID (device-writable 20-byte buffer).
    // This is the only correct source — device-cfg offset 24 is the
    // topology block, not a serial. Trimmed to printable ASCII; an
    // empty result just means index-based naming is the identity.
    if let Ok(raw) = state.get_id() {
        blk::trim_serial(&raw, &mut state.serial);
    }

    // Registry NAME by registration order — unique per device,
    // independent of serial collisions (#2). The serial above is the
    // separate identity label, accessible via `BlkState::serial()`.
    let disk_index = NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed);
    let name = disk_name(disk_index);
    // Capture the trimmed serial as a String BEFORE coercing to
    // `Arc<dyn BlockDevice>` (which erases `BlkState::serial()`), so the
    // registry can bind named volumes (oxide-root/oxide-home) by serial.
    let serial_len = state.serial.iter().position(|&b| b == 0).unwrap_or(state.serial.len());
    let serial_str = String::from_utf8_lossy(&state.serial[..serial_len]).into_owned();
    let state: Arc<BlkState> = Arc::new(state);
    let serial_opt = if serial_str.is_empty() { None } else { Some(serial_str.as_str()) };
    let existed = block::registry::by_name(&name).is_some();
    let idx = block::registry::register_with_serial(&name, serial_opt, state.clone());
    let published = if idx != 0 && !existed {
        let mut devices = DEVICES.lock();
        if devices.iter().any(|d| same_bdf(d, init.bus, init.device, init.function)) {
            false
        } else {
            devices.push(BlkRecord {
                bus: init.bus,
                device: init.device,
                function: init.function,
                name: name.clone(),
                state: state.clone(),
            });
            true
        }
    } else {
        false
    };
    if !published {
        if idx != 0 && !existed {
            let _ = block::registry::unregister(&name);
        }
        state.remove();
        return 0;
    }
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-blk-modern ");
        klog::write_dec_u64(init.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(init.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(init.function as u64);
        klog::write_raw(b" cap_sec=");
        klog::write_dec_u64(device_cfg.capacity);
        klog::write_raw(b" blk_size=");
        klog::write_dec_u64(blk_size as u64);
        klog::write_raw(b" idx=");
        klog::write_dec_u64(idx as u64);
        klog::write_raw(b"\n");
    }
    idx
}

/// Remove the virtio-blk device identified by its PCI BDF. Stops future I/O,
/// unregisters the block disk, and drops this driver's per-device record.
/// Existing filesystem references keep their Arc alive but see EIO.
/// # C: O(N_virtio_blk + N_disks + N_devices)
pub fn remove_blk(bus: u8, device: u8, function: u8) -> bool {
    let rec = {
        let mut devices = DEVICES.lock();
        match devices.iter().position(|d| same_bdf(d, bus, device, function)) {
            Some(i) => devices.remove(i),
            None => return false,
        }
    };
    rec.state.remove();
    block::registry::unregister(&rec.name)
}

/// Shutdown the virtio-blk device identified by its PCI BDF without
/// unregistering block/devtmpfs/sysfs publication. Used by reboot/poweroff,
/// not hot-unplug.
/// # C: O(N_virtio_blk + shutdown)
pub fn shutdown_blk(bus: u8, device: u8, function: u8) -> bool {
    let state = {
        DEVICES.lock()
            .iter()
            .find(|d| same_bdf(d, bus, device, function))
            .map(|d| d.state.clone())
    };
    let Some(state) = state else { return false; };
    state.shutdown();
    true
}

#[cfg(test)]
pub(crate) fn test_publish_record(bus: u8, device: u8, function: u8, name: &str) -> u32 {
    if DEVICES.lock().iter().any(|d| same_bdf(d, bus, device, function)) {
        return 0;
    }
    let state = Arc::new(BlkState {
        cfg_va:       0,
        requestq:     virtio::VirtQueueResource {
            index:      0,
            size:       0,
            desc_pa:    0,
            driver_pa:  0,
            device_pa:  0,
            notify_va:  0,
            notify_off: 0,
        },
        capacity:     8,
        blk_size:     512,
        serial:       [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa:    0,
        inflight:     Spinlock::new(RingShadow { avail_idx: 0, used_seen: 0, busy: false }),
        poisoned:     core::sync::atomic::AtomicBool::new(false),
    });
    let idx = block::registry::register_with_serial(name, None, state.clone());
    if idx != 0 {
        DEVICES.lock().push(BlkRecord {
            bus,
            device,
            function,
            name: String::from(name),
            state,
        });
    }
    idx
}

#[cfg(test)]
pub(crate) fn test_has_record(bus: u8, device: u8, function: u8) -> bool {
    DEVICES.lock().iter().any(|d| same_bdf(d, bus, device, function))
}
