use super::*;
use core::sync::atomic::AtomicU64;

/// Virtio device ID for block devices.
pub const VIRTIO_ID_BLOCK: u16 = 2;

/// Driver-model identity for virtio-blk child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-blk", VIRTIO_ID_BLOCK);

/// Per-condition wait queues — Linux waits on the CONDITION, not on a shared
/// per-device list. `BLK_COMPL`: the turn-holder waiting for its in-flight
/// request's used-ring entry (≤1 waiter). `BLK_TURN`: tasks in `acquire_turn`
/// waiting for the engine's single-outstanding turn to free (N waiters).
///
/// One shared list made every completion `wake_all` rouse EVERY turn-waiter,
/// all but one of which immediately re-parked: a thundering herd costing O(N)
/// scheduling churn per I/O, which serialized into multi-ms wake latency across
/// an I/O-storm boot.
#[cfg(target_os = "oxide-kernel")]
pub(super) static BLK_COMPL: WaitList = WaitList::new();
#[cfg(target_os = "oxide-kernel")]
pub(super) static BLK_TURN: WaitList = WaitList::new();

#[cfg(feature = "debug-hibernate")]
static HIBERNATE_SYNC_TRACE: AtomicU16 = AtomicU16::new(0);

/// Number of completion notifications delivered through the virtio-blk IRQ
/// entry point. Polling a dedicated queue must not increment this counter;
/// it is runtime evidence that the polled path avoided a device interrupt.
static COMPLETION_INTERRUPTS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn note_completion_interrupt() {
    COMPLETION_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
}

/// Read the cumulative completion-interrupt count for diagnostics and tests.
/// # C: O(1)
pub fn completion_interrupt_count() -> u64 {
    COMPLETION_INTERRUPTS.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn note_completion_interrupt_for_tests() {
    note_completion_interrupt();
}

/// Arm allocation-free traces of the first 512 synchronous image I/Os.
pub fn arm_hibernate_sync_trace() {
    #[cfg(feature = "debug-hibernate")]
    HIBERNATE_SYNC_TRACE.store(512, Ordering::Release);
}

#[cfg(feature = "debug-hibernate")]
pub(super) fn claim_hibernate_sync_trace() -> u16 {
    match HIBERNATE_SYNC_TRACE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |remaining| remaining.checked_sub(1)) {
        Ok(remaining) => 513 - remaining,
        Err(_) => 0,
    }
}

/// Rouse every block waiter regardless of which condition it sleeps on. For
/// abort-everything transitions (poison / shutdown / device removal) where a
/// sleeper on EITHER queue must re-check and bail — waking only one queue after
/// the split above would strand `acquire_turn` sleepers forever, since
/// `park_blk_checked` parks with no deadline.
/// # C: O(waiters)
#[cfg(target_os = "oxide-kernel")]
pub(super) fn wake_all_blk_waiters() {
    BLK_COMPL.wake_all();
    BLK_TURN.wake_all();
}

#[cfg(target_os = "oxide-kernel")]
pub fn wake_completions() {
    note_completion_interrupt();
    // The interrupt is the completion notification for both wait conditions:
    // it may finish the synchronous owner, or retire an asynchronous request
    // that frees the engine turn. Wake both classes in hard-IRQ context; each
    // waiter rechecks its predicate, while the block softirq still owns
    // used-ring retirement and completion callbacks.
    BLK_COMPL.wake_all();
    BLK_TURN.wake_one();
    block::completion::raise();
}

/// Process virtio-blk completion notifications outside hard-IRQ context.
///
/// The current request engine has one owner at a time, but completion
/// observation and task wakeup still belong in the block softirq. Keeping the
/// IRQ side to a bit raise is required before the engine can safely grow to
/// multiple outstanding descriptor chains.
#[cfg(target_os = "oxide-kernel")]
pub(super) fn run_completion_bottom_half() {
    let devices: Vec<Arc<BlkState>> = DEVICES.lock_bh::<sched::bh::SchedBh>()
        .iter().map(|record| record.state.clone()).collect();
    for device in devices {
        // ONLY the interrupt-driven queue. Nothing raises this softirq for the
        // poll queue — the device has no vector for it and its `avail.flags`
        // suppress the notification — and draining it here would take
        // completions out from under the poller that owns them.
        for q in device.queues().filter(|q| softirq_drains(q)) {
            let _reaped = device.drain_owned_completions(q);
        }
    }
    // Wake the in-flight turn-holder (≤1 waiter, no herd), then hand a chance to
    // ONE turn-waiter in case the drain freed the engine turn for an async
    // completion (FIFO; the woken task re-checks and re-parks if still busy).
    BLK_COMPL.wake_all();
    BLK_TURN.wake_one();
}

#[inline]
pub(super) fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

#[cfg(target_os = "oxide-kernel")]
#[inline]
pub(super) fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

#[cfg(target_os = "oxide-kernel")]
#[inline]
fn can_sleep() -> bool {
    if sched::live::global().is_none() { return false; }
    // Interrupt context must never sleep (Linux `in_interrupt()` /
    // `might_sleep()`). The IRQ entry asm runs the dispatcher on the SHARED
    // per-CPU hard-IRQ stack. Parking from there records a `Context.sp` pointing
    // into that shared stack; the next IRQ on this CPU resets SP to the same top
    // and overwrites the sleeper's frames, so it resumes with garbage return
    // addresses — observed on aarch64 as an EL1 branch into `.data`. Spin instead:
    // the caller's budget loop re-polls, which is what a Linux softirq does.
    #[cfg(target_arch = "aarch64")]
    if hal_aarch64::on_irq_stack() { return false; }
    #[cfg(target_arch = "x86_64")]
    if hal_x86_64::on_irq_stack() { return false; }
    match sched::live::current() {
        Some(t) => !matches!(t.sched_class(), sched::SchedClass::Idle),
        None => false,
    }
}

/// Register-then-recheck park for the block-wait condition variables
/// (`BLK_COMPL`/`BLK_TURN`). A naive "poll condition, then park" (safe on a
/// single CPU is a lost-wakeup under SMP: the completion IRQ can land on a
/// DIFFERENT cpu, so `run_completion_bottom_half` can observe
/// the completion and `wake_all()` an EMPTY `BLK_COMPL`/`BLK_TURN` in the gap
/// between this cpu's last poll and its `park()` call. With exactly one
/// outstanding turn/completion, no later wake ever arrives to rescue the
/// sleeper — a permanent lost-wakeup hang (B1426: `fstat` parked forever
/// under `SMP=4`, never under `SMP=1`).
///
/// Fix: register FIRST (`park()` — Sleeping + enqueued on `list`), THEN
/// evaluate `done`. A waker landing after registration finds us on the list
/// and flips us Runnable before `schedule()` can switch away (same guarantee
/// `park_interruptible_with_deadline` uses for signal-before-sleep). If `done`
/// is already true by the time we check, unregister without sleeping — the
/// `rt_sigtimedwait` park/recheck/`cancel_current_park` idiom. A nonzero
/// `deadline_ns` also arms the scheduler's timeout queue, so a lost device IRQ
/// cannot strand the waiter past the I/O deadline. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
#[track_caller]
pub(super) fn park_blk_checked(list: &WaitList, deadline_ns: u64, done: impl FnMut() -> bool) {
    if can_sleep() {
        // SAFETY: process context (can_sleep() ruled out IRQ-stack/idle), no
        // lock held; this shared timed predicate loop owns the publication.
        let _ = unsafe {
            sched::live::wait_event_uninterruptible_until(list, deadline_ns, now_ns, done)
        };
    } else {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(super) const IO_TIMEOUT_NS: u64 = 5_000_000_000;
#[cfg(not(target_os = "oxide-kernel"))]
pub(super) const IO_FALLBACK_SPINS: u64 = 50_000_000;

/// Error-only request completion trace. Kept behind `debug-boot` so normal
/// block I/O remains silent while a device-reported failure remains diagnosable.
#[cfg(feature = "debug-boot")]
pub(super) fn log_status_error(type_: u32, sector: u64, data_len: u32, status: u8) {
    klog::write_raw(b"[VBLK-STATUS] type=");
    klog::write_hex_u64(type_ as u64);
    klog::write_raw(b" sector=");
    klog::write_hex_u64(sector);
    klog::write_raw(b" bytes=");
    klog::write_hex_u64(data_len as u64);
    klog::write_raw(b" status=");
    klog::write_hex_u64(status as u64);
    klog::write_raw(b"\n");
}

/// Error-only synchronous submission trace. `stage` tells whether the
/// transport was already invalid or the posted request itself failed.
#[cfg(feature = "debug-boot")]
pub(super) fn log_submit_failure(
    stage: &[u8], type_: u32, sector: u64, data_len: u32, error: BlockError,
) {
    klog::write_raw(b"[VBLK-FAIL] stage=");
    klog::write_raw(stage);
    klog::write_raw(b" type=");
    klog::write_hex_u64(type_ as u64);
    klog::write_raw(b" sector=");
    klog::write_hex_u64(sector);
    klog::write_raw(b" bytes=");
    klog::write_hex_u64(data_len as u64);
    klog::write_raw(b" error=");
    klog::write_dec_u64(error as i32 as u64);
    klog::write_raw(b"\n");
}

/// Feature bits we ask the device for. `VIRTIO_BLK_F_FLUSH` is what makes
/// `VIRTIO_BLK_T_FLUSH` a legal request at all (Virtio 1.2 §5.2.6) and is in
/// the reference's requested feature set for exactly that reason.
/// Without it negotiated the device may answer every barrier `S_UNSUPP`, so a
/// journal commit that believes it fenced its writes has not.
///
/// `VIRTIO_BLK_F_MQ` is what makes `num_queues` in the device config meaningful
/// and licenses use of any virtqueue past index 0 (Virtio 1.2 §5.2.3/§5.2.4).
/// Without it the driver has exactly one request queue and no queue to poll
/// without an interrupt.
///
/// `VIRTIO_BLK_F_ZONED` is what makes the zoned characteristics block in the
/// device config meaningful and the zone commands legal at all. Asking for it
/// is also how a host-managed drive becomes REFUSABLE: without the bit the
/// device presents itself as flat, and a filesystem would place blocks the
/// drive rejects. Negotiating it is what lets the probe see the model byte.
const WANTED_FEATURES: u64 =
    virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_BLK_F_BLK_SIZE | virtio::VIRTIO_BLK_F_FLUSH
    | virtio::VIRTIO_BLK_F_MQ | virtio::VIRTIO_BLK_F_ZONED;

/// Requested transport feature mask. # C: O(1)
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Transport profile used for probe and thaw. # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    #[cfg(target_os = "oxide-kernel")]
    let completion_irq = Some(wake_completions as fn());
    #[cfg(not(target_os = "oxide-kernel"))]
    let completion_irq = None;
    virtio::VirtioTransportProfile::q0_device_cfg_poll_q1(wanted_features(), completion_irq)
}

/// `virtio_blk_req` is a type/reserved/sector tuple (Virtio 1.2 §5.2.6).
pub(super) const VIRTIO_BLK_REQUEST_HEADER_BYTES: usize = 16;
/// The device-written in-header that follows the request header. One status
/// byte for every request type but zone append, which prefixes the sector its
/// data landed at; the status is the last byte either way.
pub(super) const VIRTIO_BLK_MAX_IN_HEADER_BYTES: usize =
    virtio::blk::zoned::ZONE_APPEND_IN_HEADER_BYTES;
pub(super) const HDR_OFF: usize = 0;
pub(super) const STATUS_OFF: usize = HDR_OFF + VIRTIO_BLK_REQUEST_HEADER_BYTES;
/// Start payload on its own PMM page so header/status metadata can never
/// overlap a device data transfer.
pub(super) const DATA_OFF: usize = hal::PAGE_SIZE_BYTES as usize;
pub(super) const BOUNCE_BYTES: usize = DATA_OFF + blk::BOUNCE_DATA_BYTES;

/// Publish one request's CPU-written bounce allocation to the device before a
/// descriptor names it.  The x86 DMA contract is coherent; ARM still needs
/// the explicit clean that Linux's dma_map_single() performs for a
/// non-coherent device.
#[inline]
pub(super) fn clean_bounce_for_device(h: u64, bounce_pa: u64) {
    virtio::dma::clean_to_device(h.wrapping_add(bounce_pa), BOUNCE_BYTES);
}

/// Publish the descriptor and driver areas after writing a chain and its
/// avail entry.  The device owns these frames once avail.idx is visible.
#[inline]
pub(super) fn clean_queue_submission(h: u64, q: &BlkQueue) {
    virtio::dma::clean_to_device(
        h.wrapping_add(q.res.desc_pa), hal::PAGE_SIZE_BYTES as usize,
    );
    virtio::dma::clean_to_device(
        h.wrapping_add(q.res.driver_pa), hal::PAGE_SIZE_BYTES as usize,
    );
}

/// Smallest PMM buddy order that contains `bytes`, derived instead of tied to
/// a specific 4 KiB-page machine or a handwritten allocation size.
const fn allocation_order_for_bytes(bytes: usize) -> u8 {
    let pages = (bytes + hal::PAGE_SIZE_BYTES as usize - 1) / hal::PAGE_SIZE_BYTES as usize;
    let mut order = 0u8;
    let mut covered = 1usize;
    while covered < pages {
        covered <<= 1;
        order += 1;
    }
    order
}

pub(super) const BOUNCE_ORDER: u8 = allocation_order_for_bytes(BOUNCE_BYTES);
/// A read/write chain consumes header, payload, and status descriptors.
pub(super) const MAX_REQUEST_DESCRIPTORS: u16 = 3;

/// Descriptor heads that can be independently owned by outstanding requests.
/// Each head reserves a contiguous maximum-size chain in the split ring.
pub(super) fn request_heads(queue_size: u16) -> Vec<u16> {
    let count = queue_size / MAX_REQUEST_DESCRIPTORS;
    (0..count).map(|slot| slot * MAX_REQUEST_DESCRIPTORS).collect()
}

pub(super) static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);

pub(super) struct BlkRecord {
    pub(super) device_key: virtio::VirtioChildDeviceKey,
    pub(super) name: String,
    pub(super) state: Arc<BlkState>,
}

pub(super) static DEVICES: Spinlock<Vec<BlkRecord>, DriverLockClass> = Spinlock::new(Vec::new());

#[cfg(test)]
pub(super) fn child_key(bus: u8, device: u8, function: u8) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(
        (bus as u32) << 16 | (device as u32) << 8 | (function as u32),
    )
}

#[cfg(feature = "debug-boot")]
pub(super) fn key_raw(key: virtio::VirtioChildDeviceKey) -> u32 { key.raw() }

pub(super) fn same_device(rec: &BlkRecord, device_key: virtio::VirtioChildDeviceKey) -> bool {
    rec.device_key == device_key
}

pub struct BlkState {
    pub(super) bdf: pci::Bdf,
    pub(super) cfg_va: u64,
    /// The interrupt-driven request queue. Its completions raise the device
    /// interrupt, which raises the block softirq, which drains it.
    pub(super) requestq: BlkQueue,
    /// The interrupt-free request queue, when the device offered one to spare.
    /// No MSI-X vector is bound to it and its `avail.flags` carry
    /// `VRING_AVAIL_F_NO_INTERRUPT`, so its completions reach the driver only
    /// through a poll — that is the whole cost saving of a polled ring.
    pub(super) pollq: Option<BlkQueue>,
    pub(super) capacity: u64,
    pub(super) blk_size: u32,
    pub(super) serial: [u8; blk::BLK_SERIAL_LEN],
    pub(super) bounce_pa: u64,
    pub(super) bounce_dma: u64,
    /// Post-negotiation cache mode (Linux `virtblk_get_cache_mode` →
    /// `blk_queue_write_cache`). `false` = write-through: no volatile cache to
    /// fence, and `VIRTIO_BLK_T_FLUSH` must NOT go on the wire.
    pub(super) write_cache: bool,
    /// The drive's zone geometry when it is host-managed, `None` when it has
    /// no zones. A drive that claims zones this driver cannot honour is never
    /// attached at all, so this is never a downgraded `None`.
    pub(super) zoned: Option<virtio::blk::zoned::ZonedInfo>,
    pub(super) poisoned: core::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl BlkState {
    pub(crate) fn for_test_cfg(cfg_va: u64) -> Self {
        Self::for_test_cfg_with_poll_queue(cfg_va, false)
    }

    /// `with_poll_queue` builds the device the way a multiqueue device probes:
    /// a second, interrupt-free request queue beside the default one. # C: O(1)
    pub(crate) fn for_test_cfg_with_poll_queue(cfg_va: u64, with_poll_queue: bool) -> Self {
        Self {
            bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 },
            cfg_va,
            requestq: BlkQueue::new(unprogrammed_queue(0), 0, false),
            pollq: if with_poll_queue {
                Some(BlkQueue::new(unprogrammed_queue(virtio::POLL_QUEUE_INDEX), 0, true))
            } else {
                None
            },
            capacity: 8,
            blk_size: blk::VIRTIO_BLK_SECTOR_BYTES,
            serial: [0u8; blk::BLK_SERIAL_LEN],
            bounce_pa: 0,
            bounce_dma: 0,
            write_cache: true,
            zoned: None,
            poisoned: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The same device, host-managed with the given geometry. # C: O(1)
    pub(crate) fn for_test_zoned(zoned: virtio::blk::zoned::ZonedInfo, blk_size: u32) -> Self {
        let mut s = Self::for_test_cfg(0);
        s.zoned = Some(zoned);
        s.blk_size = blk_size;
        s.capacity = 1 << 20;
        s
    }

    /// Take the synchronous engine turn on every queue this device has.
    /// # C: O(queues)
    pub(crate) fn hold_inflight_for_tests(&self) {
        for q in self.queues() { q.lock().busy = true; }
    }

    pub(crate) fn release_inflight_for_tests(&self) {
        for q in self.queues() { q.lock().busy = false; }
    }

    /// Whether the queue a request with this `polled` flag would be issued on
    /// is the interrupt-free one. # C: O(1)
    pub(crate) fn queue_is_polled_for_tests(&self, polled: bool) -> bool {
        self.queue_for(polled).polled
    }

    /// # C: O(queues)
    pub(crate) fn queue_count_for_tests(&self) -> usize { self.queues().count() }

    /// # C: O(1)
    pub(crate) fn poll_queue_index_for_tests(&self) -> Option<u16> {
        self.pollq.as_ref().map(|q| q.res.index)
    }

    pub(crate) fn frozen_for_tests(&self) -> bool {
        self.poisoned.load(core::sync::atomic::Ordering::Acquire)
    }
}

pub(super) struct RingShadow {
    pub(super) avail_idx: u16,
    pub(super) used_seen: u16,
    pub(super) busy: bool,
    pub(super) free_heads: Vec<u16>,
    pub(super) pending: Vec<PendingRequest>,
    pub(super) deferred: Vec<DeferredRequest>,
}

/// One device-owned request. The DMA allocation remains live until the used
/// ring reports this descriptor head, so concurrent requests cannot alias
/// their headers, payloads, status bytes, or completion continuations.
pub(super) struct PendingRequest {
    pub(super) head: u16,
    pub(super) bounce_pa: u64,
    pub(super) bounce_dma: u64,
    pub(super) request: BlockRequest,
    pub(super) completion: BlockCompletion,
    pub(super) is_in: bool,
    pub(super) data_len: u32,
}

/// An accepted owned request waiting for a free descriptor chain. It retains
/// the caller's ownership and completion exactly as a hardware-posted request
/// does; the only difference is that no DMA allocation exists yet.
pub(super) struct DeferredRequest {
    pub(super) request: BlockRequest,
    /// Monotonic nanoseconds at which this request started waiting for a free
    /// descriptor chain. The dispatch order reads it to age out a request
    /// whose class keeps losing to a busier one.
    pub(super) queued_ns: u64,
    pub(super) completion: BlockCompletion,
    pub(super) type_: u32,
    pub(super) sector: u64,
    pub(super) is_in: bool,
    pub(super) is_flush: bool,
    pub(super) data_len: u32,
}

unsafe impl Send for BlkState {}
unsafe impl Sync for BlkState {}

#[derive(Copy, Clone)]
pub struct BlkInit {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub bdf: pci::Bdf,
    pub resources: virtio::VirtioResources,
    pub drv_features: u64,
}

#[derive(Copy, Clone)]
pub(super) struct BlkDeviceConfig {
    pub(super) capacity: u64,
    pub(super) blk_size: u32,
    /// Request queues the device advertises. Meaningful only under a
    /// negotiated `VIRTIO_BLK_F_MQ`; one otherwise.
    pub(super) num_queues: u16,
    /// What the zoned characteristics say, before the logical block size has
    /// been validated against them.
    pub(super) zoned: virtio::blk::zoned::ZonedProbe,
}
