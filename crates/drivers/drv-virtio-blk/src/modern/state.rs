use super::*;

/// Virtio device ID for block devices.
pub const VIRTIO_ID_BLOCK: u16 = 2;

/// Driver-model identity for virtio-blk child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-blk", VIRTIO_ID_BLOCK);

#[cfg(target_os = "oxide-kernel")]
pub(super) static BLK_COMPL: WaitList = WaitList::new();

#[cfg(target_os = "oxide-kernel")]
pub fn wake_completions() {
    softirq::raise(softirq::Slot::BlockIo);
}

/// Process virtio-blk completion notifications outside hard-IRQ context.
///
/// The current request engine has one owner at a time, but completion
/// observation and task wakeup still belong in the block softirq. Keeping the
/// IRQ side to a bit raise is required before the engine can safely grow to
/// multiple outstanding descriptor chains.
#[cfg(target_os = "oxide-kernel")]
pub(super) fn run_completion_bottom_half() {
    let devices: Vec<Arc<BlkState>> = DEVICES.lock().iter().map(|record| record.state.clone()).collect();
    for device in devices {
        device.drain_owned_completions();
    }
    BLK_COMPL.wake_all();
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

/// Save the current IRQ mask and ENABLE IRQs for a block-I/O wait, returning
/// the prior state token for [`irq_restore`]. The kernel runs syscalls/faults
/// IF=0; a synchronous block wait can spin+park for up to `IO_TIMEOUT_NS`, and
/// with IRQs masked that whole window freezes the timer tick, preemption, and
/// every wakeup (the completion softirq that would `BLK_COMPL.wake_all` a parked
/// waiter cannot even run). Linux services demand-paging / read / write I/O with
/// IRQs enabled; this mirrors `local_irq_enable` for the wait. SAFE only because
/// the wait holds no plain lock an IRQ/softirq path also takes (audited).
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
pub(super) fn irq_save_enable() -> u64 {
    use sync::IrqGate;
    // SAFETY: bounded block-I/O wait; paired with irq_restore on every exit.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::save_enable() }
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::save_enable() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Restore the IRQ mask saved by [`irq_save_enable`] (re-mask if the caller
/// entered IF=0). # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
pub(super) fn irq_restore(token: u64) {
    use sync::IrqGate;
    // SAFETY: token came from the matching irq_save_enable on this CPU/task.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::restore(token) }
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::restore(token) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = token; }
}

#[cfg(target_os = "oxide-kernel")]
#[inline]
fn can_sleep() -> bool {
    if sched::live::global().is_none() { return false; }
    match sched::live::current() {
        Some(t) => !matches!(t.sched_class(), sched::SchedClass::Idle),
        None => false,
    }
}

#[cfg(target_os = "oxide-kernel")]
#[inline]
pub(super) fn park_blk() {
    if can_sleep() {
        unsafe {
            BLK_COMPL.park();
            sched::live::schedule::schedule();
        }
    } else {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(super) const IO_TIMEOUT_NS: u64 = 5_000_000_000;
#[cfg(target_os = "oxide-kernel")]
pub(super) const IO_SPIN_BUDGET: u64 = 200_000;
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

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_BLK_F_BLK_SIZE;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    #[cfg(target_os = "oxide-kernel")]
    let completion_irq = Some(wake_completions as fn());
    #[cfg(not(target_os = "oxide-kernel"))]
    let completion_irq = None;
    virtio::VirtioTransportProfile::q0_device_cfg(wanted_features(), completion_irq)
}

/// `virtio_blk_req` is a type/reserved/sector tuple (Virtio 1.2 §5.2.6).
pub(super) const VIRTIO_BLK_REQUEST_HEADER_BYTES: usize = 16;
/// One device-written status byte follows the request header.
pub(super) const VIRTIO_BLK_REQUEST_STATUS_BYTES: usize = 1;
pub(super) const HDR_OFF: usize = 0;
pub(super) const STATUS_OFF: usize = HDR_OFF + VIRTIO_BLK_REQUEST_HEADER_BYTES;
/// Start payload on its own PMM page so header/status metadata can never
/// overlap a device data transfer.
pub(super) const DATA_OFF: usize = hal::PAGE_SIZE_BYTES as usize;
pub(super) const BOUNCE_BYTES: usize = DATA_OFF + blk::BOUNCE_DATA_BYTES;

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
    pub(super) cfg_va: u64,
    pub(super) requestq: virtio::VirtQueueResource,
    pub(super) capacity: u64,
    pub(super) blk_size: u32,
    pub(super) serial: [u8; blk::BLK_SERIAL_LEN],
    pub(super) bounce_pa: u64,
    pub(super) inflight: Spinlock<RingShadow, DriverLockClass>,
    pub(super) poisoned: core::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl BlkState {
    pub(crate) fn for_test_cfg(cfg_va: u64) -> Self {
        Self {
            cfg_va,
            requestq: virtio::VirtQueueResource {
                index: 0,
                size: 0,
                desc_pa: 0,
                driver_pa: 0,
                device_pa: 0,
                notify_va: 0,
                notify_off: 0,
            },
            capacity: 8,
            blk_size: blk::VIRTIO_BLK_SECTOR_BYTES,
            serial: [0u8; blk::BLK_SERIAL_LEN],
            bounce_pa: 0,
            inflight: Spinlock::new(RingShadow {
                avail_idx: 0, used_seen: 0, busy: false, free_heads: Vec::new(), pending: Vec::new(), deferred: Vec::new(),
            }),
            poisoned: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn hold_inflight_for_tests(&self) {
        self.inflight.lock().busy = true;
    }

    pub(crate) fn release_inflight_for_tests(&self) {
        self.inflight.lock().busy = false;
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
    pub resources: virtio::VirtioResources,
    pub drv_features: u64,
}

#[derive(Copy, Clone)]
pub(super) struct BlkDeviceConfig {
    pub(super) capacity: u64,
    pub(super) blk_size: u32,
}
