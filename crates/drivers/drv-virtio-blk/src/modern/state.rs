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

pub(super) const HDR_OFF: usize = 0x000;
pub(super) const STATUS_OFF: usize = 0x010;
pub(super) const DATA_OFF: usize = 0x1000;
pub(super) const BOUNCE_BYTES: usize = DATA_OFF + blk::BOUNCE_DATA_BYTES;
pub(super) const BOUNCE_ORDER: u8 = 6;

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
pub(super) fn key_bus(key: virtio::VirtioChildDeviceKey) -> u8 { ((key.raw() >> 16) & 0xff) as u8 }
#[cfg(feature = "debug-boot")]
pub(super) fn key_device(key: virtio::VirtioChildDeviceKey) -> u8 { ((key.raw() >> 8) & 0xff) as u8 }
#[cfg(feature = "debug-boot")]
pub(super) fn key_function(key: virtio::VirtioChildDeviceKey) -> u8 { (key.raw() & 0xff) as u8 }

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

pub(super) struct RingShadow {
    pub(super) avail_idx: u16,
    pub(super) used_seen: u16,
    pub(super) busy: bool,
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
