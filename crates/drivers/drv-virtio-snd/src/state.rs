use super::*;

pub(super) struct Ctx {
    pub device_key: DeviceKey,
    pub controlq: virtio::VirtQueueResource,
    pub hhdm: u64,
    pub cfg_va: u64,
    pub scratch_pa: u64,
    pub avail_idx: u16,
    pub eventq: Option<virtio::VirtQueueResource>,
    pub event_buf_pa: u64,
    pub event_last_used: u16,
    pub event_avail_idx: u16,
    pub event_drained: u64,
    pub event_last_raw: u64,
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
    pub controls: u32,
    pub out_stream: Option<u32>,
    pub out_formats: u64,
    pub out_rates: u64,
    pub out_ch_min: u8,
    pub out_ch_max: u8,
    pub txq: Option<virtio::VirtQueueResource>,
    pub tx_avail_idx: u16,
    pub tx_buf_pa: u64,
    pub tx_scratch_pa: u64,
    pub pcm_state: PcmState,
    pub cfg_rate: u8,
    pub cfg_format: u8,
    pub cfg_channels: u8,
    pub cfg_period_bytes: u32,
    pub in_stream: Option<u32>,
    pub in_formats: u64,
    pub in_rates: u64,
    pub in_ch_min: u8,
    pub in_ch_max: u8,
    pub rxq: Option<virtio::VirtQueueResource>,
    pub rx_avail_idx: u16,
    pub rx_buf_pa: u64,
    pub rx_scratch_pa: u64,
    pub cap_state: PcmState,
    pub cap_rate: u8,
    pub cap_format: u8,
    pub cap_channels: u8,
    pub cap_period_bytes: u32,
}

#[derive(PartialEq, Clone, Copy)]
pub enum PcmState { Idle, Configured, Prepared, Running }

pub(super) static CTX: Spinlock<Vec<Ctx>, DriverLockClass> = Spinlock::new(Vec::new());
pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static LAST_EVENT: AtomicU64 = AtomicU64::new(0);

pub struct SndInstall {
    pub device_key: DeviceKey,
    pub resources: virtio::VirtioResources,
}

#[derive(Clone, Copy)]
pub(super) struct SndDeviceConfig {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
    pub controls: u32,
}

pub struct SndProbe {
    pub streams: u32,
    pub out: u32,
    pub input: u32,
}

pub(super) struct SndProbeFrames {
    pub scratch_pa: u64,
    pub event_buf_pa: u64,
    pub tx_buf_pa: u64,
    pub tx_scratch_pa: u64,
    pub rx_buf_pa: u64,
    pub rx_scratch_pa: u64,
    owned: bool,
}

impl SndProbeFrames {
    pub fn alloc(need_tx: bool, need_rx: bool) -> Option<Self> {
        let mut frames = Self {
            scratch_pa: 0,
            event_buf_pa: 0,
            tx_buf_pa: 0,
            tx_scratch_pa: 0,
            rx_buf_pa: 0,
            rx_scratch_pa: 0,
            owned: true,
        };
        frames.scratch_pa = pmm::setup::alloc_one_frame()?;
        frames.event_buf_pa = pmm::setup::alloc_one_frame()?;
        if need_tx {
            frames.tx_buf_pa = pmm::setup::alloc_one_frame()?;
            frames.tx_scratch_pa = pmm::setup::alloc_one_frame()?;
        }
        if need_rx {
            frames.rx_buf_pa = pmm::setup::alloc_one_frame()?;
            frames.rx_scratch_pa = pmm::setup::alloc_one_frame()?;
        }
        Some(frames)
    }

    pub fn all(&self) -> [u64; 6] {
        [
            self.scratch_pa,
            self.event_buf_pa,
            self.tx_buf_pa,
            self.tx_scratch_pa,
            self.rx_buf_pa,
            self.rx_scratch_pa,
        ]
    }

    pub fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for SndProbeFrames {
    fn drop(&mut self) {
        if self.owned {
            for pa in self.all() {
                free_frame(pa);
            }
        }
    }
}

pub(super) struct SoundCardReservation {
    owner: u32,
    active: bool,
}

impl SoundCardReservation {
    pub fn reserve(owner: u32) -> Option<Self> {
        if !sound::reserve_card(owner) {
            return None;
        }
        Some(Self { owner, active: true })
    }

    pub fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for SoundCardReservation {
    fn drop(&mut self) {
        if self.active {
            let _ = sound::cancel_card_reservation(self.owner);
        }
    }
}

pub(super) fn remove_ctx(device_key: DeviceKey) -> Option<(Ctx, bool)> {
    let mut guard = CTX.lock();
    let idx = guard.iter().position(|ctx| ctx.device_key == device_key)?;
    let ctx = guard.remove(idx);
    let empty_after = guard.is_empty();
    Some((ctx, empty_after))
}

pub(super) fn active_ctx_mut(ctxs: &mut [Ctx]) -> Option<&mut Ctx> {
    let owner = sound::owner()?;
    active_ctx_mut_for(ctxs, owner)
}

pub(super) fn active_ctx(ctxs: &[Ctx]) -> Option<&Ctx> {
    let owner = sound::owner()?;
    active_ctx_for(ctxs, owner)
}

pub(super) fn active_ctx_mut_for(ctxs: &mut [Ctx], owner: u32) -> Option<&mut Ctx> {
    ctxs.iter_mut().find(|ctx| sound_owner(ctx.device_key) == owner)
}

pub(super) fn active_ctx_for(ctxs: &[Ctx], owner: u32) -> Option<&Ctx> {
    ctxs.iter().find(|ctx| sound_owner(ctx.device_key) == owner)
}

pub(super) fn free_frame(pa: u64) {
    if pa != 0 {
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}
