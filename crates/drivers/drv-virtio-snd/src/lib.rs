// Modern virtio-snd (sound) runtime driver. virtio-snd (PCI modern
// device-id 0x1059, virtio device class 25) exposes four virtqueues:
// CONTROLQ(0), EVENTQ(1), TXQ(2), RXQ(3) per docs/58§2. This module owns
// the CONTROLQ request/response engine and the device-config-driven probe
// (query the PCM stream table via VIRTIO_SND_R_PCM_INFO).
//
// The boot probe in `pci_boot::virtio_drv` performs the generic virtio
// bring-up (reset → ACK/DRIVER → feature negotiate → FEATURES_OK → q0
// desc/driver/device PA program + DRIVER_OK), harvests virtio_snd_config,
// then hands the persistent CONTROLQ ring addresses + notify VA + config
// counts here via `install`. TXQ/RXQ playback rings land with PR-C.
//
// Arch-neutral: every op is MMIO (notify_cap window) + HHDM (ring +
// control scratch frame), mirroring drv-virtio-rng / drv-virtio-blk.

#![no_std]

use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as DriverLockClass};
use virtio::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

// Wire constants — virtio 1.2 §5.14 / docs/58§4.
/// CONTROLQ request: query the PCM stream table.
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
/// Control response status: success.
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
/// PCM stream direction: guest→device (playback).
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
/// PCM stream direction: device→guest (capture).
pub const VIRTIO_SND_D_INPUT: u8 = 1;

/// sizeof(virtio_snd_pcm_info) on the wire (docs/58§4): hda_fn_nid(4)
/// features(4) formats(8) rates(8) direction(1) channels_min(1)
/// channels_max(1) padding[5] = 32 bytes. `direction` sits at byte 24.
const PCM_INFO_SIZE: usize = 32;
const PCM_INFO_DIR_OFF: usize = 24;
/// sizeof(virtio_snd_query_info): hdr(4) start_id(4) count(4) size(4).
const QUERY_INFO_SIZE: usize = 16;
/// sizeof(virtio_snd_hdr) — the status prefix in every control response.
const SND_HDR_SIZE: usize = 4;

/// Bounded spin budget for one CONTROLQ completion. QEMU retires control
/// requests near-instantly; generous headroom, matching the rng/blk style.
const CTL_POLL_BUDGET: u32 = 2_000_000;

/// Control scratch-frame layout: request at offset 0, response at 0x200
/// (leaves 0x200 for any request, 0xE00 for the response array).
const REQ_OFF: u64 = 0;
const RESP_OFF: u64 = 0x200;

/// Persistent per-device CONTROLQ engine. PAs/VA reference the q0 ring the
/// boot probe already programmed. One in-flight control request at a time,
/// serialised by the `Spinlock` around the whole request body.
struct Ctx {
    q0_desc_pa:   u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    q0_notify_va: u64,
    q0_size:      u16,
    hhdm:         u64,
    /// One 4 KiB frame split into request + response windows for control
    /// requests. Allocated once at install.
    scratch_pa:   u64,
    /// Driver-side avail.idx shadow (next ring slot to publish).
    avail_idx:    u16,
    /// virtio_snd_config (docs/58§4): jacks/streams/chmaps/controls.
    jacks:    u32,
    streams:  u32,
    chmaps:   u32,
    controls: u32,
}

// SAFETY justification: Ctx holds raw PAs/VAs into HHDM/MMIO stable for
// the device lifetime; all access is funneled through the CONTROLQ
// Spinlock, so cross-CPU sharing is sound.
static CTX: Spinlock<Option<Ctx>, DriverLockClass> = Spinlock::new(None);

/// Boot-probe → driver handoff: the CONTROLQ ring the boot path programmed
/// plus the harvested virtio_snd_config counts.
pub struct SndInstall {
    pub q0_desc_pa:   u64,
    pub q0_driver_pa: u64,
    pub q0_device_pa: u64,
    pub q0_notify_va: u64,
    pub q0_size:      u16,
    pub hhdm:         u64,
    pub jacks:    u32,
    pub streams:  u32,
    pub chmaps:   u32,
    pub controls: u32,
}

/// Probe result handed back for the boot line: total streams + the
/// OUTPUT/INPUT split discovered via VIRTIO_SND_R_PCM_INFO.
pub struct SndProbe {
    pub streams: u32,
    pub out:     u32,
    pub input:   u32,
}

/// True once a virtio-snd device has been brought up + installed.
/// # C: O(1)
pub fn present() -> bool { CTX.lock().is_some() }

/// Snapshot of the harvested virtio_snd_config: `(jacks, streams, chmaps,
/// controls)`. None until a device is installed. Backs the ALSA card /
/// jack / control-element sizing under `/dev/snd/*`.
/// # C: O(1)
pub fn config() -> Option<(u32, u32, u32, u32)> {
    CTX.lock().as_ref().map(|c| (c.jacks, c.streams, c.chmaps, c.controls))
}

/// Install the CONTROLQ engine for one virtio-snd device. Called once from
/// `pci_boot::virtio_drv` after DRIVER_OK + q0 setup + config harvest.
/// Allocates the control scratch frame, then queries the PCM stream table
/// and returns the OUTPUT/INPUT stream split. Returns None if a ring PA /
/// notify VA / HHDM is missing or no scratch frame is available.
/// # C: O(streams) — one CONTROLQ round-trip
pub fn install(p: SndInstall) -> Option<SndProbe> {
    if p.hhdm == 0 || p.q0_desc_pa == 0 || p.q0_driver_pa == 0
        || p.q0_device_pa == 0 || p.q0_notify_va == 0
    {
        return None;
    }
    let scratch_pa = pmm::setup::alloc_one_frame()?;
    // Zero the scratch frame for deterministic request/response state.
    let va = p.hhdm.wrapping_add(scratch_pa) as *mut u8;
    // SAFETY: HHDM covers all RAM the PMM hands out; this freshly-allocated
    // 4 KiB frame is owned exclusively by this driver; aligned u8 stores
    // span only the page we just allocated.
    unsafe { for i in 0..0x1000usize { core::ptr::write_volatile(va.add(i), 0); } }
    // Seed avail.idx from the live used.idx so the first request waits for a
    // fresh completion rather than mistaking a stale idx for its own.
    let used = p.hhdm.wrapping_add(p.q0_device_pa) as *const u16;
    // SAFETY: HHDM-mapped queue-0 used ring programmed by the boot probe;
    // aligned u16 load of used.idx at u16 offset 1 in the device-owned frame.
    let used_seen = unsafe { core::ptr::read_volatile(used.add(1)) };
    *CTX.lock() = Some(Ctx {
        q0_desc_pa: p.q0_desc_pa, q0_driver_pa: p.q0_driver_pa,
        q0_device_pa: p.q0_device_pa, q0_notify_va: p.q0_notify_va,
        q0_size: p.q0_size, hhdm: p.hhdm, scratch_pa,
        avail_idx: used_seen,
        jacks: p.jacks, streams: p.streams,
        chmaps: p.chmaps, controls: p.controls,
    });
    let (out, input) = pcm_info_scan();
    Some(SndProbe { streams: p.streams, out, input })
}

/// Query the PCM stream table (VIRTIO_SND_R_PCM_INFO, start_id=0,
/// count=streams) and tally the OUTPUT/INPUT split by each entry's
/// `direction` byte. Returns (out, input); (0,0) on transport/status error.
/// # C: O(streams)
fn pcm_info_scan() -> (u32, u32) {
    let mut g = CTX.lock();
    let ctx = match g.as_mut() { Some(c) => c, None => return (0, 0) };
    let count = ctx.streams;
    if count == 0 { return (0, 0); }
    let h = ctx.hhdm;

    // Build virtio_snd_query_info at REQ_OFF.
    let req = h.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    // SAFETY: HHDM-mapped scratch frame owned by this driver; four aligned
    // u32 stores within the request window build the query header.
    unsafe {
        core::ptr::write_volatile(req.add(0), VIRTIO_SND_R_PCM_INFO);
        core::ptr::write_volatile(req.add(1), 0);                     // start_id
        core::ptr::write_volatile(req.add(2), count);                 // count
        core::ptr::write_volatile(req.add(3), PCM_INFO_SIZE as u32);  // size
    }

    // Response = virtio_snd_hdr status + count × virtio_snd_pcm_info, capped
    // to the scratch frame.
    let want = SND_HDR_SIZE + count as usize * PCM_INFO_SIZE;
    let resp_len = want.min(0x1000 - RESP_OFF as usize);
    let status = match submit_ctl(ctx, QUERY_INFO_SIZE, resp_len) {
        Some(s) => s, None => return (0, 0),
    };
    if status != VIRTIO_SND_S_OK { return (0, 0); }

    // Tally direction across the entries that fit in the response window.
    let entries = ((resp_len - SND_HDR_SIZE) / PCM_INFO_SIZE).min(count as usize);
    let base = h.wrapping_add(ctx.scratch_pa + RESP_OFF + SND_HDR_SIZE as u64) as *const u8;
    let (mut out, mut input) = (0u32, 0u32);
    for i in 0..entries {
        // SAFETY: HHDM-mapped response window the device just filled;
        // bounded u8 read of the direction byte of entry `i` (< resp_len).
        let dir = unsafe { core::ptr::read_volatile(base.add(i * PCM_INFO_SIZE + PCM_INFO_DIR_OFF)) };
        if dir == VIRTIO_SND_D_INPUT { input += 1; } else { out += 1; }
    }
    (out, input)
}

/// Submit one CONTROLQ request/response pair: a 2-descriptor chain (req RO
/// + resp WO) onto q0, kick the device, poll the used ring for completion,
/// and return the response's leading virtio_snd_hdr status le32. The
/// request is read from scratch+REQ_OFF (`req_len` bytes); the device
/// writes `resp_len` bytes into scratch+RESP_OFF. None on poll timeout.
/// # C: O(CTL_POLL_BUDGET) per call
fn submit_ctl(ctx: &mut Ctx, req_len: usize, resp_len: usize) -> Option<u32> {
    let h = ctx.hhdm;

    // Descriptor chain head at index 0: [0]=req (RO, NEXT→1), [1]=resp (WO).
    // Each virtq desc = 16 bytes = 2 u64: addr; then len|flags<<32|next<<48.
    let desc = h.wrapping_add(ctx.q0_desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped queue-0 descriptor table programmed by the boot
    // probe; four aligned u64 stores into the driver-owned ring frame build
    // a 2-descriptor chain over our owned scratch request/response windows.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.scratch_pa + REQ_OFF);
        let d0 = (req_len as u64)
               | ((VRING_DESC_F_NEXT as u64) << 32)
               | (1u64 << 48);
        core::ptr::write_volatile(desc.add(1), d0);
        core::ptr::write_volatile(desc.add(2), ctx.scratch_pa + RESP_OFF);
        let d1 = (resp_len as u64) | ((VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc.add(3), d1);
    }

    // Publish to the avail ring: ring[slot]=0 (head desc index), bump idx.
    let qsz = if ctx.q0_size == 0 { 1u16 } else { ctx.q0_size };
    let slot = (ctx.avail_idx % qsz) as usize;
    let avail = h.wrapping_add(ctx.q0_driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped queue-0 avail ring; u16 stores at ring(2+slot)/
    // idx(1) within the driver-owned frame; slot bounded by q0_size; the
    // Release fence publishes the descriptor writes before the idx bump.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.avail_idx);
        ctx.avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);

    // Kick the device via the CONTROLQ notify register (queue index 0).
    // SAFETY: notify VA is the Device-attr MMIO window mapped by the boot
    // probe; an aligned u16 store of queue index 0 is the spec-defined kick.
    unsafe { core::ptr::write_volatile(ctx.q0_notify_va as *mut u16, 0u16); }

    // Poll the used ring until used.idx reaches our target (or budget).
    let used = h.wrapping_add(ctx.q0_device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped queue-0 used ring; aligned u16 load of used.idx
        // at u16 offset 1 within the device-owned frame.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { break; }
        if polls >= CTL_POLL_BUDGET { return None; }
        polls += 1;
        core::hint::spin_loop();
    }

    // Leading virtio_snd_hdr status (le32) of the response window.
    let st = h.wrapping_add(ctx.scratch_pa + RESP_OFF) as *const u32;
    // SAFETY: HHDM-mapped response window the device just wrote; aligned u32
    // load of the status header at RESP_OFF.
    Some(unsafe { core::ptr::read_volatile(st) })
}
