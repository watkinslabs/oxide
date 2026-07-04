// Generalized modern virtio-pci virtqueue setup, split out of
// `virtio_drv` so that file stays under the 1000-line cap (docs/08§7)
// and so every virtqueue is programmed uniformly (Virtio 1.2 §4.1.4.3
// virtio_pci_common_cfg), the way the Linux virtio core does — not q0/q1
// hand-coded per device. virtio-snd (4 queues: controlq0/eventq1/txq2/
// rxq3) and any future multi-queue device program q2/q3 by calling
// `program_queue` with the queue index.

// common-cfg field offsets, Virtio 1.2 §4.1.4.3. u16-precise stores per
// F59-09: QEMU's `virtio_pci_common_write` dispatches by `switch(addr)`,
// so a 4-byte store at a sub-field addr only triggers the field at that
// addr and silently drops the rest. queue_select / queue_msix_vector /
// queue_enable MUST be u16 stores at their exact offsets.
const CFG_QUEUE_SELECT: u64 = 0x16; // u16
const CFG_QUEUE_SIZE:   u64 = 0x18; // u16 (read)
const CFG_QUEUE_MSIX:   u64 = 0x1A; // u16
const CFG_QUEUE_ENABLE: u64 = 0x1C; // u16
const CFG_QUEUE_NOTIFY: u64 = 0x1E; // u16 (read: queue_notify_off)
const CFG_QUEUE_DESC:   u64 = 0x20; // le64
const CFG_QUEUE_DRIVER: u64 = 0x28; // le64
const CFG_QUEUE_DEVICE: u64 = 0x30; // le64

/// Programmed virtqueue: the three ring PAs handed to the device, the
/// per-queue `queue_notify_off`, and the negotiated `queue_size`.
#[derive(Clone, Copy)]
pub(super) struct QueueRing {
    pub(super) desc_pa:    u64,
    pub(super) driver_pa:  u64,
    pub(super) device_pa:  u64,
    pub(super) notify_off: u16,
    pub(super) size:       u16,
}

pub(super) struct ProgrammedQueues {
    pub(super) q0: QueueRing,
    extra: [Option<QueueRing>; virtio::MAX_RESOURCE_QUEUES],
}

impl ProgrammedQueues {
    /// Return a planned extra queue by index. Queue 0 is intentionally not
    /// exposed through this helper; callers use `q0` for the mandatory queue.
    /// # C: O(1)
    pub(super) const fn extra_queue(&self, index: u16) -> Option<QueueRing> {
        let index = index as usize;
        if index < virtio::MAX_RESOURCE_QUEUES {
            self.extra[index]
        } else {
            None
        }
    }
}

/// Program mandatory queue 0 and every requested extra queue through the same
/// common-cfg queue protocol. Extra queue failures are non-fatal here, matching
/// the old staged probe behavior; child probes validate the queues they
/// require before publishing runtime state.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(N_extra) queue programs
pub(super) fn program_queue_set(
    cfg_va: u64,
    hhdm: u64,
    q0_msix_vec: u16,
    extra_plans: &[Option<virtio::VirtioQueuePlan>],
) -> Option<ProgrammedQueues> {
    let q0 = program_queue(cfg_va, 0, q0_msix_vec, hhdm)?;
    let mut extra = [None; virtio::MAX_RESOURCE_QUEUES];
    for plan in extra_plans.iter().copied().flatten() {
        let index = plan.index as usize;
        if index >= virtio::MAX_RESOURCE_QUEUES {
            continue;
        }
        extra[index] = program_queue(cfg_va, plan.index, plan.msix_vec, hhdm);
    }
    Some(ProgrammedQueues { q0, extra })
}

/// Program virtqueue `qi` on the modern common-cfg window at `cfg_va`:
/// select the queue, read its `queue_size` (0 → queue absent, returns
/// None), allocate + zero the three ring frames via `hhdm`, write the
/// ring PAs, bind `msix_vec` (0xFFFF = VIRTIO_MSI_NO_VECTOR for
/// poll-only queues), set queue_enable=1, and capture `queue_notify_off`.
/// Restores queue_select=0 on return so later q0-state reads are correct.
/// Virtio 1.2 §3.1.1 / §4.1.4.3.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked;
/// `cfg_va` is the Device-attr-mapped virtio_pci_common_cfg window.
/// # C: O(1) — 3 frame allocs + a fixed number of MMIO stores
pub(super) fn program_queue(cfg_va: u64, qi: u16, msix_vec: u16, hhdm: u64) -> Option<QueueRing> {
    let w16 = |off: u64, v: u16| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; per
        // Virtio 1.2 §4.1.4.3 the field at `off` is u16-aligned within it.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: cfg_va common-cfg window; queue_desc/driver/device le64
        // fields are written as the two u32 halves at `off`/`off+4`.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    let r16 = |off: u64| -> u16 {
        // SAFETY: cfg_va common-cfg window; aligned u16 load of the
        // selected queue's field at `off`.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u16) }
    };

    // Select qi and read its negotiated queue_size. 0 = the device has no
    // such queue (Virtio 1.2 §4.1.4.3.2) — nothing to program.
    w16(CFG_QUEUE_SELECT, qi);
    let size = r16(CFG_QUEUE_SIZE);
    if size == 0 { return None; }

    let desc_pa   = pmm::setup::alloc_raw_frame()?;
    let driver_pa = pmm::setup::alloc_raw_frame()?;
    let device_pa = pmm::setup::alloc_raw_frame()?;

    // Zero the 3 ring frames via HHDM BEFORE queue_enable so the device
    // sees deterministic ring state — PMM doesn't guarantee zero-init.
    if hhdm != 0 {
        for &pa in &[desc_pa, driver_pa, device_pa] {
            let va = hhdm.wrapping_add(pa) as *mut u64;
            // SAFETY: HHDM covers all RAM PMM hands out; single-CPU
            // pre-init; we own these freshly-allocated frames; aligned
            // u64 stores stay within the 4 KiB page.
            unsafe {
                for i in 0..(0x1000 / 8) { core::ptr::write_volatile(va.add(i), 0); }
            }
        }
    }

    // Re-select qi (defensive) and program the ring layout. notify_off is
    // captured while qi is selected — the correct per-queue value.
    w16(CFG_QUEUE_SELECT, qi);
    let notify_off = r16(CFG_QUEUE_NOTIFY);
    w16(CFG_QUEUE_MSIX, msix_vec);
    w32(CFG_QUEUE_DESC,        (desc_pa   & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DESC + 4,    (desc_pa   >> 32)         as u32);
    w32(CFG_QUEUE_DRIVER,      (driver_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DRIVER + 4,  (driver_pa >> 32)         as u32);
    w32(CFG_QUEUE_DEVICE,      (device_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DEVICE + 4,  (device_pa >> 32)         as u32);
    w16(CFG_QUEUE_ENABLE, 1);
    // Restore queue_select=0 so subsequent reads in the kick path see q0.
    w16(CFG_QUEUE_SELECT, 0);

    Some(QueueRing { desc_pa, driver_pa, device_pa, notify_off, size })
}
