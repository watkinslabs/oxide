//! Modern virtio common-cfg register protocol helpers.
//!
//! These helpers own the device-status, feature-negotiation, and queue-size
//! register sequence. Concrete transports still own mapping the common-cfg
//! window and allocating/programming queue memory.

// common-cfg field offsets, Virtio 1.2 §4.1.4.3. u16-precise stores are
// required for queue fields; QEMU dispatches common-cfg writes by address.
pub const CFG_QUEUE_SELECT: u64 = 0x16; // u16
pub const CFG_QUEUE_SIZE: u64 = 0x18; // u16/read
pub const CFG_DEVICE_FEATURE_SELECT: u64 = 0x00; // u32
pub const CFG_DEVICE_FEATURE: u64 = 0x04; // u32
pub const CFG_DRIVER_FEATURE_SELECT: u64 = 0x08; // u32
pub const CFG_DRIVER_FEATURE: u64 = 0x0C; // u32
pub const CFG_MSIX_CONFIG_NUMQ: u64 = 0x10; // u16 msix_config + u16 num_queues
pub const CFG_DEVICE_STATUS: u64 = 0x14; // u8

#[derive(Clone, Copy)]
pub struct FeatureNegotiation {
    pub dev_features: u64,
    pub drv_features: u64,
    pub post_status: u32,
    pub features_ok: bool,
    pub msix_cfg: u16,
    pub num_queues: u16,
}

pub struct CommonCfgBringup<Q> {
    pub negotiated: FeatureNegotiation,
    pub queues: [(u16, u16); crate::MAX_RESOURCE_QUEUES],
    pub queues_len: usize,
    pub programmed_queues: Option<Q>,
    pub final_status: u8,
}

/// Execute the common virtio device reset + feature negotiation sequence on
/// the modern common-cfg window.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn negotiate_features(cfg_va: u64, wanted_features: u64) -> FeatureNegotiation {
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 load of a common-cfg register.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 store of a common-cfg register.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };
    let w8 = |off: u64, v: u8| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status
        // is the u8 field at CFG_DEVICE_STATUS.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u8, v); }
    };

    // Virtio 1.2 §3.1.1 / §4.1.4.3.2: after writing 0 to reset, the driver MUST
    // re-read `device_status` until it reads 0 before proceeding. A single
    // discarded read let a device still mid-DMA on a warm re-probe return stale
    // feature bits or fail FEATURES_OK — a flaky-only-on-reboot init hazard.
    w8(CFG_DEVICE_STATUS, 0);
    let mut reset_ok = false;
    for _ in 0..RESET_POLL_SPINS {
        if (r32(CFG_DEVICE_STATUS) & 0xFF) == 0 { reset_ok = true; break; }
        core::hint::spin_loop();
    }
    if !reset_ok {
        return FeatureNegotiation {
            dev_features: 0, drv_features: 0,
            post_status: crate::VIRTIO_STATUS_FAILED as u32,
            features_ok: false, msix_cfg: 0, num_queues: 0,
        };
    }
    w8(CFG_DEVICE_STATUS, crate::VIRTIO_STATUS_ACKNOWLEDGE);
    w8(
        CFG_DEVICE_STATUS,
        crate::VIRTIO_STATUS_ACKNOWLEDGE | crate::VIRTIO_STATUS_DRIVER,
    );

    w32(CFG_DEVICE_FEATURE_SELECT, 0);
    let dev_feat_lo = r32(CFG_DEVICE_FEATURE);
    w32(CFG_DEVICE_FEATURE_SELECT, 1);
    let dev_feat_hi = r32(CFG_DEVICE_FEATURE);
    let dev_features = ((dev_feat_hi as u64) << 32) | dev_feat_lo as u64;
    let drv_features = dev_features & wanted_features;

    w32(CFG_DRIVER_FEATURE_SELECT, 1);
    w32(CFG_DRIVER_FEATURE, (drv_features >> 32) as u32);
    w32(CFG_DRIVER_FEATURE_SELECT, 0);
    w32(CFG_DRIVER_FEATURE, (drv_features & 0xFFFF_FFFF) as u32);
    w8(
        CFG_DEVICE_STATUS,
        crate::VIRTIO_STATUS_ACKNOWLEDGE
            | crate::VIRTIO_STATUS_DRIVER
            | crate::VIRTIO_STATUS_FEATURES_OK,
    );

    let post_status = r32(CFG_DEVICE_STATUS) & 0xFF;
    let features_ok = post_status & crate::VIRTIO_STATUS_FEATURES_OK as u32 != 0;
    let w_msix_nq = r32(CFG_MSIX_CONFIG_NUMQ);
    FeatureNegotiation {
        dev_features,
        drv_features,
        post_status,
        features_ok,
        msix_cfg: (w_msix_nq & 0xFFFF) as u16,
        num_queues: (w_msix_nq >> 16) as u16,
    }
}

/// Scan modern common-cfg queue sizes into a compact `(index, size)` table.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(min(num_queues, MAX_RESOURCE_QUEUES))
pub fn scan_queue_sizes(
    cfg_va: u64,
    num_queues: u16,
) -> ([(u16, u16); crate::MAX_RESOURCE_QUEUES], usize) {
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; aligned
        // u32 load of a common-cfg register.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w16 = |off: u64, v: u16| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; queue
        // selection is the u16 field at CFG_QUEUE_SELECT.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, v); }
    };

    let mut queues = [(0u16, 0u16); crate::MAX_RESOURCE_QUEUES];
    let mut queues_len = 0usize;
    let cap = if num_queues == 0 || num_queues as usize > crate::MAX_RESOURCE_QUEUES {
        crate::MAX_RESOURCE_QUEUES
    } else {
        num_queues as usize
    };
    for qi in 0..cap {
        let qi = qi as u16;
        w16(CFG_QUEUE_SELECT, qi);
        let queue_size = (r32(CFG_QUEUE_SIZE) & 0xFFFF) as u16;
        queues[queues_len] = (qi, queue_size);
        queues_len += 1;
        if queue_size == 0 {
            break;
        }
    }
    (queues, queues_len)
}

/// Execute the common modern virtio common-cfg bring-up state machine.
///
/// Shared virtio owns reset, feature negotiation, queue-size discovery, and
/// the final DRIVER_OK/FAILED status transition. The concrete transport owns
/// queue allocation, IRQ/vector binding, and transport-specific unwind inside
/// `program_queues`.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(min(num_queues, MAX_RESOURCE_QUEUES) + program_queues)
pub fn bring_up_common_cfg<Q, F>(
    cfg_va: u64,
    wanted_features: u64,
    program_queues: F,
) -> CommonCfgBringup<Q>
where
    F: FnOnce() -> Option<Q>,
{
    let negotiated = negotiate_features(cfg_va, wanted_features);
    let (queues, queues_len) = scan_queue_sizes(cfg_va, negotiated.num_queues);
    let programmed_queues = if negotiated.features_ok {
        program_queues()
    } else {
        None
    };
    let final_status =
        complete_driver_status(cfg_va, negotiated.features_ok, programmed_queues.is_some());

    CommonCfgBringup {
        negotiated,
        queues,
        queues_len,
        programmed_queues,
        final_status,
    }
}

/// Read the modern common-cfg device status byte.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn read_status(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::read_volatile((cfg_va + CFG_DEVICE_STATUS) as *const u8) }
}

/// Bounded spin budget for `reset_device`'s status-readback poll. Real
/// hardware and QEMU's emulated backends complete a reset near-instantly;
/// this only guards against a genuinely wedged device, not normal latency.
const RESET_POLL_SPINS: u32 = 1_000_000;

/// Reset a modern virtio device through the common-cfg status register.
/// Per virtio 1.2 §4.1.4.3.1/§2.4: the driver MUST write 0 to device status
/// AND wait for a readback of status==0 before treating the device as
/// quiescent — writing 0 alone does not guarantee any in-flight DMA the
/// device backend was mid-way through has actually stopped. A caller that
/// frees a buffer right after the write-only version (no readback) races
/// the device's own reset completion: if the backend is still mid-DMA into
/// that buffer, the freed physical page becomes live again under whatever
/// the allocator hands it to next — a genuine device-side wild write into
/// unrelated kernel memory (found this session tracing `drv-virtio-blk`'s
/// `cancel_owned_requests`, which frees DMA bounce buffers on exactly this
/// unconfirmed assumption; state.md).
/// Returns `true` once status readback confirmed 0 (device quiesced),
/// `false` if `cfg_va` is absent or the poll exhausted without a
/// confirming readback. Callers that free DMA memory after a reset MUST
/// check this: on `false`, the device's actual quiescence is unconfirmed,
/// and freeing is unsafe (see this fn's doc comment) — leak the buffer
/// instead (matches the "consume off the free list, leave to its real
/// owner" philosophy `mm-pmm`'s own allocator-integrity retry already
/// uses for the same in-use-frame hazard).
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(RESET_POLL_SPINS) worst case
#[must_use]
pub fn reset_device(cfg_va: u64) -> bool {
    if cfg_va == 0 {
        return false;
    }
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe { core::ptr::write_volatile((cfg_va + CFG_DEVICE_STATUS) as *mut u8, 0u8); }
    for _ in 0..RESET_POLL_SPINS {
        if read_status(cfg_va) == 0 { return true; }
        core::hint::spin_loop();
    }
    false
}

/// Publish FAILED when the transport cannot complete feature or mandatory
/// queue bring-up.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn set_failed(cfg_va: u64) -> u8 {
    let status = read_status(cfg_va) | crate::VIRTIO_STATUS_FAILED;
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe {
        core::ptr::write_volatile((cfg_va + CFG_DEVICE_STATUS) as *mut u8, status);
    }
    read_status(cfg_va)
}

/// Publish DRIVER_OK after features and queues are fully programmed.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn set_driver_ok(cfg_va: u64) -> u8 {
    // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; status is
    // the u8 field at CFG_DEVICE_STATUS.
    unsafe {
        core::ptr::write_volatile(
            (cfg_va + CFG_DEVICE_STATUS) as *mut u8,
            crate::VIRTIO_STATUS_ACKNOWLEDGE
                | crate::VIRTIO_STATUS_DRIVER
                | crate::VIRTIO_STATUS_FEATURES_OK
                | crate::VIRTIO_STATUS_DRIVER_OK,
        );
    }
    read_status(cfg_va)
}

/// Complete modern virtio bring-up after queue programming.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1)
pub fn complete_driver_status(cfg_va: u64, features_ok: bool, queues_programmed: bool) -> u8 {
    if !features_ok {
        set_failed(cfg_va)
    } else if queues_programmed {
        set_driver_ok(cfg_va)
    } else {
        set_failed(cfg_va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct Regs([u32; 16]);

    #[test]
    fn common_cfg_bringup_programs_queues_before_driver_ok() {
        let mut regs = Regs([0; 16]);
        regs.0[(CFG_DEVICE_FEATURE / 4) as usize] = crate::VIRTIO_F_VERSION_1 as u32;
        regs.0[(CFG_MSIX_CONFIG_NUMQ / 4) as usize] = (2u32 << 16) | 7;
        regs.0[(CFG_QUEUE_SIZE / 4) as usize] = 8;

        let cfg_va = regs.0.as_mut_ptr() as u64;
        let mut programmed = false;
        let bringup = bring_up_common_cfg(cfg_va, crate::VIRTIO_F_VERSION_1, || {
            programmed = true;
            Some(0x55u32)
        });

        assert!(programmed);
        assert!(bringup.negotiated.features_ok);
        assert_eq!(bringup.negotiated.msix_cfg, 7);
        assert_eq!(bringup.negotiated.num_queues, 2);
        assert_eq!(bringup.queues_len, 2);
        assert_eq!(bringup.programmed_queues, Some(0x55));
        assert_eq!(
            bringup.final_status,
            crate::VIRTIO_STATUS_ACKNOWLEDGE
                | crate::VIRTIO_STATUS_DRIVER
                | crate::VIRTIO_STATUS_FEATURES_OK
                | crate::VIRTIO_STATUS_DRIVER_OK
        );
    }

    #[test]
    fn common_cfg_bringup_marks_failed_when_queue_programming_fails() {
        let mut regs = Regs([0; 16]);
        regs.0[(CFG_DEVICE_FEATURE / 4) as usize] = crate::VIRTIO_F_VERSION_1 as u32;
        regs.0[(CFG_MSIX_CONFIG_NUMQ / 4) as usize] = 1u32 << 16;
        regs.0[(CFG_QUEUE_SIZE / 4) as usize] = 8;

        let cfg_va = regs.0.as_mut_ptr() as u64;
        let bringup = bring_up_common_cfg::<u32, _>(cfg_va, crate::VIRTIO_F_VERSION_1, || None);

        assert!(bringup.negotiated.features_ok);
        assert_eq!(bringup.programmed_queues, None);
        assert_eq!(
            bringup.final_status & crate::VIRTIO_STATUS_FAILED,
            crate::VIRTIO_STATUS_FAILED
        );
    }
}
