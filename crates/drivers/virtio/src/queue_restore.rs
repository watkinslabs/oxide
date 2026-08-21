//! Reprogram retained split-virtqueue storage after a device reset.

use crate::queue_cfg::{
    CFG_QUEUE_DESC, CFG_QUEUE_DEVICE, CFG_QUEUE_DRIVER, CFG_QUEUE_ENABLE,
    CFG_QUEUE_MSIX, CFG_QUEUE_NOTIFY, CFG_QUEUE_SELECT, CFG_QUEUE_SIZE,
};
use crate::VirtQueueResource;

const QUEUE_ENABLE_READY: u16 = 1;
const QUEUE_ADDR_HIGH_OFF: u64 = 4;

/// Reinstall one retained queue without allocating a second ring owner.
///
/// The caller has reset the device, retained the three DMA mappings, and
/// zeroed all three ring pages. The saved resource is the driver's sole queue
/// identity; a device that no longer accepts its size, notification offset,
/// or interrupt vector is a different transport and is refused.
/// # C: O(1)
pub fn restore_queue(
    cfg_va: u64,
    resource: VirtQueueResource,
    desc_dma: u64,
    driver_dma: u64,
    device_dma: u64,
    msix_vector: u16,
) -> bool {
    if cfg_va == 0 || !resource.is_runtime_valid()
        || desc_dma == 0 || driver_dma == 0 || device_dma == 0
    {
        return false;
    }
    let w16 = |off: u64, value: u16| {
        // SAFETY: cfg_va is the retained Device-attr common-cfg mapping and
        // every supplied offset names its aligned u16 queue field.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u16, value); }
    };
    let r16 = |off: u64| {
        // SAFETY: cfg_va is the retained Device-attr common-cfg mapping and
        // every supplied offset names its aligned u16 queue field.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u16) }
    };
    let w64 = |off: u64, value: u64| {
        // SAFETY: cfg_va is the retained Device-attr common-cfg mapping; the
        // queue address fields are aligned adjacent low/high u32 registers.
        unsafe {
            core::ptr::write_volatile((cfg_va + off) as *mut u32, value as u32);
            core::ptr::write_volatile(
                (cfg_va + off + QUEUE_ADDR_HIGH_OFF) as *mut u32,
                (value >> 32) as u32,
            );
        }
    };

    w16(CFG_QUEUE_SELECT, resource.index);
    let offered_size = r16(CFG_QUEUE_SIZE);
    if offered_size < resource.size {
        w16(CFG_QUEUE_SELECT, 0);
        return false;
    }
    w16(CFG_QUEUE_SIZE, resource.size);
    if r16(CFG_QUEUE_SIZE) != resource.size
        || r16(CFG_QUEUE_NOTIFY) != resource.notify_off
    {
        w16(CFG_QUEUE_SELECT, 0);
        return false;
    }
    w16(CFG_QUEUE_MSIX, msix_vector);
    if r16(CFG_QUEUE_MSIX) != msix_vector {
        w16(CFG_QUEUE_SELECT, 0);
        return false;
    }
    w64(CFG_QUEUE_DESC, desc_dma);
    w64(CFG_QUEUE_DRIVER, driver_dma);
    w64(CFG_QUEUE_DEVICE, device_dma);
    w16(CFG_QUEUE_ENABLE, QUEUE_ENABLE_READY);
    let enabled = r16(CFG_QUEUE_ENABLE) == QUEUE_ENABLE_READY;
    w16(CFG_QUEUE_SELECT, 0);
    enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_queue_reinstalls_exact_addresses_and_vector() {
        let mut cfg = [0u64; 16];
        let base = cfg.as_mut_ptr() as u64;
        let resource = VirtQueueResource::new(
            0, 128, 0x1000, 0x2000, 0x3000, 0x8000, 0,
        );
        // SAFETY: cfg is a live, aligned test-owned common-cfg byte array and
        // this writes the u16 queue-size field within that array.
        unsafe {
            core::ptr::write_volatile((base + CFG_QUEUE_SIZE) as *mut u16, 256);
        }
        assert!(restore_queue(
            base, resource, 0x1_0000_1000, 0x2_0000_2000, 0x3_0000_3000, 7,
        ));
        // SAFETY: restore_queue wrote only aligned fields within the same live
        // test-owned common-cfg array, which remains borrowed for these reads.
        unsafe {
            assert_eq!(core::ptr::read_volatile((base + CFG_QUEUE_MSIX) as *const u16), 7);
            assert_eq!(core::ptr::read_volatile((base + CFG_QUEUE_DESC) as *const u64), 0x1_0000_1000);
            assert_eq!(core::ptr::read_volatile((base + CFG_QUEUE_DRIVER) as *const u64), 0x2_0000_2000);
            assert_eq!(core::ptr::read_volatile((base + CFG_QUEUE_DEVICE) as *const u64), 0x3_0000_3000);
            assert_eq!(core::ptr::read_volatile((base + CFG_QUEUE_ENABLE) as *const u16), 1);
        }
    }
}
