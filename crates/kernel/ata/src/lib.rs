//! ATA device identity ownership and its Linux `HDIO_GET_IDENTITY` ABI page.

#![no_std]

extern crate alloc;
#[cfg(test)] extern crate std;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};

/// Linux `HDIO_GET_IDENTITY` command number. # C: O(1)
pub const HDIO_GET_IDENTITY: u64 = 0x030d;
/// One ATA IDENTIFY DEVICE page, in bytes. # C: O(1)
pub const IDENTIFY_BYTES: usize = 512;

const SERIAL_OFFSET: usize = 10 * 2;
const SERIAL_BYTES: usize = 20;
const FIRMWARE_OFFSET: usize = 23 * 2;
const FIRMWARE_BYTES: usize = 8;
const MODEL_OFFSET: usize = 27 * 2;
const MODEL_BYTES: usize = 40;

/// A live ATA endpoint that can supply the IDENTIFY page it retained during
/// probe. The transport owns command execution; this owner only exports the
/// shared Linux ABI view. # C: O(1)
pub trait Device: Send + Sync {
    /// `None` after the device has departed or been shut down. # C: O(1)
    fn identify_page(&self) -> Option<[u8; IDENTIFY_BYTES]>;
}

struct TargetRecord { dev_t: u32, device: Arc<dyn Device> }
static TARGETS: Spinlock<Vec<TargetRecord>, Devices> = Spinlock::new(Vec::new());

/// A resolved live ATA endpoint. # C: O(1)
#[derive(Clone)]
pub struct IdentityTarget { device: Arc<dyn Device> }

impl IdentityTarget {
    /// Return the Linux `struct hd_driveid` page, including the reference's
    /// string-field byte-order conversion. # C: O(1)
    pub fn hdio_identity(&self) -> Option<[u8; IDENTIFY_BYTES]> {
        let mut page = self.device.identify_page()?;
        normalize_identity(&mut page);
        Some(page)
    }
}

/// Resolve the ATA device attached to a canonical block `dev_t`. # C: O(devices)
pub fn identity_target(dev_t: u32) -> Option<IdentityTarget> {
    TARGETS.lock().iter().find(|entry| entry.dev_t == dev_t)
        .map(|entry| IdentityTarget { device: Arc::clone(&entry.device) })
}

/// Register or replace the live ATA owner for a newly published block node.
/// Failure is allocation-only so callers can roll the block publication back.
/// # C: O(devices)
pub fn register_target(dev_t: u32, device: Arc<dyn Device>) -> bool {
    let mut targets = TARGETS.lock();
    if let Some(existing) = targets.iter_mut().find(|entry| entry.dev_t == dev_t) {
        existing.device = device;
        return true;
    }
    if targets.try_reserve(1).is_err() { return false; }
    targets.push(TargetRecord { dev_t, device });
    true
}

/// Drop a departed or shut-down ATA endpoint from the canonical lookup.
/// # C: O(devices)
pub fn unregister_target(dev_t: u32) -> bool {
    let mut targets = TARGETS.lock();
    let Some(index) = targets.iter().position(|entry| entry.dev_t == dev_t) else {
        return false;
    };
    targets.remove(index);
    true
}

/// Convert only ATA's word-swapped serial, firmware, and product strings.
/// Linux copies the native IDENTIFY page first, then overwrites exactly these
/// three fields through `ata_id_string`; every other byte remains untouched.
/// # C: O(1)
fn normalize_identity(page: &mut [u8; IDENTIFY_BYTES]) {
    for (offset, bytes) in [
        (SERIAL_OFFSET, SERIAL_BYTES),
        (FIRMWARE_OFFSET, FIRMWARE_BYTES),
        (MODEL_OFFSET, MODEL_BYTES),
    ] {
        for word in page[offset..offset + bytes].chunks_exact_mut(2) { word.swap(0, 1); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_ata_string(page: &mut [u8; 512], offset: usize, text: &[u8]) {
        assert_eq!(text.len() % 2, 0);
        for (index, pair) in text.chunks_exact(2).enumerate() {
            page[offset + index * 2] = pair[1];
            page[offset + index * 2 + 1] = pair[0];
        }
    }

    #[test]
    fn hdio_identity_swaps_only_the_ata_string_fields() {
        let mut page = [0xa5; 512];
        write_ata_string(&mut page, 20, b"SN-42               ");
        write_ata_string(&mut page, 46, b"FW1.0   ");
        write_ata_string(&mut page, 54, b"Oxide ATA disk                          ");
        let raw = page;

        normalize_identity(&mut page);

        assert_eq!(&page[..20], &raw[..20]);
        assert_eq!(&page[20..40], b"SN-42               ");
        assert_eq!(&page[40..46], &raw[40..46]);
        assert_eq!(&page[46..54], b"FW1.0   ");
        assert_eq!(&page[54..94], b"Oxide ATA disk                          ");
        assert_eq!(&page[94..], &raw[94..]);
    }

    struct Fixture { page: [u8; IDENTIFY_BYTES] }

    impl Device for Fixture {
        fn identify_page(&self) -> Option<[u8; IDENTIFY_BYTES]> { Some(self.page) }
    }

    #[test]
    fn published_dev_t_owns_one_live_ata_identity_source() {
        const DEV_T: u32 = 0x0008_00f0;
        let _ = unregister_target(DEV_T);
        let mut page = [0u8; IDENTIFY_BYTES];
        write_ata_string(&mut page, SERIAL_OFFSET, b"ATA-IDENTITY-0001   ");
        let device: Arc<dyn Device> = Arc::new(Fixture { page });

        assert!(register_target(DEV_T, device));
        let target = identity_target(DEV_T).expect("registered ATA target");
        assert_eq!(&target.hdio_identity().expect("live page")[SERIAL_OFFSET..SERIAL_OFFSET + SERIAL_BYTES], b"ATA-IDENTITY-0001   ");
        assert!(unregister_target(DEV_T));
        assert!(identity_target(DEV_T).is_none());
    }
}
