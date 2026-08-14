use crate::{capabilities, clear_bus_master, disable_msi, msix_control_value, Bdf,
    ConfigSpaceReader, CAP_ID_MSI, CAP_ID_MSIX};

/// Mask PCI message delivery and revoke DMA before the model releases a
/// function. Drivers have already stopped their hardware at this point; this
/// closes the remaining generic transport gates before the function vanishes
/// from the live PCI registry.
/// # C: O(N_caps)
pub fn quiesce_function<R: ConfigSpaceReader>(r: &R, bdf: Bdf) {
    for cap in capabilities(r, bdf).iter() {
        match cap.id {
            CAP_ID_MSI => { let _ = disable_msi(r, bdf, cap.cfg_off); }
            CAP_ID_MSIX => {
                let off = cap.cfg_off & 0xFC;
                let old = r.read32(bdf, off);
                let new = msix_control_value(old, false);
                if new != old {
                    r.write32(bdf, off, new);
                    let _ = r.read32(bdf, off);
                }
            }
            _ => {}
        }
    }
    let _ = clear_bus_master(r, bdf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct Config { words: Mutex<HashMap<u8, u32>>, writes: Mutex<std::vec::Vec<u8>> }
    impl ConfigSpaceReader for Config {
        fn read32(&self, _: Bdf, off: u8) -> u32 {
            self.words.lock().unwrap().get(&off).copied().unwrap_or(u32::MAX)
        }
        fn write32(&self, _: Bdf, off: u8, val: u32) {
            self.words.lock().unwrap().insert(off, val);
            self.writes.lock().unwrap().push(off);
        }
    }

    const BDF: Bdf = Bdf { segment: 0, bus: 0, device: 1, function: 0 };

    #[test]
    fn quiesce_masks_messages_before_revoking_bus_master() {
        let r = Config { words: Mutex::new(HashMap::from([
            (0x04, 0x1234_0007), (0x34, 0x40),
            (0x40, 0x44 << 8 | u32::from(CAP_ID_MSI) | (0x13 << 16)),
            (0x44, u32::from(CAP_ID_MSIX) | (0xc002 << 16)),
        ])), writes: Mutex::new(std::vec::Vec::new()) };

        quiesce_function(&r, BDF);

        assert_eq!(r.read32(BDF, 0x40) & crate::MSI_ENABLE, 0);
        assert_eq!(r.read32(BDF, 0x44) & crate::MSIX_ENABLE, 0);
        assert_ne!(r.read32(BDF, 0x44) & crate::MSIX_FUNCTION_MASK, 0);
        assert_eq!(r.read32(BDF, 0x04), 0x1234_0003);
        assert_eq!(&*r.writes.lock().unwrap(), &[0x40, 0x44, 0x04]);
    }
}
