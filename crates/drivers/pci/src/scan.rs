use alloc::vec::Vec;

use crate::{Bdf, ConfigSpaceReader, PciDevice};

/// Walk the PCI bus: 256 buses x 32 devices x 8 functions.
/// Returns every present device. Skips multi-function probing past function 0
/// unless the header_type's MF bit (0x80) is set.
/// # C: O(256 x 32 x 8) - single sweep at boot
pub fn enumerate<R: ConfigSpaceReader>(r: &R) -> Vec<PciDevice> {
    enumerate_buses(r, 256)
}

/// Like `enumerate` but caps the bus scan at `n_buses`. Used by callers where
/// the per-arch `ConfigSpaceReader` only has the first N buses device-mapped.
/// # C: O(n_buses x 32 x 8)
pub fn enumerate_buses<R: ConfigSpaceReader>(r: &R, n_buses: u16) -> Vec<PciDevice> {
    let mut out = Vec::new();
    let cap = (n_buses as u32).min(256);
    for bus in 0u32..cap {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let bdf = Bdf {
                    bus: bus as u8,
                    device: dev,
                    function: func,
                };
                let d_opt = PciDevice::from_config(r, bdf);
                if let Some(d) = d_opt {
                    out.push(d);
                    if func == 0 && (d.header_type & 0x80) == 0 {
                        break;
                    }
                } else if func == 0 {
                    break;
                }
            }
        }
    }
    out
}
