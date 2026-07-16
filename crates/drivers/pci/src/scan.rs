use alloc::vec::Vec;

use crate::{Bdf, ConfigSpaceReader, PciDevice};

const PCI_MAX_BUSES: u16 = 256;
const PCI_DEVS_PER_BUS: u8 = 32;
const PCI_FUNCS_PER_DEV: u8 = 8;
const HEADER_TYPE_MULTIFUNCTION: u8 = 0x80;
const PCI_BRIDGE_CLASS: u8 = 0x06;
const PCI_BRIDGE_SUBCLASS_PCI: u8 = 0x04;
const PCI_SECONDARY_BUS_OFF: u8 = 0x18;
const PCI_PRIMARY_BUS_SHIFT: u32 = 0;
const PCI_SECONDARY_BUS_SHIFT: u32 = 8;
const PCI_SUBORDINATE_BUS_SHIFT: u32 = 16;

/// Walk the PCI topology from root bus 0 through discovered PCI-PCI bridge
/// windows. Returns every present reachable function and skips multi-function
/// probing past function 0 unless the header_type MF bit is set.
/// # C: O(256 x 32 x 8) - single sweep at boot
pub fn enumerate<R: ConfigSpaceReader>(r: &R) -> Vec<PciDevice> {
    enumerate_buses(r, PCI_MAX_BUSES)
}

/// Like `enumerate` but caps reachable bus numbers at `n_buses`. Used by
/// callers where the per-arch `ConfigSpaceReader` only maps part of ECAM.
/// # C: O(n_buses x 32 x 8)
pub fn enumerate_buses<R: ConfigSpaceReader>(r: &R, n_buses: u16) -> Vec<PciDevice> {
    let mut out = Vec::new();
    let cap = n_buses.min(PCI_MAX_BUSES);
    if cap == 0 {
        return out;
    }

    let mut seen = [false; PCI_MAX_BUSES as usize];
    let mut pending = Vec::new();
    pending.push(0u8);
    while let Some(bus) = pending.pop() {
        if bus as u16 >= cap || seen[bus as usize] {
            continue;
        }
        seen[bus as usize] = true;
        scan_bus(r, bus, cap, &mut seen, &mut pending, &mut out);
    }
    out
}

fn scan_bus<R: ConfigSpaceReader>(
    r: &R,
    bus: u8,
    cap: u16,
    seen: &mut [bool; PCI_MAX_BUSES as usize],
    pending: &mut Vec<u8>,
    out: &mut Vec<PciDevice>,
) {
    for dev in 0u8..PCI_DEVS_PER_BUS {
        for func in 0u8..PCI_FUNCS_PER_DEV {
            let bdf = Bdf { bus, device: dev, function: func };
            let d_opt = PciDevice::from_config(r, bdf);
            if let Some(d) = d_opt {
                enqueue_bridge_buses(r, d, cap, seen, pending);
                out.push(d);
                if func == 0 && (d.header_type & HEADER_TYPE_MULTIFUNCTION) == 0 {
                    break;
                }
            } else if func == 0 {
                break;
            }
        }
    }
}

fn enqueue_bridge_buses<R: ConfigSpaceReader>(
    r: &R,
    d: PciDevice,
    cap: u16,
    seen: &[bool; PCI_MAX_BUSES as usize],
    pending: &mut Vec<u8>,
) {
    if d.class_code != PCI_BRIDGE_CLASS || d.subclass != PCI_BRIDGE_SUBCLASS_PCI {
        return;
    }
    let buses = r.read32(d.bdf, PCI_SECONDARY_BUS_OFF);
    let primary = ((buses >> PCI_PRIMARY_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
                let secondary = ((buses >> PCI_SECONDARY_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
                let subordinate = ((buses >> PCI_SUBORDINATE_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
    if secondary == 0 || secondary <= primary || subordinate < secondary {
        return;
    }
    let last = subordinate.min((cap - 1) as u8);
    for bus in secondary..=last {
        if !seen[bus as usize] {
            pending.push(bus);
        }
    }
}
