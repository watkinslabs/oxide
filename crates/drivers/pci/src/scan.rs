use alloc::vec::Vec;

use crate::{Bdf, ConfigSpaceReader, PciDevice};

use crate::layout::{BRIDGE_CLASS, BRIDGE_SUBCLASS_PCI, DEVS_PER_BUS, FUNCS_PER_DEV,
    HEADER_TYPE_MULTIFUNCTION, MAX_BUSES, PRIMARY_BUS_SHIFT, SECONDARY_BUS_OFF,
    SECONDARY_BUS_SHIFT, SUBORDINATE_BUS_SHIFT};

/// Walk the PCI topology from root bus 0 through discovered PCI-PCI bridge
/// windows. Returns every present reachable function and skips multi-function
/// probing past function 0 unless the header_type MF bit is set.
/// # C: O(256 x 32 x 8) - single sweep at boot
pub fn enumerate<R: ConfigSpaceReader>(r: &R) -> Vec<PciDevice> {
    enumerate_segment_buses(r, 0, 0, MAX_BUSES)
}

/// Like `enumerate` but caps reachable bus numbers at `n_buses`. Used by
/// callers where the per-arch `ConfigSpaceReader` only maps part of ECAM.
/// # C: O(n_buses x 32 x 8)
pub fn enumerate_buses<R: ConfigSpaceReader>(r: &R, n_buses: u16) -> Vec<PciDevice> {
    enumerate_segment_buses(r, 0, 0, n_buses)
}

/// Enumerate one PCI segment through its MCFG bus window. `bus_start` is the
/// first bus covered by the ECAM allocation; `n_buses` is its span.
/// # C: O(n_buses x 32 x 8)
pub fn enumerate_segment_buses<R: ConfigSpaceReader>(
    r: &R, segment: u16, bus_start: u8, n_buses: u16,
) -> Vec<PciDevice> {
    let mut out = Vec::new();
    let cap = n_buses.min(MAX_BUSES);
    if cap == 0 {
        return out;
    }

    let mut seen = [false; MAX_BUSES as usize];
    let mut pending = Vec::new();
    pending.push(bus_start);
    while let Some(bus) = pending.pop() {
        let relative = match bus.checked_sub(bus_start) { Some(v) => v, None => continue };
        if relative as u16 >= cap || seen[bus as usize] {
            continue;
        }
        seen[bus as usize] = true;
        scan_bus(r, segment, bus, bus_start, cap, &mut seen, &mut pending, &mut out);
    }
    out
}

fn scan_bus<R: ConfigSpaceReader>(
    r: &R,
    segment: u16,
    bus: u8,
    bus_start: u8,
    cap: u16,
    seen: &mut [bool; MAX_BUSES as usize],
    pending: &mut Vec<u8>,
    out: &mut Vec<PciDevice>,
) {
    for dev in 0u8..DEVS_PER_BUS {
        for func in 0u8..FUNCS_PER_DEV {
            let bdf = Bdf { segment, bus, device: dev, function: func };
            let d_opt = PciDevice::from_config(r, bdf);
            if let Some(d) = d_opt {
                enqueue_bridge_buses(r, d, bus_start, cap, seen, pending);
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
    bus_start: u8,
    cap: u16,
    seen: &[bool; MAX_BUSES as usize],
    pending: &mut Vec<u8>,
) {
    if d.class_code != BRIDGE_CLASS || d.subclass != BRIDGE_SUBCLASS_PCI {
        return;
    }
    let buses = r.read32(d.bdf, SECONDARY_BUS_OFF);
    let primary = ((buses >> PRIMARY_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
                let secondary = ((buses >> SECONDARY_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
                let subordinate = ((buses >> SUBORDINATE_BUS_SHIFT) & crate::layout::BUS_MASK) as u8;
    if secondary == 0 || secondary <= primary || subordinate < secondary {
        return;
    }
    let last = subordinate.min(bus_start.saturating_add((cap - 1) as u8));
    for bus in secondary..=last {
        if !seen[bus as usize] {
            pending.push(bus);
        }
    }
}
