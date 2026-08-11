//! xHCI capability-register geometry shared by controller bring-up and tests.

/// PCI class code for an xHCI USB host controller. # C: O(1)
pub const XHCI_CLASS24: u32 = 0x0c_03_30;
pub const CAPLENGTH: u64 = 0x00;
pub const HCSPARAMS1: u64 = 0x04;
/// Capability Parameters 1 includes the context-size flag. # C: O(1)
pub const HCCPARAMS1: u64 = 0x10;
pub const DBOFF: u64 = 0x14;
pub const RTSOFF: u64 = 0x18;
pub const CAP_REGS_MIN: u64 = 0x20;
pub const REGISTER_ALIGN: u64 = 4;
pub const RUNTIME_INTR0: u64 = 0x20;
pub const DOORBELL_HOST: u8 = 0;

/// Validated controller register-file locations and hardware limits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub operational: u64,
    pub runtime: u64,
    pub doorbells: u64,
    pub max_slots: u8,
    pub max_interrupters: u16,
    pub max_ports: u8,
    pub context_bytes: u8,
}

/// Decode an xHCI capability block and prove later MMIO accesses remain in BAR0.
/// # C: O(1)
pub fn geometry(bar_bytes: u64, caplength: u8, hcsparams1: u32, hccparams1: u32, dboff: u32, rtsoff: u32) -> Option<Geometry> {
    let operational = caplength as u64;
    let runtime = (rtsoff as u64) & !0x1f;
    let doorbells = (dboff as u64) & !0x3;
    let max_slots = hcsparams1 as u8;
    let max_interrupters = ((hcsparams1 >> 8) & 0x07ff) as u16;
    let max_ports = (hcsparams1 >> 24) as u8;
    // Linux `HCC_64BYTE_CONTEXT`: only bit 2 selects the context stride.
    let context_bytes = if hccparams1 & (1 << 2) != 0 { 64 } else { 32 };
    if bar_bytes < CAP_REGS_MIN || operational < CAP_REGS_MIN
        || operational & (REGISTER_ALIGN - 1) != 0 || runtime < operational || runtime & 0x1f != 0
        || doorbells < operational || doorbells & (REGISTER_ALIGN - 1) != 0
        || max_slots == 0 || max_interrupters == 0 || max_ports == 0
        || runtime.checked_add(RUNTIME_INTR0 + 0x20)? > bar_bytes || doorbells.checked_add(4)? > bar_bytes
    { return None; }
    Some(Geometry { operational, runtime, doorbells, max_slots, max_interrupters, max_ports, context_bytes })
}

/// Address of one interrupter register set after capability validation. # C: O(1)
pub fn interrupter_offset(g: Geometry, index: u16) -> Option<u64> {
    if index >= g.max_interrupters { return None; }
    g.runtime.checked_add(RUNTIME_INTR0)?.checked_add((index as u64).checked_mul(0x20)?)
}

/// Address of a device or host doorbell after capability validation. # C: O(1)
pub fn doorbell_offset(g: Geometry, index: u8) -> Option<u64> {
    if index > g.max_slots { return None; }
    g.doorbells.checked_add((index as u64).checked_mul(4)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_geometry_preserves_hardware_offsets_and_limits() {
        let hcs = 64 | (8 << 8) | (12 << 24);
        let g = geometry(0x4000, 0x40, hcs, 1 << 2, 0x2000, 0x1000).unwrap();
        assert_eq!((g.operational, g.runtime, g.doorbells, g.max_slots, g.context_bytes), (0x40, 0x1000, 0x2000, 64, 64));
        assert_eq!(interrupter_offset(g, 7), Some(0x1100));
        assert_eq!(doorbell_offset(g, 64), Some(0x2100));
    }

    #[test]
    fn malformed_or_out_of_aperture_controller_is_rejected() {
        let hcs = 1 | (1 << 8) | (1 << 24);
        assert!(geometry(0x1000, 0x1f, hcs, 0, 0x200, 0x400).is_none());
        assert!(geometry(0x1000, 0x20, hcs, 0, 0x200, 0x1000).is_none());
        assert!(geometry(0x1000, 0x20, hcs, 0, 0x1000, 0x400).is_none());
        assert!(geometry(0x1000, 0x20, 0, 0, 0x200, 0x400).is_none());
    }

    #[test]
    fn device_doorbells_follow_the_valid_slot_range() {
        let g = Geometry { operational: 0x40, runtime: 0x1000, doorbells: 0x2000, max_slots: 4, max_interrupters: 1, max_ports: 1, context_bytes: 32 };
        assert_eq!(doorbell_offset(g, 1), Some(0x2004));
        assert_eq!(doorbell_offset(g, 4), Some(0x2010));
    }
}
