//! xHCI operational/runtime register sequencing.

use crate::regs::Geometry;

/// Operational USBCMD register. # C: O(1)
pub const USBCMD: u64 = 0x00;
/// Operational USBSTS register. # C: O(1)
pub const USBSTS: u64 = 0x04;
/// Command Ring Control Register. # C: O(1)
pub const CRCR: u64 = 0x18;
/// Device Context Base Address Array Pointer. # C: O(1)
pub const DCBAAP: u64 = 0x30;
/// Maximum enabled slots. # C: O(1)
pub const CONFIG: u64 = 0x38;
/// Interrupter management register. # C: O(1)
pub const IMAN: u64 = 0x00;
/// Event Ring Segment Table size. # C: O(1)
pub const ERSTSZ: u64 = 0x08;
/// Event Ring Segment Table base. # C: O(1)
pub const ERSTBA: u64 = 0x10;
/// Event Ring Dequeue Pointer. # C: O(1)
pub const ERDP: u64 = 0x18;
/// Start controller execution. # C: O(1)
pub const CMD_RUN: u32 = 1;
/// Reset a halted controller. # C: O(1)
pub const CMD_RESET: u32 = 1 << 1;
/// Enable host-controller events. # C: O(1)
pub const CMD_EIE: u32 = 1 << 2;
/// Enable host-system-error events. # C: O(1)
pub const CMD_HSEIE: u32 = 1 << 3;
/// Controller is stopped. # C: O(1)
pub const STS_HALT: u32 = 1;
/// Event interrupt status (write one to acknowledge). # C: O(1)
pub const STS_EINT: u32 = 1 << 3;
/// Controller is not ready for operational accesses. # C: O(1)
pub const STS_CNR: u32 = 1 << 11;
/// Enable event interrupts for interrupter zero. # C: O(1)
pub const IMAN_IE: u32 = 1 << 1;
/// Event-handler-busy acknowledgement on ERDP. # C: O(1)
pub const ERDP_EHB: u64 = 1 << 3;

/// Registers that must be programmed before the first Run transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RunPlan {
    pub crcr: u64,
    pub dcbaap: u64,
    pub config: u32,
    pub iman: u32,
    pub erstsz: u32,
    pub erstba: u64,
    pub erdp: u64,
}

/// Remove execution and interrupt enable bits while preserving unrelated state.
/// # C: O(1)
pub fn halt_command(command: u32) -> u32 { command & !(CMD_RUN | CMD_EIE | CMD_HSEIE) }

/// Request a reset only when the controller has halted and is addressable.
/// # C: O(1)
pub fn reset_command(command: u32, status: u32) -> Option<u32> {
    if status == u32::MAX || status & (STS_HALT | STS_CNR) != STS_HALT { return None; }
    Some(halt_command(command) | CMD_RESET)
}

/// Decide whether reset completion permits DMA structure programming. # C: O(1)
pub fn reset_complete(command: u32, status: u32) -> bool { command & CMD_RESET == 0 && status & STS_CNR == 0 && status != u32::MAX }

/// Build the initial one-interrupter controller plan after reset completion.
/// # C: O(1)
pub fn run_plan(g: Geometry, command_ring_pa: u64, dcbaa_pa: u64, erst_pa: u64, event_ring_pa: u64) -> Option<RunPlan> {
    if command_ring_pa & 0x3f != 0 || dcbaa_pa & 0x3f != 0 || erst_pa & 0x3f != 0 || event_ring_pa & 0x3f != 0 { return None; }
    Some(RunPlan {
        crcr: command_ring_pa | 1,
        dcbaap: dcbaa_pa,
        config: g.max_slots as u32,
        iman: IMAN_IE,
        erstsz: 1,
        erstba: erst_pa,
        erdp: event_ring_pa | ERDP_EHB,
    })
}

/// Add execution and interrupt enables only after every DMA pointer is live.
/// # C: O(1)
pub fn run_command(command: u32) -> u32 { command | CMD_RUN | CMD_EIE | CMD_HSEIE }

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry() -> Geometry { Geometry { hci_version: 0x0100, operational: 0x40, runtime: 0x1000, doorbells: 0x2000, max_slots: 32, max_interrupters: 1, max_ports: 8, context_bytes: 32, extended_capabilities: 0 } }

    #[test]
    fn reset_requires_halted_addressable_controller() {
        assert_eq!(halt_command(u32::MAX), !(CMD_RUN | CMD_EIE | CMD_HSEIE));
        assert_eq!(reset_command(CMD_RUN, STS_HALT), Some(CMD_RESET));
        assert_eq!(reset_command(0, 0), None);
        assert_eq!(reset_command(0, STS_HALT | STS_CNR), None);
        assert!(!reset_complete(CMD_RESET, STS_HALT));
        assert!(reset_complete(0, STS_HALT));
    }

    #[test]
    fn run_plan_uses_exact_controller_dma_pointer_encodings() {
        let p = run_plan(geometry(), 0x20_000, 0x21_000, 0x22_000, 0x23_000).unwrap();
        assert_eq!(p.crcr, 0x20_001);
        assert_eq!(p.dcbaap, 0x21_000);
        assert_eq!(p.config, 32);
        assert_eq!(p.erstsz, 1);
        assert_eq!(p.erdp, 0x23_008);
        assert_eq!(run_command(0), CMD_RUN | CMD_EIE | CMD_HSEIE);
    }

    #[test]
    fn unaligned_dma_tables_are_never_programmed() {
        assert!(run_plan(geometry(), 0x20_004, 0x21_000, 0x22_000, 0x23_000).is_none());
        assert!(run_plan(geometry(), 0x20_000, 0x21_004, 0x22_000, 0x23_000).is_none());
    }
}
