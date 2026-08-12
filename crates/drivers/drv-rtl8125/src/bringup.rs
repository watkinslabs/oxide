//! RTL8125 reset and descriptor-publication ordering.

use crate::regs;

/// One MMIO operation in the device-start transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Op { Write8(u64, u8), Write16(u64, u16), Write32(u64, u32), Read32(u64) }

/// Build the ordered reset-to-running transaction for a validated RTL8125.
/// DMA remains disabled until both ring addresses, receive geometry, and filters
/// have been published. # C: O(1)
pub fn start_plan(tx_config: u32, rx_dma: u64, tx_dma: u64) -> Option<[Op; 12]> {
    if !regs::supported_chip(tx_config) || rx_dma & 0xff != 0 || tx_dma & 0xff != 0 { return None; }
    Some([
        Op::Write16(regs::INTR_MASK, 0), Op::Write8(regs::CHIP_CMD, regs::CMD_RESET),
        Op::Read32(regs::TX_CONFIG), Op::Write32(regs::RX_DESC_LOW, rx_dma as u32),
        Op::Write32(regs::RX_DESC_HIGH, (rx_dma >> 32) as u32), Op::Write32(regs::TX_DESC_LOW, tx_dma as u32),
        Op::Write32(regs::TX_DESC_HIGH, (tx_dma >> 32) as u32), Op::Write32(regs::RX_CONFIG, regs::initial_rx_config()),
        Op::Write32(regs::RX_CONFIG, regs::rx_config_unicast_broadcast()), Op::Write8(regs::CHIP_CMD, regs::start_command()),
        Op::Read32(regs::TX_CONFIG), Op::Write16(regs::INTR_MASK, regs::INTR_DEFAULT),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rings_and_filters_precede_dma_enable_and_interrupts() {
        let plan = start_plan(0x6410_0000, 0x1000, 0x2000).unwrap();
        assert_eq!(plan[0], Op::Write16(regs::INTR_MASK, 0));
        assert_eq!(plan[9], Op::Write8(regs::CHIP_CMD, regs::start_command()));
        assert_eq!(plan[11], Op::Write16(regs::INTR_MASK, regs::INTR_DEFAULT));
        assert!(start_plan(0x5000_0000, 0x1000, 0x2000).is_none());
    }
}
