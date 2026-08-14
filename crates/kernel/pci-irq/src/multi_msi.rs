//! Indexed multi-message MSI allocation and PCI capability programming.

use crate::MSI_MAX_MESSAGES;

const MSI_CONTROL_ENABLE: u32 = 1 << 16;
const MSI_CONTROL_MME_SHIFT: u32 = 20;
const MSI_CONTROL_MME_MASK: u32 = 0x7 << MSI_CONTROL_MME_SHIFT;
const MSI_MESSAGE_ADDR_LOW_OFF: u8 = 4;
const MSI_MESSAGE_ADDR_HIGH_OFF: u8 = 8;
const MSI_32_MESSAGE_DATA_OFF: u8 = 8;
const MSI_64_MESSAGE_DATA_OFF: u8 = 12;
const MSI_32_MASK_BITS_OFF: u8 = 12;
const MSI_64_MASK_BITS_OFF: u8 = 16;

/// A coherent MSI message block owned until a PCI binding accepts it.
pub(super) struct Block {
    messages: [arch_irq::MsiMessage; MSI_MAX_MESSAGES],
    count: usize,
}

/// Allocate a hardware-valid message block covering `message_number`.
/// # C: O(messages * irq_slots)
pub(super) fn allocate(bdf: pci::Bdf, message_number: u8, capable: u8) -> Option<Block> {
    let count = message_count(message_number, capable)?;
    let mut pending = [None; MSI_MAX_MESSAGES];
    for index in 0..count {
        let Some(message) = arch_irq::alloc_pci_msi(bdf, index as u32) else {
            release_pending(&pending, count);
            return None;
        };
        pending[index] = Some(message);
    }
    let Some(messages) = coherent_messages(&pending, count) else {
        release_pending(&pending, count);
        return None;
    };
    Some(Block { messages, count })
}

impl Block {
    /// Return one exact device-relative MSI message. # C: O(1)
    pub(super) fn message(&self, index: usize) -> Option<arch_irq::MsiMessage> {
        (index < self.count).then_some(self.messages[index])
    }

    /// Count hardware messages in this block. # C: O(1)
    pub(super) const fn count(&self) -> usize { self.count }

    /// Program this block and mask every non-service message when supported.
    /// # C: O(1)
    pub(super) fn program<R: pci::ConfigSpaceReader>(&self, r: &R, bdf: pci::Bdf,
        cap_off: u8, cap: pci::MsiCap, target: usize) -> bool {
        let first = self.messages[0];
        if target >= self.count || first.data > u16::MAX as u32
            || (!cap.address_64 && first.address > u32::MAX as u64) { return false; }
        let off = cap_off & 0xfc;
        let header = r.read32(bdf, off);
        let mme = self.count.trailing_zeros() << MSI_CONTROL_MME_SHIFT;
        r.write32(bdf, off, (header & !(MSI_CONTROL_ENABLE | MSI_CONTROL_MME_MASK)) | mme);
        let _ = r.read32(bdf, off);
        r.write32(bdf, off.wrapping_add(MSI_MESSAGE_ADDR_LOW_OFF), first.address as u32);
        let data_off = if cap.address_64 {
            r.write32(bdf, off.wrapping_add(MSI_MESSAGE_ADDR_HIGH_OFF), (first.address >> 32) as u32);
            MSI_64_MESSAGE_DATA_OFF
        } else { MSI_32_MESSAGE_DATA_OFF };
        let old_data = r.read32(bdf, off.wrapping_add(data_off));
        r.write32(bdf, off.wrapping_add(data_off), (old_data & 0xffff_0000) | first.data);
        if cap.per_vector_mask {
            let mask_off = if cap.address_64 { MSI_64_MASK_BITS_OFF } else { MSI_32_MASK_BITS_OFF };
            let other_messages = (1u32 << self.count).wrapping_sub(1) & !(1u32 << target);
            let target_mask = 1u32 << target;
            let current = r.read32(bdf, off.wrapping_add(mask_off));
            r.write32(bdf, off.wrapping_add(mask_off), (current | other_messages) & !target_mask);
        }
        let _ = r.read32(bdf, off.wrapping_add(data_off));
        r.write32(bdf, off, (header & !MSI_CONTROL_MME_MASK) | mme | MSI_CONTROL_ENABLE);
        let _ = r.read32(bdf, off);
        true
    }

    /// Free all architecture messages after the PCI source is disabled.
    /// # C: O(messages)
    pub(super) fn release(&self) {
        for message in &self.messages[..self.count] { arch_irq::free_pci_msi(message.irq); }
    }
}

fn message_count(message_number: u8, capable: u8) -> Option<usize> {
    let needed = (message_number as usize).checked_add(1)?;
    let count = needed.checked_next_power_of_two()?;
    (count <= MSI_MAX_MESSAGES && count <= (1usize << capable)).then_some(count)
}

fn coherent_messages(pending: &[Option<arch_irq::MsiMessage>; MSI_MAX_MESSAGES], count: usize)
    -> Option<[arch_irq::MsiMessage; MSI_MAX_MESSAGES]> {
    let first = pending[0]?;
    if first.data > u16::MAX as u32 || first.data & (count as u32 - 1) != 0 { return None; }
    let mut messages = [first; MSI_MAX_MESSAGES];
    for index in 0..count {
        let message = pending[index]?;
        if message.address != first.address || message.data != first.data.checked_add(index as u32)? { return None; }
        messages[index] = message;
    }
    Some(messages)
}

fn release_pending(pending: &[Option<arch_irq::MsiMessage>; MSI_MAX_MESSAGES], count: usize) {
    for message in pending[..count].iter().flatten() { arch_irq::free_pci_msi(message.irq); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_service_index_rounds_to_the_hardware_message_block() {
        assert_eq!(message_count(0, 0), Some(1));
        assert_eq!(message_count(2, 2), Some(4));
        assert_eq!(message_count(3, 2), Some(4));
        assert_eq!(message_count(4, 2), None);
    }

    #[test]
    fn incoherent_architecture_messages_are_not_a_pci_msi_block() {
        let first = arch_irq::MsiMessage { irq: 0x50, address: 0xfee0_0000, data: 0x50 };
        let second = arch_irq::MsiMessage { irq: 0x53, address: 0xfee0_0000, data: 0x53 };
        let mut pending = [None; MSI_MAX_MESSAGES];
        pending[0] = Some(first);
        pending[1] = Some(second);
        assert!(coherent_messages(&pending, 2).is_none());
    }
}
