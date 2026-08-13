//! RTL8125 firmware selection and instruction-stream validation.

use crate::regs;

const HEADER_BYTES: usize = 45;
const ACTION_BYTES: usize = 4;
const OPCODE_MDIO_CHANGE: u32 = 4;
const OPCODE_BACK_JUMP: u32 = 3;
const OPCODE_READCOUNT_SKIP: u32 = 9;
const OPCODE_COMPARE_EQUAL_SKIP: u32 = 10;
const OPCODE_COMPARE_NOT_EQUAL_SKIP: u32 = 11;
const OPCODE_SKIP: u32 = 13;
const OPCODE_MAX: u32 = 14;

/// Select the PHY OCP page represented by one firmware page-register write. # C: O(1)
pub const fn phy_page_base(value: u16) -> u32 { if value == 0 { regs::OCP_STANDARD_PHY_BASE } else { (value as u32) << 4 } }
/// Translate one firmware PHY register through the current OCP page. # C: O(1)
pub const fn phy_ocp_register(base: u32, reg: u16) -> Option<u32> {
    let reg = if base == regs::OCP_STANDARD_PHY_BASE { reg } else { match reg.checked_sub(regs::MDIO_OCP_OFFSET) { Some(value) => value, None => return None } };
    Some(base + reg as u32 * 2)
}

/// Firmware name selected by the MAC revision encoded in TxConfig. # C: O(1)
pub const fn name_for(tx_config: u32) -> Option<&'static [u8]> {
    match regs::chip_xid(tx_config) & regs::CHIP_XID_MASK {
        regs::CHIP_RTL8125A => Some(b"rtl_nic/rtl8125a-3.fw"),
        regs::CHIP_RTL8125B => Some(b"rtl_nic/rtl8125b-2.fw"),
        regs::CHIP_RTL8125D1 => Some(b"rtl_nic/rtl8125d-1.fw"),
        regs::CHIP_RTL8125D2 => Some(b"rtl_nic/rtl8125d-2.fw"),
        regs::CHIP_RTL8125K => Some(b"rtl_nic/rtl8125k-1.fw"),
        regs::CHIP_RTL8125BP => Some(b"rtl_nic/rtl8125bp-2.fw"),
        regs::CHIP_RTL8125CP => Some(b"rtl_nic/rtl8125cp-1.fw"),
        _ => None,
    }
}

/// Validated firmware action stream. # C: O(1)
pub struct Image<'a> { actions: &'a [u8] }
/// Hardware access operations used by the validated instruction interpreter.
pub trait Ops {
    fn phy_read(&mut self, reg: u16) -> Option<u16>;
    fn phy_write(&mut self, reg: u16, value: u16) -> bool;
    fn mac_read(&mut self, reg: u16) -> Option<u16>;
    fn mac_write(&mut self, reg: u16, value: u16) -> bool;
    fn delay_ms(&mut self, value: u16) -> bool;
}
impl<'a> Image<'a> {
    /// Parse, checksum, and bounds-check one firmware image. # C: O(image bytes)
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < ACTION_BYTES { return None; }
        let actions = if le32(bytes, 0)? == 0 {
            if bytes.len() < HEADER_BYTES || bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 { return None; }
            let start = le32(bytes, 36)? as usize;
            let count = le32(bytes, 40)? as usize;
            let size = count.checked_mul(ACTION_BYTES)?;
            let end = start.checked_add(size)?;
            bytes.get(start..end)?
        } else {
            if bytes.len() % ACTION_BYTES != 0 { return None; }
            bytes
        };
        if actions.is_empty() || !actions_valid(actions) { return None; }
        Some(Self { actions })
    }

    /// Number of validated instructions. # C: O(1)
    pub const fn action_count(&self) -> usize { self.actions.len() / ACTION_BYTES }

    /// Execute the validated action stream through one controller access owner. # C: O(actions)
    pub fn apply(&self, ops: &mut impl Ops) -> bool {
        let mut index = 0usize;
        let mut value = 0u16;
        let mut reads = 0u16;
        let mut mac = false;
        while index < self.action_count() {
            let Some(action) = le32(self.actions, index * ACTION_BYTES) else { return false; };
            let data = action as u16;
            let reg = ((action >> 16) & 0x0fff) as u16;
            match action >> 28 {
                0 => { let next = if mac { ops.mac_read(reg) } else { ops.phy_read(reg) }; let Some(next) = next else { return false; }; value = next; reads = reads.saturating_add(1); }
                1 => value |= data,
                2 => value &= data,
                3 => { let Some(next) = index.checked_sub(reg as usize + 1) else { return false; }; index = next; }
                4 => mac = data != 0,
                7 => reads = 0,
                8 => if mac { if !ops.mac_write(reg, data) { return false; } } else if !ops.phy_write(reg, data) { return false; },
                9 => if reads == data { index += 1; },
                10 => if value == data { index += reg as usize; },
                11 => if value != data { index += reg as usize; },
                12 => if mac { if !ops.mac_write(reg, value) { return false; } } else if !ops.phy_write(reg, value) { return false; },
                13 => index += reg as usize,
                14 => if !ops.delay_ms(data) { return false; },
                _ => return false,
            }
            index += 1;
        }
        true
    }
}

fn actions_valid(actions: &[u8]) -> bool {
    let count = actions.len() / ACTION_BYTES;
    for index in 0..count {
        let Some(action) = le32(actions, index * ACTION_BYTES) else { return false; };
        let opcode = action >> 28;
        let data = action & 0xffff;
        let reg = ((action >> 16) & 0x0fff) as usize;
        if opcode > OPCODE_MAX { return false; }
        if opcode == OPCODE_MDIO_CHANGE && data > 1 { return false; }
        if opcode == OPCODE_BACK_JUMP && reg >= index { return false; }
        if opcode == OPCODE_READCOUNT_SKIP && index.saturating_add(2) >= count { return false; }
        if matches!(opcode, OPCODE_COMPARE_EQUAL_SKIP | OPCODE_COMPARE_NOT_EQUAL_SKIP | OPCODE_SKIP)
            && index.checked_add(1).and_then(|next| next.checked_add(reg)).is_none_or(|target| target >= count) { return false; }
    }
    true
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    let part: [u8; ACTION_BYTES] = bytes.get(offset..offset.checked_add(ACTION_BYTES)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_select_their_own_firmware() {
        assert_eq!(name_for(0x6410_0000), Some(&b"rtl_nic/rtl8125b-2.fw"[..]));
        assert_eq!(name_for(0x5000_0000), None);
    }

    #[test]
    fn raw_instruction_stream_requires_valid_branches() {
        assert_eq!(Image::parse(&0x8000_0000u32.to_le_bytes()).unwrap().action_count(), 1);
        assert!(Image::parse(&0xd001_0000u32.to_le_bytes()).is_none());
        assert!(Image::parse(&0xf000_0000u32.to_le_bytes()).is_none());
        assert!(Image::parse(&0x3000_0000u32.to_le_bytes()).is_none());
    }

    #[derive(Default)] struct Fake { value: u16, writes: usize }
    impl Ops for Fake {
        fn phy_read(&mut self, _: u16) -> Option<u16> { Some(self.value) }
        fn phy_write(&mut self, _: u16, value: u16) -> bool { self.value = value; self.writes += 1; true }
        fn mac_read(&mut self, _: u16) -> Option<u16> { Some(self.value) }
        fn mac_write(&mut self, _: u16, value: u16) -> bool { self.phy_write(0, value) }
        fn delay_ms(&mut self, _: u16) -> bool { true }
    }
    #[test]
    fn interpreter_applies_read_modify_write() {
        let stream = [0x4000_0000u32, 0, 0x1000_0001, 0xc000_0002].map(u32::to_le_bytes).concat();
        let image = Image::parse(&stream).unwrap(); let mut ops = Fake { value: 0x10, ..Fake::default() };
        assert!(image.apply(&mut ops)); assert_eq!(ops.value, 0x11); assert_eq!(ops.writes, 1);
    }
    #[test]
    fn firmware_page_writes_rebase_subsequent_phy_registers() {
        assert_eq!(phy_page_base(0), regs::OCP_STANDARD_PHY_BASE);
        assert_eq!(phy_page_base(0xc40), 0xc400);
        assert_eq!(phy_ocp_register(0xc400, 0x10), Some(0xc400));
        assert_eq!(phy_ocp_register(0xc400, 0x0f), None);
        assert_eq!(phy_ocp_register(regs::OCP_STANDARD_PHY_BASE, 0), Some(regs::OCP_STANDARD_PHY_BASE));
    }
}
