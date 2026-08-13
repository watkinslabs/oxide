//! AQC113 firmware shared-buffer transaction.

pub const INPUT_BUFFER: u64 = 0x12000;
pub const OUTPUT_BUFFER: u64 = 0x13000;
pub const INPUT_MTU: u32 = 0;
pub const INPUT_MAC: u32 = 2;
pub const INPUT_LINK_CONTROL: u32 = 4;
pub const INPUT_LINK_OPTIONS: u32 = 6;
pub const HOST_FINISHED_WRITE: u64 = 0x0e00;
pub const FIRMWARE_FINISHED_READ: u64 = 0x0e04;
pub const HOST_ACTIVE: u32 = 1;
pub const LINK_MODE_MASK: u32 = 0x0f;
pub const MAX_MTU: u32 = 16_352;
pub const POLL_INTERVAL_NS: u64 = 100;
pub const INITIALIZE_TIMEOUT_NS: u64 = 5_000_000_000;
pub const ACK_TIMEOUT_NS: u64 = 100_000;
pub const LINK_RATE_MASK: u32 = 0x0000_ffe1;
pub const AQC113_AUTONEG_RATES: u32 = 0x0000_af01;
pub const SHARED_READ_TRIES: usize = 1000;
pub const SHARED_UNSTABLE_DELAY_NS: u64 = 1_000_000;
pub const OUTPUT_TRANSACTION: u32 = 0;
pub const OUTPUT_FILTER_CAPS: u32 = 477;
pub const L2_FILTER_SLOT_LIMIT: u8 = 38;

pub trait Access { fn read32(&mut self, offset: u64) -> u32; fn write32(&mut self, offset: u64, value: u32); fn now_ns(&mut self) -> u64; fn relax(&mut self); }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { FirmwareTimeout, SharedReadTimeout }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FilterCaps { pub l2_filter_slot: u8, pub l2_filter_count: u8, pub art_base: u8, pub art_count: u8 }

/// # C: O(1)
pub const fn input_offset(word: u32) -> u64 { INPUT_BUFFER + word as u64 * 4 }
/// # C: O(1)
pub const fn output_offset(word: u32) -> u64 { OUTPUT_BUFFER + word as u64 * 4 }

/// Places the resident firmware in active host mode and waits for its acknowledgement.
/// # C: bounded by INITIALIZE_TIMEOUT_NS
pub fn activate(access: &mut impl Access) -> Result<(), Error> {
    let control = access.read32(input_offset(INPUT_LINK_CONTROL));
    access.write32(input_offset(INPUT_LINK_CONTROL), control & !LINK_MODE_MASK | HOST_ACTIVE);
    access.write32(input_offset(INPUT_MTU), MAX_MTU);
    access.write32(HOST_FINISHED_WRITE, 1);
    let start = access.now_ns();
    loop {
        if access.read32(FIRMWARE_FINISHED_READ) == 0 { return Ok(()); }
        if access.now_ns().saturating_sub(start) >= INITIALIZE_TIMEOUT_NS { return Err(Error::FirmwareTimeout); }
        access.relax();
    }
}

/// Reads the permanent address published by resident firmware in the input buffer.
/// # C: O(1)
pub fn mac(access: &mut impl Access) -> Option<[u8; 6]> {
    let low = access.read32(input_offset(INPUT_MAC)); let high = access.read32(input_offset(INPUT_MAC + 1));
    let value = [low as u8, (low >> 8) as u8, (low >> 16) as u8, (low >> 24) as u8, high as u8, (high >> 8) as u8];
    (value != [0; 6] && value != [0xff; 6]).then_some(value)
}

/// Publishes AQC113's full-duplex autonegotiation set and waits for firmware acknowledgement.
/// # C: bounded by ACK_TIMEOUT_NS
pub fn set_aqc113_link_speed(access: &mut impl Access) -> Result<(), Error> {
    let options = access.read32(input_offset(INPUT_LINK_OPTIONS));
    access.write32(input_offset(INPUT_LINK_OPTIONS), options & !LINK_RATE_MASK | AQC113_AUTONEG_RATES);
    access.write32(HOST_FINISHED_WRITE, 1);
    let start = access.now_ns();
    loop {
        if access.read32(FIRMWARE_FINISHED_READ) == 0 { return Ok(()); }
        if access.now_ns().saturating_sub(start) >= ACK_TIMEOUT_NS { return Err(Error::FirmwareTimeout); }
        access.relax();
    }
}

/// Reads a stable firmware-owned output-buffer range under its transaction counter.
/// # C: O(SHARED_READ_TRIES × words)
fn read_output_stable(access: &mut impl Access, word: u32, words: &mut [u32]) -> Result<(), Error> {
    let mut tries = 0;
    loop {
        let before = access.read32(output_offset(OUTPUT_TRANSACTION));
        tries += 1;
        if tries > SHARED_READ_TRIES { return Err(Error::SharedReadTimeout); }
        if (before as u16) != (before >> 16) as u16 {
            let until = access.now_ns().saturating_add(SHARED_UNSTABLE_DELAY_NS);
            while access.now_ns() < until { access.relax(); }
            continue;
        }
        for (index, value) in words.iter_mut().enumerate() { *value = access.read32(output_offset(word + index as u32)); }
        let after = access.read32(output_offset(OUTPUT_TRANSACTION));
        tries += 1;
        if tries > SHARED_READ_TRIES { return Err(Error::SharedReadTimeout); }
        if before == after && (after as u16) == (after >> 16) as u16 { return Ok(()); }
    }
}

/// Reads firmware filter capabilities and selects its primary unicast L2-filter slot.
/// # C: O(SHARED_READ_TRIES)
pub fn filter_caps(access: &mut impl Access) -> Result<FilterCaps, Error> {
    let mut words = [0u32; 3];
    read_output_stable(access, OUTPUT_FILTER_CAPS, &mut words)?;
    let bytes = [
        words[0] as u8, (words[0] >> 8) as u8, (words[0] >> 16) as u8, (words[0] >> 24) as u8,
        words[1] as u8, (words[1] >> 8) as u8, (words[1] >> 16) as u8, (words[1] >> 24) as u8,
        words[2] as u8, (words[2] >> 8) as u8, (words[2] >> 16) as u8, (words[2] >> 24) as u8,
    ];
    let slot = bytes[0] & 0x3f;
    let art_count = bytes[11].saturating_mul(8);
    Ok(FilterCaps { l2_filter_slot: if slot < L2_FILTER_SLOT_LIMIT { slot } else { 0 }, l2_filter_count: bytes[1], art_base: bytes[10].saturating_mul(8), art_count: if art_count == 0 { 128 } else { art_count } })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake { control: u32, firmware_done: bool, output: [u32; 480], writes: [(u64, u32); 3], count: usize, time: u64 }
    impl Access for Fake {
        fn read32(&mut self, offset: u64) -> u32 { match offset { FIRMWARE_FINISHED_READ => (!self.firmware_done) as u32, value if value == input_offset(INPUT_LINK_CONTROL) => self.control, value if value == input_offset(INPUT_LINK_OPTIONS) => 0xffff_0000, value if value >= OUTPUT_BUFFER && value < OUTPUT_BUFFER + self.output.len() as u64 * 4 => self.output[((value - OUTPUT_BUFFER) / 4) as usize], _ => 0 } }
        fn write32(&mut self, offset: u64, value: u32) { self.writes[self.count] = (offset, value); self.count += 1; }
        fn now_ns(&mut self) -> u64 { self.time }
        fn relax(&mut self) { self.firmware_done = true; self.time += POLL_INTERVAL_NS; }
    }
    #[test] fn activation_preserves_link_flags_then_waits_for_firmware_ack() { let mut fake = Fake { control: 0xffff_fff0, firmware_done: false, output: [0; 480], writes: [(0, 0); 3], count: 0, time: 0 }; assert_eq!(activate(&mut fake), Ok(())); assert_eq!(fake.writes, [(input_offset(INPUT_LINK_CONTROL), 0xffff_fff1), (input_offset(INPUT_MTU), MAX_MTU), (HOST_FINISHED_WRITE, 1)]); }
    #[test] fn firmware_mac_requires_a_non_sentinel_address() { let mut fake = Fake { control: 0, firmware_done: true, output: [0; 480], writes: [(0, 0); 3], count: 0, time: 0 }; assert_eq!(mac(&mut fake), None); }
    #[test] fn link_speed_preserves_unrelated_options_and_acknowledges_firmware() { let mut fake = Fake { control: 0, firmware_done: true, output: [0; 480], writes: [(0, 0); 3], count: 0, time: 0 }; assert_eq!(set_aqc113_link_speed(&mut fake), Ok(())); assert_eq!(fake.writes[..2], [(input_offset(INPUT_LINK_OPTIONS), 0xffff_af01), (HOST_FINISHED_WRITE, 1)]); }
    #[test] fn filter_caps_use_a_stable_transaction_and_clamp_invalid_primary_slot() { let mut fake = Fake { control: 0, firmware_done: true, output: [0; 480], writes: [(0, 0); 3], count: 0, time: 0 }; fake.output[OUTPUT_FILTER_CAPS as usize] = 0x0000_0a3f; assert_eq!(filter_caps(&mut fake), Ok(FilterCaps { l2_filter_slot: 0, l2_filter_count: 10, art_base: 0, art_count: 128 })); fake.output[OUTPUT_FILTER_CAPS as usize] = 0x0000_0a25; fake.output[OUTPUT_FILTER_CAPS as usize + 2] = 0x0805_0000; assert_eq!(filter_caps(&mut fake), Ok(FilterCaps { l2_filter_slot: 37, l2_filter_count: 10, art_base: 40, art_count: 64 })); }
}
