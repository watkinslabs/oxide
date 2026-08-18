//! Linux `HDIO_GET_IDENTITY` page presentation.

/// Linux `HDIO_GET_IDENTITY` command number. # C: O(1)
pub const HDIO_GET_IDENTITY: u64 = 0x030d;
/// One ATA IDENTIFY DEVICE page, in bytes. # C: O(1)
pub const IDENTIFY_BYTES: usize = 512;

const SERIAL_OFFSET: usize = 10 * 2;
const SERIAL_BYTES: usize = 20;
const FIRMWARE_OFFSET: usize = 23 * 2;
const FIRMWARE_BYTES: usize = 8;
const MODEL_OFFSET: usize = 27 * 2;
const MODEL_BYTES: usize = 40;

/// Convert only ATA's word-swapped serial, firmware, and product strings.
/// Linux copies the native IDENTIFY page first, then overwrites exactly these
/// three fields; every other byte remains untouched. # C: O(1)
pub(crate) fn normalize_identity(page: &mut [u8; IDENTIFY_BYTES]) {
    for (offset, bytes) in [
        (SERIAL_OFFSET, SERIAL_BYTES),
        (FIRMWARE_OFFSET, FIRMWARE_BYTES),
        (MODEL_OFFSET, MODEL_BYTES),
    ] {
        for word in page[offset..offset + bytes].chunks_exact_mut(2) { word.swap(0, 1); }
    }
}

#[cfg(test)]
pub(crate) const TEST_SERIAL_OFFSET: usize = SERIAL_OFFSET;
