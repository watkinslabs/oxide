use super::*;
use crate::lifecycle::prepost_eventq;

const EVENTQ_INDEX: u16 = 1;
const QUEUE_SIZE: u16 = 4;
const DESC_ENTRY_BYTES: usize = 16;
const DESC_ADDR_OFF: usize = 0;
const DESC_LEN_OFF: usize = 8;
const DESC_FLAGS_OFF: usize = 12;
const DESC_NEXT_OFF: usize = 14;
const AVAIL_FLAGS_OFF: usize = 0;
const AVAIL_IDX_OFF: usize = 2;
const AVAIL_RING_OFF: usize = 4;
const AVAIL_RING_ENTRY_BYTES: usize = 2;
const DESC_BYTES: usize = QUEUE_SIZE as usize * DESC_ENTRY_BYTES;
const AVAIL_BYTES: usize = AVAIL_RING_OFF + QUEUE_SIZE as usize * AVAIL_RING_ENTRY_BYTES;
const EVENT_BUF_PA: u64 = 0x4000;
const EVENT_AVAIL_IDX: u16 = 0x30;
const TEST_HHDM: u64 = 0;
const TEST_DEVICE_PA: u64 = 0x8000;
const TEST_NOTIFY_OFF: u16 = 0x10;
const NO_AVAIL_FLAGS: u16 = 0;
const NO_DESC_NEXT: u16 = 0;

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

#[test]
fn eventq_prepost_writes_writable_descriptors_and_notifies() {
    let mut desc = [0u8; DESC_BYTES];
    let mut avail = [0u8; AVAIL_BYTES];
    let mut notify = 0u16;
    let eventq = virtio::VirtQueueResource {
        index: EVENTQ_INDEX,
        size: QUEUE_SIZE,
        desc_pa: desc.as_mut_ptr() as u64,
        driver_pa: avail.as_mut_ptr() as u64,
        device_pa: TEST_DEVICE_PA,
        notify_va: (&mut notify as *mut u16) as u64,
        notify_off: TEST_NOTIFY_OFF,
    };

    prepost_eventq(TEST_HHDM, eventq, EVENT_BUF_PA, EVENT_AVAIL_IDX);

    for desc_id in 0..QUEUE_SIZE as usize {
        let desc_off = desc_id * DESC_ENTRY_BYTES;
        assert_eq!(
            read_u64(&desc, desc_off + DESC_ADDR_OFF),
            EVENT_BUF_PA + (desc_id as u64) * EVENT_SIZE as u64,
        );
        assert_eq!(read_u32(&desc, desc_off + DESC_LEN_OFF), EVENT_SIZE as u32);
        assert_eq!(read_u16(&desc, desc_off + DESC_FLAGS_OFF), virtio::VRING_DESC_F_WRITE);
        assert_eq!(read_u16(&desc, desc_off + DESC_NEXT_OFF), NO_DESC_NEXT);
        assert_eq!(
            read_u16(&avail, AVAIL_RING_OFF + desc_id * AVAIL_RING_ENTRY_BYTES),
            desc_id as u16,
        );
    }
    assert_eq!(read_u16(&avail, AVAIL_FLAGS_OFF), NO_AVAIL_FLAGS);
    assert_eq!(read_u16(&avail, AVAIL_IDX_OFF), EVENT_AVAIL_IDX);
    assert_eq!(notify, EVENTQ_INDEX);
}
