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
const EVENT_BUF_PA: u64 = 0x4000;
const TEST_NOTIFY_OFF: u16 = 0x10;

#[repr(align(4096))]
struct Page([u8; 4096]);

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
fn eventq_prepost_uses_shared_queue_publication_before_its_first_notify() {
    let mut desc = Page([0; 4096]);
    let mut avail = Page([0; 4096]);
    let used = Page([0; 4096]);
    let mut notify = 0u16;
    let resource = virtio::VirtQueueResource {
        index: EVENTQ_INDEX,
        size: QUEUE_SIZE,
        desc_pa: desc.0.as_mut_ptr() as u64,
        driver_pa: avail.0.as_mut_ptr() as u64,
        device_pa: used.0.as_ptr() as u64,
        notify_va: (&mut notify as *mut u16) as u64,
        notify_off: TEST_NOTIFY_OFF,
    };
    let mut eventq = virtio::VirtioSplitQueue::new(resource, 0).unwrap();

    assert!(prepost_eventq(&mut eventq, EVENT_BUF_PA));

    for desc_id in 0..QUEUE_SIZE as usize {
        let desc_off = desc_id * DESC_ENTRY_BYTES;
        assert_eq!(
            read_u64(&desc.0, desc_off + DESC_ADDR_OFF),
            EVENT_BUF_PA + (desc_id as u64) * EVENT_SIZE as u64,
        );
        assert_eq!(read_u32(&desc.0, desc_off + DESC_LEN_OFF), EVENT_SIZE as u32);
        assert_eq!(read_u16(&desc.0, desc_off + DESC_FLAGS_OFF), virtio::VRING_DESC_F_WRITE);
        assert_eq!(read_u16(&desc.0, desc_off + DESC_NEXT_OFF), 0);
        assert_eq!(
            read_u16(&avail.0, AVAIL_RING_OFF + desc_id * AVAIL_RING_ENTRY_BYTES),
            desc_id as u16,
        );
    }
    assert_eq!(read_u16(&avail.0, AVAIL_FLAGS_OFF), 0);
    assert_eq!(read_u16(&avail.0, AVAIL_IDX_OFF), QUEUE_SIZE);
    assert_eq!(eventq.avail_idx(), QUEUE_SIZE);
    assert_eq!(notify, 0);
    eventq.kick();
    assert_eq!(notify, EVENTQ_INDEX);
}
