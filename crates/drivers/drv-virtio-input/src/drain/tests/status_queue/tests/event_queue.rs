use super::*;

#[test]
fn eventq_publishes_every_frame_backed_descriptor() {
    let _devices = crate::registry::own_device_table();
    let mut fixture = Fixture::new();
    let eventq = virtio::VirtQueueResource {
        index: EVENT_QUEUE_INDEX,
        ..fixture.queue(queue::MAX_EVENT_BUFFERS)
    };
    let frame_pa = fixture.frames.0.as_mut_ptr() as u64;

    let mut owner = virtio::VirtioSplitQueue::new(eventq, 0).expect("event queue");
    let mut slots = [u16::MAX; queue::MAX_EVENT_BUFFERS as usize];
    let supplied = queue::post_event_buffers(&mut owner, frame_pa, &mut slots)
        .expect("event buffers");

    assert_eq!(supplied, queue::MAX_EVENT_BUFFERS);
    assert_eq!(
        read_u16(&fixture.avail, RING_INDEX_OFF),
        queue::MAX_EVENT_BUFFERS,
    );
    assert_eq!(
        read_u16(
            &fixture.avail,
            RING_ENTRIES_OFF
                + (queue::MAX_EVENT_BUFFERS as usize - 1) * AVAIL_ENTRY_BYTES,
        ),
        queue::MAX_EVENT_BUFFERS - 1,
    );
    let last = (queue::MAX_EVENT_BUFFERS as usize - 1) * DESC_BYTES;
    assert_eq!(
        read_u64(&fixture.desc, last),
        frame_pa + u64::from(queue::MAX_EVENT_BUFFERS - 1) * EVENT_BYTES as u64,
    );
    assert_eq!(read_u32(&fixture.desc, last + DESC_LEN_OFF), EVENT_BYTES as u32);
}


