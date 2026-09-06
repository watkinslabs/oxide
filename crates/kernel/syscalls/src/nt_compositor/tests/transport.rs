use super::{Queue, Completion, TransportError, stream};
use syscall::nt_compositor::{self as wire, Header, Opcode, Record};
use alloc::vec;

impl Queue {
    fn enqueue(&mut self, opcode: Opcode, hwnd: u64, payload: alloc::vec::Vec<u8>) -> Result<u64, TransportError> {
        if self.is_dead() { return Err(TransportError::Disconnected); }
        let mut prepared = Some(super::queue::Prepared::new(opcode, hwnd, payload)?);
        self.enqueue_prepared(&mut prepared)
    }
}

#[test]
fn queue_acceptance_is_not_presentation_and_completion_frees_capacity() {
    let mut queue = Queue::new();
    let ticket = queue.enqueue(Opcode::Destroy, 7, vec![]).unwrap();
    assert_eq!(queue.take_completion(ticket), Ok(Completion::Pending));
    assert_eq!(queue.acknowledge(ticket, 7, 0), Err(TransportError::Unknown));
    let bytes = queue.take_send().unwrap();
    assert_eq!(Header::decode(&bytes).unwrap().sequence, ticket);
    assert!(queue.take_send().is_none());
    assert_eq!(queue.acknowledge(ticket, 8, 0), Err(TransportError::Unknown));
    queue.acknowledge(ticket, 7, 0).unwrap();
    assert_eq!(queue.take_completion(ticket), Ok(Completion::Pending));
    queue.sent().unwrap();
    assert_eq!(queue.take_completion(ticket), Ok(Completion::Presented));
    assert_eq!(queue.take_completion(ticket), Err(TransportError::Unknown));
}

#[test]
fn bounded_records_include_unconsumed_completions() {
    let mut queue = Queue::new();
    for _ in 0..wire::MAX_QUEUED_RECORDS { queue.enqueue(Opcode::Destroy, 1, vec![]).unwrap(); }
    assert_eq!(queue.enqueue(Opcode::Destroy, 1, vec![]), Err(TransportError::Full));
    queue.take_send().unwrap(); queue.sent().unwrap(); queue.acknowledge(1, 1, 0).unwrap();
    assert_eq!(queue.enqueue(Opcode::Destroy, 1, vec![]), Err(TransportError::Full));
    assert_eq!(queue.take_completion(1), Ok(Completion::Presented));
    assert!(queue.enqueue(Opcode::Destroy, 1, vec![]).is_ok());
}

#[test]
fn disconnect_and_backend_failure_never_report_presented() {
    let mut queue = Queue::new(); let ticket = queue.enqueue(Opcode::Destroy, 1, vec![]).unwrap();
    queue.take_send(); queue.sent().unwrap(); queue.acknowledge(ticket, 1, 3).unwrap();
    assert_eq!(queue.take_completion(ticket), Ok(Completion::Failed(3)));
    let next = queue.enqueue(Opcode::Destroy, 1, vec![]).unwrap(); queue.close();
    assert_eq!(queue.take_completion(next), Err(TransportError::Disconnected));
    assert_eq!(queue.enqueue(Opcode::Destroy, 1, vec![]), Err(TransportError::Disconnected));
    assert!(queue.take_send().is_none());
}

#[test]
fn fragmented_input_and_output_preserve_every_byte() {
    let record = Record::new(Opcode::Text, 1, 4, b"Hello".to_vec()).unwrap();
    let bytes = record.encode().unwrap(); let mut offset = 0;
    let decoded = stream::read_record(|out| {
        let n = out.len().min(2).min(bytes.len()-offset);
        out[..n].copy_from_slice(&bytes[offset..offset+n]); offset += n; Ok(n)
    }).unwrap();
    assert_eq!(record, decoded);
    let mut received = vec![];
    stream::write_record(&bytes, |chunk| { let n = chunk.len().min(3); received.extend_from_slice(&chunk[..n]); Ok(n) }).unwrap();
    assert_eq!(received, bytes);
}

#[test]
fn eof_at_every_truncation_is_failure() {
    let bytes = Record::new(Opcode::Text, 1, 4, b"hello".to_vec()).unwrap().encode().unwrap();
    for cut in 0..bytes.len() {
        let mut offset = 0;
        assert_eq!(stream::read_record(|out| { let n = out.len().min(cut-offset); out[..n].copy_from_slice(&bytes[offset..offset+n]); offset += n; Ok(n) }), Err(TransportError::Disconnected));
    }
    let mut calls = 0;
    assert_eq!(stream::write_record(&bytes, |_| { calls += 1; if calls == 1 { Ok(2) } else { Ok(0) } }), Err(TransportError::Disconnected));
}

#[test]
fn invalid_header_rejected_before_payload_read() {
    let mut bytes = Record::new(Opcode::Close, 1, 1, vec![]).unwrap().encode().unwrap();
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut calls = 0;
    assert_eq!(stream::read_record(|out| { calls += 1; out.copy_from_slice(&bytes); Ok(bytes.len()) }), Err(TransportError::Invalid));
    assert_eq!(calls, 1);
}

#[test]
fn backend_cannot_send_kernel_window_mutations() {
    let bytes = Record::new(Opcode::Destroy, 1, 1, vec![]).unwrap().encode().unwrap();
    let mut calls = 0;
    assert_eq!(stream::read_record(|out| { calls += 1; out.copy_from_slice(&bytes); Ok(bytes.len()) }), Err(TransportError::Invalid));
    assert_eq!(calls, 1);
}

#[test]
fn byte_budget_applies_even_with_record_slots_remaining() {
    let mut queue = Queue::new();
    let frame = || {
        let mut p = vec![];
        for value in [4096u32, 1024, 16384, wire::PIXEL_BGRA8888] { p.extend_from_slice(&value.to_le_bytes()); }
        p.resize(16 + 16384 * 1024, 0); p
    };
    for _ in 0..3 { queue.enqueue(Opcode::Frame, 1, frame()).unwrap(); }
    assert_eq!(queue.enqueue(Opcode::Frame, 1, frame()), Err(TransportError::Full));
    queue.take_send().unwrap(); queue.sent().unwrap(); queue.acknowledge(1, 1, 0).unwrap();
    assert_eq!(queue.take_completion(1), Ok(Completion::Presented));
    assert!(queue.enqueue(Opcode::Frame, 1, frame()).is_ok());
}

#[test]
fn ack_before_failed_transfer_is_never_success_and_duplicates_are_rejected() {
    let mut queue = Queue::new(); let ticket = queue.enqueue(Opcode::Destroy, 1, vec![]).unwrap();
    queue.take_send().unwrap(); queue.acknowledge(ticket, 1, 0).unwrap();
    assert_eq!(queue.acknowledge(ticket, 1, 0), Err(TransportError::Unknown));
    assert_eq!(queue.take_completion(ticket), Ok(Completion::Pending));
    queue.close();
    assert_eq!(queue.sent(), Err(TransportError::Disconnected));
    assert_eq!(queue.take_completion(ticket), Err(TransportError::Disconnected));
}

#[test]
fn rejected_prepared_record_stays_with_caller_for_drop_after_unlock() {
    let mut queue = Queue::try_new().unwrap();
    for _ in 0..wire::MAX_QUEUED_RECORDS { queue.enqueue(Opcode::Destroy, 1, vec![]).unwrap(); }
    let mut prepared = Some(super::queue::Prepared::new(Opcode::Title, 1, b"owned".to_vec()).unwrap());
    assert_eq!(queue.enqueue_prepared(&mut prepared), Err(TransportError::Full)); assert!(prepared.is_some());
    queue.take_send(); queue.sent().unwrap(); queue.acknowledge(1, 1, 0).unwrap(); queue.take_completion(1).unwrap();
    assert!(queue.enqueue_prepared(&mut prepared).is_ok()); assert!(prepared.is_none());
}

#[test]
fn notepad_visible_child_statusbar_starts_at_zero_extent() {
    const WS_VISIBLE: u32 = 0x1000_0000;
    const WS_CHILD: u32 = 0x4000_0000;
    let parent = 0x43u64;
    let child = 0x44u64;
    let rect = wire::Rect { x: 0, y: 0, width: 0, height: 0 };
    let mut payload = rect.encode_window().unwrap().to_vec();
    payload.extend_from_slice(&parent.to_le_bytes());
    payload.extend_from_slice(&(WS_VISIBLE | WS_CHILD).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    let record = Record::new(Opcode::Create, 1, child, payload).unwrap();
    assert_eq!(wire::Rect::decode_window(&record.payload[..16]), Ok(rect));
    assert_eq!(wire::u64_at(&record.payload, 16), Ok(parent));
    assert_eq!(wire::u32_at(&record.payload, 24), Ok(WS_VISIBLE | WS_CHILD));
    let mut queue = Queue::try_new().unwrap();
    assert!(queue.enqueue(Opcode::Create, child, record.payload).is_ok());
    for opcode in [Opcode::Geometry, Opcode::Configure] {
        assert!(Record::new(opcode, 2, child, rect.encode_window().unwrap().to_vec()).is_ok());
    }
    assert!(wire::Rect::decode(&rect.encode_window().unwrap()).is_err());
    assert!(wire::pixel_len(0, 0, 0, wire::PIXEL_BGRA8888).is_err());
    let mut monitors = 1u32.to_le_bytes().to_vec();
    monitors.extend_from_slice(&rect.encode_window().unwrap()); monitors.extend_from_slice(&rect.encode_window().unwrap());
    assert!(Record::new(Opcode::Monitors, 3, 0, monitors).is_err());
}

#[test]
fn zero_window_dimension_does_not_relax_bounds_or_coordinate_overflow() {
    for (width, height) in [(0, 20), (20, 0), (0, 0)] {
        let r = wire::Rect { x: -20, y: -10, width, height };
        assert_eq!(wire::Rect::decode_window(&r.encode_window().unwrap()), Ok(r));
    }
    assert!(wire::Rect { x: i32::MAX, y: 0, width: 1, height: 0 }.encode_window().is_err());
    assert!(wire::Rect { x: 0, y: 0, width: wire::MAX_DIMENSION + 1, height: 0 }.encode_window().is_err());
}

#[test]
fn version_opcode_reserved_and_pixels_are_checked() {
    let bytes = Record::new(Opcode::Close, 1, 1, vec![]).unwrap().encode().unwrap();
    for index in [0, 4, 6, 12] { let mut bad = bytes.clone(); bad[index] = 0xff; assert!(Header::decode(&bad).is_err()); }
    assert_eq!(wire::pixel_len(4, 3, 16, wire::PIXEL_BGRA8888), Ok(48));
    for (w,h,s,f) in [(0,1,4,1),(1,0,4,1),(4,3,15,1),(4,3,16,2),(8192,8192,u32::MAX,1)] { assert!(wire::pixel_len(w,h,s,f).is_err()); }
    let mut p = vec![]; for v in [4u32, 3, 16, 1] { p.extend_from_slice(&v.to_le_bytes()); } p.resize(16+47, 0);
    assert!(Record::new(Opcode::Frame, 1, 1, p).is_err());
}

#[test]
fn desktop_snapshot_requires_real_valid_geometry() {
    let mut p = 1u32.to_le_bytes().to_vec();
    let r = wire::Rect { x: -100, y: 0, width: 100, height: 100 };
    p.extend_from_slice(&r.encode().unwrap()); p.extend_from_slice(&r.encode().unwrap());
    let record = Record::new(Opcode::Monitors, 1, 0, p.clone()).unwrap();
    assert_eq!(record.monitors().unwrap()[0].monitor, r);
    p[20..24].copy_from_slice(&1000i32.to_le_bytes());
    assert!(Record::new(Opcode::Monitors, 2, 0, p).is_err());
    assert!(Record::new(Opcode::Monitors, 2, 0, 0u32.to_le_bytes().to_vec()).unwrap().monitors().unwrap().is_empty());
    assert!(wire::Rect { x: i32::MAX, y: 0, width: 1, height: 1 }.encode().is_err());
}
