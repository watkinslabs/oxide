// Device-configuration parsing. The tag is what a mount names.

use crate::config::{parse_tag, TagError};
use crate::consts::{CFG_OFF_NUM_REQUEST_QUEUES, CFG_TAG_LEN, HIPRIO_QUEUE, REQUEST_QUEUE};

fn field(name: &[u8]) -> alloc::vec::Vec<u8> {
    let mut f = alloc::vec![0u8; CFG_TAG_LEN];
    f[..name.len()].copy_from_slice(name);
    f
}

#[test]
fn the_tag_field_is_nul_padded_not_nul_terminated() {
    // A tag filling all 36 bytes has no terminator; a C-string read would run
    // into the queue count that follows the field.
    let full = alloc::vec![b'x'; CFG_TAG_LEN];
    assert_eq!(parse_tag(&full).unwrap().len(), CFG_TAG_LEN);
    assert_eq!(parse_tag(&field(b"myfs")).unwrap(), "myfs");
}

#[test]
fn bytes_past_the_field_width_are_never_part_of_the_tag() {
    let mut over = field(b"myfs");
    over.extend_from_slice(b"NOTTHETAG");
    assert_eq!(parse_tag(&over).unwrap(), "myfs");
}

#[test]
fn an_all_nul_field_is_refused_because_nothing_could_name_it() {
    assert_eq!(parse_tag(&alloc::vec![0u8; CFG_TAG_LEN]).unwrap_err(), TagError::Empty);
    assert_eq!(parse_tag(&[]).unwrap_err(), TagError::Empty);
}

#[test]
fn a_control_byte_in_a_mount_source_is_refused() {
    assert_eq!(parse_tag(&field(b"my\nfs")).unwrap_err(), TagError::BadByte);
    assert_eq!(parse_tag(&field(b"my\tfs")).unwrap_err(), TagError::BadByte);
}

#[test]
fn a_non_utf8_tag_is_refused_rather_than_converted_lossily() {
    // Two distinct byte tags must not collapse onto one name and become
    // indistinguishable mount sources.
    assert_eq!(parse_tag(&field(&[b'a', 0xFF])).unwrap_err(), TagError::NotUtf8);
}

#[test]
fn the_queue_count_sits_immediately_after_the_tag_field() {
    assert_eq!(CFG_OFF_NUM_REQUEST_QUEUES, CFG_TAG_LEN as u64);
    assert_eq!(CFG_TAG_LEN, 36);
}

#[test]
fn the_priority_queue_comes_before_the_request_queue() {
    // A FORGET queued behind ordinary requests starves the mount when they
    // arrive in bulk, which is exactly when they arrive.
    assert_eq!(HIPRIO_QUEUE, 0);
    assert_eq!(REQUEST_QUEUE, 1);
    let p = crate::transport_profile();
    assert!(p.child_requirements.required_queues[HIPRIO_QUEUE as usize]);
    assert!(p.child_requirements.required_queues[REQUEST_QUEUE as usize]);
    assert!(p.child_requirements.needs_device_cfg);
}

#[test]
fn every_bounded_request_queue_is_handed_to_the_child_when_present() {
    let p = crate::transport_profile();
    for index in REQUEST_QUEUE as usize..virtio::MAX_RESOURCE_QUEUES {
        assert!(p.child_requirements.optional_queues[index] || index == REQUEST_QUEUE as usize);
        assert_eq!(p.queue_plans[index].map(|plan| plan.index), Some(index as u16));
    }
}

#[test]
fn the_device_identity_is_the_shared_filesystem_one() {
    assert_eq!(crate::VIRTIO_ID_FS, 26);
    assert_eq!(crate::DRIVER_ID.device_id, crate::VIRTIO_ID_FS);
}

#[test]
fn the_staging_buffer_can_carry_a_useful_fuse_message() {
    // A message ceiling below a page makes every read a partial one.
    assert!(crate::consts::BUFFER_BYTES >= 64 * 1024);
}
