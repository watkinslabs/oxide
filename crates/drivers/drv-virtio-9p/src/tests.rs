// Device-configuration parsing. The tag is what a mount names, so getting it
// wrong selects the wrong share or none at all.

use crate::config::{parse_tag, TagError, MAX_TAG_LEN};

#[test]
fn a_tag_that_fills_its_field_has_no_terminator() {
    // Treating the field as a C string would read past it.
    let bytes = b"hostshare";
    let t = parse_tag(bytes.len() as u16, bytes).unwrap();
    assert_eq!(t, "hostshare");
}

#[test]
fn a_nul_ends_the_tag_early_without_being_part_of_it() {
    let bytes = b"share\0\0\0\0\0";
    assert_eq!(parse_tag(bytes.len() as u16, bytes).unwrap(), "share");
}

#[test]
fn the_declared_length_bounds_the_tag_not_the_buffer() {
    // Trailing bytes beyond `tag_len` belong to no field and must not appear
    // in the name — a longer read here aliases two devices onto one tag.
    let bytes = b"abcdefghij";
    assert_eq!(parse_tag(3, bytes).unwrap(), "abc");
}

#[test]
fn a_length_past_the_readable_bytes_is_refused() {
    assert_eq!(parse_tag(64, b"short").unwrap_err(), TagError::TooLong);
    let big = alloc::vec![b'x'; MAX_TAG_LEN + 1];
    assert_eq!(parse_tag((MAX_TAG_LEN + 1) as u16, &big).unwrap_err(), TagError::TooLong);
}

#[test]
fn an_empty_tag_is_refused_because_nothing_could_name_it() {
    assert_eq!(parse_tag(0, b"").unwrap_err(), TagError::Empty);
    assert_eq!(parse_tag(4, b"\0\0\0\0").unwrap_err(), TagError::Empty);
}

#[test]
fn a_control_byte_in_a_device_name_is_refused() {
    // A newline breaks every line-oriented consumer of a mount table.
    assert_eq!(parse_tag(5, b"a\nb c").unwrap_err(), TagError::BadByte);
    assert_eq!(parse_tag(3, b"a\tb").unwrap_err(), TagError::BadByte);
    assert_eq!(parse_tag(3, b"a\x7fb").unwrap_err(), TagError::BadByte);
}

#[test]
fn a_non_utf8_tag_is_refused_rather_than_converted_lossily() {
    // Two distinct byte tags must not collapse onto one replacement-character
    // name and become indistinguishable mount sources.
    assert_eq!(parse_tag(3, &[b'a', 0xFF, b'b']).unwrap_err(), TagError::NotUtf8);
}

#[test]
fn an_ordinary_tag_with_punctuation_is_accepted() {
    assert_eq!(parse_tag(11, b"host-share_").unwrap(), "host-share_");
    assert_eq!(parse_tag(9, b"/mnt/host").unwrap(), "/mnt/host");
}

#[test]
fn the_mount_tag_feature_is_the_lowest_bit() {
    // A device that does not offer it publishes no tag and cannot be named.
    assert_eq!(crate::VIRTIO_9P_F_MOUNT_TAG, 1);
    assert!(crate::wanted_features() & crate::VIRTIO_9P_F_MOUNT_TAG != 0);
    assert!(crate::wanted_features() & virtio::VIRTIO_F_VERSION_1 != 0);
}

#[test]
fn the_profile_asks_for_the_queue_and_the_configuration_the_tag_lives_in() {
    let p = crate::transport_profile();
    assert!(p.child_requirements.required_queues[0]);
    assert!(p.child_requirements.needs_device_cfg);
    assert_eq!(crate::DRIVER_ID.device_id, crate::VIRTIO_ID_9P);
}

#[test]
fn the_staging_buffer_can_carry_a_useful_frame() {
    // A frame below the protocol floor would make every mount fail its
    // handshake, and one below the I/O envelope would make reads return
    // nothing.
    let cap = crate::consts::BUFFER_BYTES as u32;
    assert!(cap >= ninep::uapi::limits::MIN_MSIZE);
    assert!(cap as usize > ninep::uapi::limits::IOHDRSZ * 16);
}
