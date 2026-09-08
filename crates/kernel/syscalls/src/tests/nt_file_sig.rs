//! Every scalar an NT file service declares survives the stale upper half of
//! the caller's frame word, and no scalar is refused for carrying one.

use super::*;

/// Upper halves no caller ever wrote: what a frame word left over from an
/// earlier call carries into the slot beneath a 32-bit or one-byte store.
const STALE: u64 = 0x7fff_0a5c_0000_0000;
/// The stale bytes above a one-byte `BOOLEAN` store.
const STALE_BYTES: u64 = 0x7fff_0a5c_1234_5600;

const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0x0000_0000;
const FILE_PIPE_QUEUE_OPERATION: u32 = 0x0000_0000;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const GENERIC_READ: u32 = 0x8000_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_STANDARD_INFORMATION: u32 = 5;
const FSCTL_PIPE_PEEK: u32 = 0x0011_000c;
/// One page: the byte count the loader reads a section header with.
const PAGE: u32 = 4096;

#[test]
fn a_boolean_carries_only_its_own_byte() {
    assert!(!boolean(STALE_BYTES));
    assert!(boolean(STALE_BYTES | 1));
    assert!(boolean(1));
    assert!(!boolean(0));
    assert!(boolean(0x100 | 0xff));
    // A caller storing FALSE as a full word is still FALSE.
    assert!(!boolean(0));
    // Only the low byte counts: a word whose low byte is zero is FALSE even
    // when every other byte is set.
    assert!(!boolean(0xffff_ffff_ffff_ff00));
}

#[test]
fn a_handle_is_never_refused_for_being_pointer_wide() {
    assert_eq!(handle(u64::MAX), u32::MAX);
    assert_eq!(handle(0x0000_0000_0000_0044), 0x44);
    assert_eq!(handle(0x7fff_0000_0000_0044), 0x44);
}

#[test]
fn a_server_pipe_creation_survives_nine_stale_frame_words() {
    let decoded = named_pipe_create(
        [0x1000, STALE | u64::from(GENERIC_READ | SYNCHRONIZE), 0x2000, 0x3000,
         STALE | u64::from(FILE_SHARE_READ | FILE_SHARE_WRITE), STALE | u64::from(FILE_CREATE)],
        [STALE | u64::from(FILE_SYNCHRONOUS_IO_NONALERT), STALE | u64::from(FILE_PIPE_BYTE_STREAM_TYPE),
         STALE, STALE | u64::from(FILE_PIPE_QUEUE_OPERATION), STALE | 4, STALE | 0x1000,
         STALE | 0x1000, 0x9000]).unwrap();
    assert_eq!(decoded.access, GENERIC_READ | SYNCHRONIZE);
    assert_eq!(decoded.sharing, FILE_SHARE_READ | FILE_SHARE_WRITE);
    assert_eq!(decoded.disposition, FILE_CREATE);
    assert_eq!(decoded.options, FILE_SYNCHRONOUS_IO_NONALERT);
    assert_eq!(decoded.pipe_type, FILE_PIPE_BYTE_STREAM_TYPE);
    assert_eq!(decoded.read_mode, 0);
    assert_eq!(decoded.completion_mode, FILE_PIPE_QUEUE_OPERATION);
    assert_eq!(decoded.max_instances, 4);
    assert_eq!(decoded.inbound_quota, 0x1000);
    assert_eq!(decoded.outbound_quota, 0x1000);
    // The timeout is a pointer and keeps every bit the caller passed.
    assert_eq!(decoded.timeout, 0x9000);
    assert_eq!(named_pipe_create([0, 0, 0x2000, 0, 0, 0], [0; 8]), None);
    assert_eq!(named_pipe_create([0x1000, 0, 0, 0, 0, 0], [0; 8]), None);
}

#[test]
fn a_page_sized_read_survives_a_stale_length_word() {
    let decoded = file_io([0x44, 0, 0, 0, 0x4000, 0x5000], STALE | u64::from(PAGE), 0x6000).unwrap();
    assert_eq!(decoded.file, 0x44);
    assert_eq!(decoded.length, PAGE);
    assert_eq!(decoded.io_status, 0x4000);
    assert_eq!(decoded.buffer, 0x5000);
    // The byte offset is a pointer to a sixty-four-bit value, never a count.
    assert_eq!(decoded.offset_ptr, 0x6000);
    assert_eq!(file_io([0x44, 0, 0, 0, 0, 0x5000], 16, 0), None);
    assert_eq!(file_io([0x44, 0, 0, 0, 0x4000, 0], 16, 0), None);
}

#[test]
fn a_segmented_transfer_survives_a_stale_length_word() {
    let decoded = segment_io([0x44, 0, 0, 0x3000, 0x4000, 0x5000], STALE | u64::from(PAGE * 4), 0);
    assert_eq!(decoded.file, 0x44);
    assert_eq!(decoded.length, PAGE * 4);
    assert_eq!(decoded.segments, 0x5000);
    assert_eq!(decoded.apc_context, 0x3000);
}

#[test]
fn object_directory_enumeration_advances_because_restart_is_one_byte() {
    let decoded = directory_object_query([0x44, 0x1000, STALE | 0x400, STALE_BYTES, STALE_BYTES,
        0x2000], [0x3000]).unwrap();
    assert_eq!(decoded.size, 0x400);
    assert!(!decoded.single_entry, "a stale frame word must not turn ReturnSingleEntry TRUE");
    assert!(!decoded.restart, "a stale frame word must not restart the enumeration");
    assert_eq!(decoded.context, 0x2000);
    // The returned-length slot is a pointer the service writes.
    assert_eq!(decoded.return_length, 0x3000);
    let restarting = directory_object_query([0x44, 0x1000, 0x400, 1, STALE_BYTES | 1, 0x2000],
        [0]).unwrap();
    assert!(restarting.single_entry);
    assert!(restarting.restart);
    assert_eq!(restarting.return_length, 0);
}

#[test]
fn a_directory_watch_survives_stale_length_filter_and_subtree_words() {
    let decoded = directory_watch([0x44, 0x45, 0, 0, 0x4000, 0x5000],
        [STALE | 0x200, STALE | u64::from(FILE_NOTIFY_CHANGE_FILE_NAME), STALE_BYTES]).unwrap();
    assert_eq!(decoded.directory, 0x44);
    assert_eq!(decoded.event, 0x45);
    assert_eq!(decoded.length, 0x200);
    assert_eq!(decoded.filter, FILE_NOTIFY_CHANGE_FILE_NAME);
    assert!(!decoded.subtree, "a stale frame word must not request a subtree watch");
    assert!(directory_watch([0x44, 0x45, 0, 0, 0x4000, 0x5000], [0x200, 1, STALE_BYTES | 1])
        .unwrap().subtree);
    assert_eq!(directory_watch([0x44, 0x45, 0, 0, 0, 0x5000], [0x200, 1, 0]), None);
}

#[test]
fn a_lock_request_reads_its_range_as_pointers_and_its_modes_as_bytes() {
    let decoded = file_lock([0x44, 0x45, 0, 0x3000, 0x4000, 0x5000],
        [0x6000, 0x7000, STALE_BYTES, STALE_BYTES | 1]).unwrap();
    assert_eq!(decoded.file, 0x44);
    assert_eq!(decoded.offset_ptr, 0x5000);
    assert_eq!(decoded.count_ptr, 0x6000);
    // The lock key is a pointer, never a count to be bounded.
    assert_eq!(decoded.key_ptr, 0x7000);
    assert!(!decoded.dont_wait, "a stale frame word must not turn a waiting lock into a try-lock");
    assert!(decoded.exclusive);
    assert_eq!(file_lock([0x44, 0, 0, 0, 0x4000, 0], [0x6000, 0, 0, 0]), None);
    assert_eq!(file_lock([0x44, 0, 0, 0, 0x4000, 0x5000], [0, 0, 0, 0]), None);
}

#[test]
fn an_unlock_request_is_a_handle_and_four_pointers() {
    let decoded = file_unlock([0x7fff_0000_0000_0044, 0x4000, 0x5000, 0x6000, 0x7000, 0]).unwrap();
    assert_eq!(decoded.file, 0x44);
    assert_eq!(decoded.io_status, 0x4000);
    assert_eq!(decoded.offset_ptr, 0x5000);
    assert_eq!(decoded.count_ptr, 0x6000);
    assert_eq!(decoded.key_ptr, 0x7000);
    assert_eq!(file_unlock([0x44, 0x4000, 0, 0x6000, 0, 0]), None);
    assert_eq!(file_unlock([0x44, 0x4000, 0x5000, 0, 0, 0]), None);
}

#[test]
fn an_information_query_survives_a_stale_length_and_class_word() {
    let decoded = file_information([0x44, 0x2000, 0x3000, STALE | 24,
        STALE | u64::from(FILE_STANDARD_INFORMATION), 0]).unwrap();
    assert_eq!(decoded.length, 24);
    assert_eq!(decoded.class, FILE_STANDARD_INFORMATION);
    assert_eq!(file_information([0x44, 0, 0x3000, 24, 5, 0]), None);
    assert_eq!(file_information([0x44, 0x2000, 0, 24, 5, 0]), None);
}

#[test]
fn a_directory_enumeration_reads_its_mask_as_a_pointer() {
    let decoded = directory_enumeration([0x44, 0x45, 0, 0, 0x4000, 0x5000],
        [STALE | 0x1000, STALE | u64::from(FILE_DIRECTORY_INFORMATION), STALE_BYTES, 0x8000,
         STALE_BYTES | 1]).unwrap();
    assert_eq!(decoded.length, 0x1000);
    assert_eq!(decoded.class, FILE_DIRECTORY_INFORMATION);
    assert!(!decoded.single_entry);
    // The search mask is a counted-string pointer, never a count.
    assert_eq!(decoded.mask, 0x8000);
    assert!(decoded.restart);
    assert_eq!(directory_enumeration([0x44, 0, 0, 0, 0, 0x5000], [0; 5]), None);
}

#[test]
fn a_control_transfer_survives_stale_code_and_length_words() {
    let decoded = device_control([0x44, 0, 0, 0x3000, 0x4000, STALE | u64::from(FSCTL_PIPE_PEEK)],
        [0, STALE, 0x9000, STALE | 0x400]).unwrap();
    assert_eq!(decoded.code, FSCTL_PIPE_PEEK);
    assert_eq!(decoded.input, 0);
    assert_eq!(decoded.input_length, 0);
    assert_eq!(decoded.output, 0x9000);
    assert_eq!(decoded.output_length, 0x400);
    assert_eq!(device_control([0x44, 0, 0, 0, 0, 0], [0; 4]), None);
}
