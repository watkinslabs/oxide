//! Turning a command number and its argument bytes into a request.
//!
//! The padded structures are where this goes wrong silently: a field read at
//! the offset it would have without padding decodes the padding bytes and
//! produces a plausible zero. Every padded argument here is built at the
//! offsets a caller's compiler places them at.

use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::ioctl::arg::KeySpec;
use crate::ioctl::req::{decode, Extra, Req};
use crate::ioctl::uapi::*;

fn none() -> Extra { Extra::default() }

fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

#[test]
fn a_command_this_filesystem_does_not_answer_reports_no_such_operation() {
    assert_eq!(decode(0x5413, &[], &none(), true), Err(Errno::Enotty));
}

#[test]
fn the_two_atomic_start_commands_decode_to_the_same_request_with_different_intent() {
    assert_eq!(decode(START_ATOMIC_WRITE, &[], &none(), true),
               Ok(Req::StartAtomicWrite { replace: false }));
    assert_eq!(decode(START_ATOMIC_REPLACE, &[], &none(), true),
               Ok(Req::StartAtomicWrite { replace: true }));
}

#[test]
fn both_volatile_commands_decode_to_the_one_request() {
    assert_eq!(decode(START_VOLATILE_WRITE, &[], &none(), true), Ok(Req::VolatileWrite));
    assert_eq!(decode(RELEASE_VOLATILE_WRITE, &[], &none(), true), Ok(Req::VolatileWrite));
}

/// Four bytes of padding sit between the flag word and the first address. A
/// decode that packed the structure would read the start out of the padding
/// and get zero for every request.
#[test]
fn the_range_request_reads_past_the_padding_after_its_flag_word() {
    let mut b = vec![0u8; GC_RANGE_SIZE as usize];
    put32(&mut b, 0, 1);
    put64(&mut b, 8, 0x1122_3344);
    put64(&mut b, 16, 0x99);
    assert_eq!(decode(GARBAGE_COLLECT_RANGE, &b, &none(), true),
               Ok(Req::GcRange { sync: true, start: 0x1122_3344, len: 0x99 }));
    // The padding itself is not read: setting it changes nothing.
    put32(&mut b, 4, 0xdead_beef);
    assert_eq!(decode(GARBAGE_COLLECT_RANGE, &b, &none(), true),
               Ok(Req::GcRange { sync: true, start: 0x1122_3344, len: 0x99 }));
}

/// The same padding trap, one field wider: the destination descriptor is a
/// word and the three positions after it are all eight-byte aligned.
#[test]
fn the_move_request_reads_past_the_padding_after_its_descriptor() {
    let mut b = vec![0u8; MOVE_RANGE_SIZE as usize];
    put32(&mut b, 0, 7);
    put32(&mut b, 4, 0xffff_ffff);
    put64(&mut b, 8, 0x1000);
    put64(&mut b, 16, 0x2000);
    put64(&mut b, 24, 0x3000);
    assert_eq!(decode(MOVE_RANGE, &b, &none(), true),
               Ok(Req::MoveRange { dst_fd: 7, pos_in: 0x1000, pos_out: 0x2000, len: 0x3000 }));
}

#[test]
fn the_flush_request_has_two_words_and_no_padding_between_them() {
    let mut b = vec![0u8; FLUSH_DEVICE_SIZE as usize];
    put32(&mut b, 0, 2);
    put32(&mut b, 4, 9);
    assert_eq!(decode(FLUSH_DEVICE, &b, &none(), true),
               Ok(Req::FlushDevice { dev_num: 2, segments: 9 }));
}

#[test]
fn the_file_trim_request_carries_three_full_width_fields() {
    let mut b = vec![0u8; SECTRIM_RANGE_SIZE as usize];
    put64(&mut b, 0, 4096);
    put64(&mut b, 8, 8192);
    put64(&mut b, 16, TRIM_FILE_ZEROOUT);
    assert_eq!(decode(SEC_TRIM_FILE, &b, &none(), true),
               Ok(Req::SecTrimFile { start: 4096, len: 8192, flags: TRIM_FILE_ZEROOUT }));
}

/// The codec pair is two bare bytes with no alignment at all: a decode that
/// assumed word fields would read the second one out of the next structure.
#[test]
fn the_codec_pair_is_two_adjacent_bytes() {
    assert_eq!(decode(SET_COMPRESS_OPTION, &[3, 5], &none(), true),
               Ok(Req::SetCompressOption { algorithm: 3, log_cluster_size: 5 }));
}

#[test]
fn the_free_space_trim_carries_start_length_and_the_smallest_run() {
    let mut b = vec![0u8; FSTRIM_RANGE_SIZE as usize];
    put64(&mut b, 0, 1);
    put64(&mut b, 8, 2);
    put64(&mut b, 16, 3);
    assert_eq!(decode(FITRIM, &b, &none(), true),
               Ok(Req::Fitrim { start: 1, len: 2, minlen: 3 }));
}

#[test]
fn a_synchronous_collection_is_told_apart_from_a_background_one() {
    assert_eq!(decode(GARBAGE_COLLECT, &0u32.to_le_bytes(), &none(), true),
               Ok(Req::Gc { sync: false }));
    assert_eq!(decode(GARBAGE_COLLECT, &1u32.to_le_bytes(), &none(), true),
               Ok(Req::Gc { sync: true }));
    // Any non-zero means synchronous, not just one.
    assert_eq!(decode(GARBAGE_COLLECT, &99u32.to_le_bytes(), &none(), true),
               Ok(Req::Gc { sync: true }));
}

/// The raw key travels past the size the command number encodes, so the copy
/// layer fetches it separately. A count that does not match what the argument
/// declared means the layer could not fetch it all.
#[test]
fn the_raw_key_arrives_beside_the_argument_and_must_match_its_declared_size() {
    let mut b = vec![0u8; ADD_KEY_ARG_SIZE as usize];
    put32(&mut b, ADD_KEY_SPECIFIER + SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    put32(&mut b, ADD_KEY_RAW_SIZE, 32);
    let x = Extra { first: vec![0xab; 32], second: Vec::new() };
    match decode(ADD_ENCRYPTION_KEY, &b, &x, true).unwrap() {
        Req::AddEncryptionKey { key, raw } => {
            assert_eq!(key.raw_size, 32);
            assert_eq!(raw.len(), 32);
        }
        other => panic!("wrong request: {other:?}"),
    }
    let short = Extra { first: vec![0xab; 16], second: Vec::new() };
    assert!(matches!(decode(ADD_ENCRYPTION_KEY, &b, &short, true), Err(Errno::Efault)));
}

/// The two removal commands share one argument and differ only in reach.
#[test]
fn removing_for_one_user_and_for_all_users_share_one_argument() {
    let mut b = vec![0u8; REMOVE_KEY_ARG_SIZE as usize];
    put32(&mut b, REMOVE_KEY_SPECIFIER + SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    let one = decode(REMOVE_ENCRYPTION_KEY, &b, &none(), true).unwrap();
    let all = decode(REMOVE_ENCRYPTION_KEY_ALL_USERS, &b, &none(), true).unwrap();
    assert_eq!(one, Req::RemoveEncryptionKey {
        spec: KeySpec::Identifier([0u8; 16]), all_users: false,
    });
    assert_eq!(all, Req::RemoveEncryptionKey {
        spec: KeySpec::Identifier([0u8; 16]), all_users: true,
    });
}

/// The salt and the signature both arrive beside the argument, and both must
/// match the lengths it declared.
#[test]
fn the_verity_salt_and_signature_arrive_beside_the_argument() {
    let mut b = vec![0u8; VERITY_ENABLE_ARG_SIZE as usize];
    put32(&mut b, VE_VERSION, VERITY_ENABLE_VERSION);
    put32(&mut b, VE_BLOCK_SIZE, 4096);
    put32(&mut b, VE_SALT_SIZE, 8);
    put64(&mut b, VE_SALT_PTR, 0x1000);
    put32(&mut b, VE_SIG_SIZE, 4);
    put64(&mut b, VE_SIG_PTR, 0x2000);
    let x = Extra { first: vec![1; 8], second: vec![2; 4] };
    match decode(ENABLE_VERITY, &b, &x, true).unwrap() {
        Req::EnableVerity { salt, sig, .. } => {
            assert_eq!(salt.len(), 8);
            assert_eq!(sig.len(), 4);
        }
        other => panic!("wrong request: {other:?}"),
    }
    let wrong = Extra { first: vec![1; 7], second: vec![2; 4] };
    assert!(matches!(decode(ENABLE_VERITY, &b, &wrong, true), Err(Errno::Efault)));
}

/// The measurement's argument declares only how much room the caller has; the
/// digest itself comes back.
#[test]
fn the_measurement_argument_declares_the_callers_capacity() {
    let mut b = vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
    b[VD_SIZE..VD_SIZE + 2].copy_from_slice(&64u16.to_le_bytes());
    assert_eq!(decode(MEASURE_VERITY, &b, &none(), true),
               Ok(Req::MeasureVerity { capacity: 64 }));
}

#[test]
fn the_label_arrives_as_a_string_beside_the_argument() {
    let x = Extra { first: b"disk\0".to_vec(), second: Vec::new() };
    assert_eq!(decode(FS_IOC_SETFSLABEL, &[], &x, true),
               Ok(Req::SetFsLabel(b"disk\0".to_vec())));
}

#[test]
fn the_single_word_commands_decode_their_word() {
    assert_eq!(decode(SHUTDOWN, &GOING_DOWN_METASYNC.to_le_bytes(), &none(), true),
               Ok(Req::Shutdown(GOING_DOWN_METASYNC)));
    assert_eq!(decode(SET_PIN_FILE, &1u32.to_le_bytes(), &none(), true),
               Ok(Req::SetPinFile(1)));
    assert_eq!(decode(IO_PRIO, &IOPRIO_WRITE.to_le_bytes(), &none(), true),
               Ok(Req::IoPrio(IOPRIO_WRITE)));
    assert_eq!(decode(RESIZE_FS, &(1u64 << 30).to_le_bytes(), &none(), true),
               Ok(Req::ResizeFs(1 << 30)));
    assert_eq!(decode(FS_IOC_SETVERSION, &7u32.to_le_bytes(), &none(), true),
               Ok(Req::SetVersion(7)));
}

#[test]
fn the_argument_free_commands_decode_to_themselves() {
    for (cmd, want) in [(WRITE_CHECKPOINT, Req::WriteCheckpoint),
                        (PRECACHE_EXTENTS, Req::PrecacheExtents),
                        (COMMIT_ATOMIC_WRITE, Req::CommitAtomicWrite),
                        (ABORT_ATOMIC_WRITE, Req::AbortAtomicWrite),
                        (COMPRESS_FILE, Req::CompressFile),
                        (DECOMPRESS_FILE, Req::DecompressFile),
                        (GET_FEATURES, Req::GetFeatures),
                        (GET_PIN_FILE, Req::GetPinFile),
                        (GET_DEV_ALIAS_FILE, Req::GetDevAliasFile),
                        (GET_COMPRESS_BLOCKS, Req::GetCompressBlocks),
                        (RELEASE_COMPRESS_BLOCKS, Req::ReleaseCompressBlocks),
                        (RESERVE_COMPRESS_BLOCKS, Req::ReserveCompressBlocks),
                        (GET_COMPRESS_OPTION, Req::GetCompressOption),
                        (GET_ENCRYPTION_POLICY, Req::GetEncryptionPolicy),
                        (GET_ENCRYPTION_PWSALT, Req::GetEncryptionPwsalt),
                        (GET_ENCRYPTION_NONCE, Req::GetEncryptionNonce),
                        (FS_IOC_GETFSLABEL, Req::GetFsLabel),
                        (FS_IOC_GETVERSION, Req::GetVersion)] {
        assert_eq!(decode(cmd, &[], &none(), true), Ok(want), "{cmd:#x}");
    }
}

/// Every command the surface lists decodes from a correctly sized zero
/// payload, or refuses it for a stated reason — never for a missing arm.
#[test]
fn every_command_has_a_decode_arm() {
    for &cmd in crate::ioctl::spec::ALL {
        let n = crate::ioctl::spec::payload_len(cmd) as usize;
        let payload = vec![0u8; n];
        let out = decode(cmd, &payload, &none(), true);
        assert_ne!(out, Err(Errno::Enotty), "no decode arm for {cmd:#x}");
    }
}
