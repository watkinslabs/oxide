//! The command numbers a caller actually sends.
//!
//! Every constant is derived from the encoding rule and the argument's size,
//! so these tests are the check that the derivation lands on the number the
//! ABI defines. A struct that changes size silently changes its command's
//! number; pinning the number here is what turns that into a failure instead
//! of a command nothing dispatches.

use crate::ioctl::uapi::*;

#[test]
fn the_filesystems_own_commands_carry_their_defined_numbers() {
    assert_eq!(START_ATOMIC_WRITE, 0x0000_f501);
    assert_eq!(COMMIT_ATOMIC_WRITE, 0x0000_f502);
    assert_eq!(START_VOLATILE_WRITE, 0x0000_f503);
    assert_eq!(RELEASE_VOLATILE_WRITE, 0x0000_f504);
    assert_eq!(ABORT_ATOMIC_WRITE, 0x0000_f505);
    assert_eq!(GARBAGE_COLLECT, 0x4004_f506);
    assert_eq!(WRITE_CHECKPOINT, 0x0000_f507);
    assert_eq!(DEFRAGMENT, 0xc010_f508);
    assert_eq!(MOVE_RANGE, 0xc020_f509);
    assert_eq!(FLUSH_DEVICE, 0x4008_f50a);
    assert_eq!(GARBAGE_COLLECT_RANGE, 0x4018_f50b);
    assert_eq!(GET_FEATURES, 0x8004_f50c);
    assert_eq!(SET_PIN_FILE, 0x4004_f50d);
    assert_eq!(GET_PIN_FILE, 0x8004_f50e);
    assert_eq!(PRECACHE_EXTENTS, 0x0000_f50f);
    assert_eq!(RESIZE_FS, 0x4008_f510);
    assert_eq!(GET_COMPRESS_BLOCKS, 0x8008_f511);
    assert_eq!(RELEASE_COMPRESS_BLOCKS, 0x8008_f512);
    assert_eq!(RESERVE_COMPRESS_BLOCKS, 0x8008_f513);
    assert_eq!(SEC_TRIM_FILE, 0x4018_f514);
    assert_eq!(GET_COMPRESS_OPTION, 0x8002_f515);
    assert_eq!(SET_COMPRESS_OPTION, 0x4002_f516);
    assert_eq!(DECOMPRESS_FILE, 0x0000_f517);
    assert_eq!(COMPRESS_FILE, 0x0000_f518);
    assert_eq!(START_ATOMIC_REPLACE, 0x0000_f519);
    assert_eq!(GET_DEV_ALIAS_FILE, 0x8004_f51a);
    assert_eq!(IO_PRIO, 0x4004_f51b);
}

#[test]
fn the_generic_commands_this_filesystem_answers_carry_their_defined_numbers() {
    assert_eq!(SHUTDOWN, 0x8004_587d);
    assert_eq!(FS_IOC_GETVERSION, 0x8008_7601);
    assert_eq!(FS_IOC_SETVERSION, 0x4008_7602);
    assert_eq!(FS_IOC_GETFLAGS, 0x8008_6601);
    assert_eq!(FS_IOC_SETFLAGS, 0x4008_6602);
    assert_eq!(FS_IOC_FSGETXATTR, 0x801c_581f);
    assert_eq!(FS_IOC_FSSETXATTR, 0x401c_5820);
    assert_eq!(FS_IOC_GETFSLABEL, 0x8100_9431);
    assert_eq!(FS_IOC_SETFSLABEL, 0x4100_9432);
    assert_eq!(FITRIM, 0xc018_5879);
}

#[test]
fn the_encryption_commands_carry_their_defined_numbers() {
    assert_eq!(SET_ENCRYPTION_POLICY, 0x800c_6613);
    assert_eq!(GET_ENCRYPTION_PWSALT, 0x4010_6614);
    assert_eq!(GET_ENCRYPTION_POLICY, 0x400c_6615);
    assert_eq!(GET_ENCRYPTION_POLICY_EX, 0xc009_6616);
    assert_eq!(ADD_ENCRYPTION_KEY, 0xc050_6617);
    assert_eq!(REMOVE_ENCRYPTION_KEY, 0xc040_6618);
    assert_eq!(REMOVE_ENCRYPTION_KEY_ALL_USERS, 0xc040_6619);
    assert_eq!(GET_ENCRYPTION_KEY_STATUS, 0xc080_661a);
    assert_eq!(GET_ENCRYPTION_NONCE, 0x8010_661b);
}

#[test]
fn the_verity_commands_carry_their_defined_numbers() {
    assert_eq!(ENABLE_VERITY, 0x4080_6685);
    assert_eq!(MEASURE_VERITY, 0xc004_6686);
    assert_eq!(READ_VERITY_METADATA, 0xc028_6687);
}

/// The two oldest encryption commands have direction bits that contradict
/// what they do. Nothing may read the payload direction off the number.
#[test]
fn the_oldest_encryption_commands_have_inverted_direction_bits() {
    assert_eq!(ioc_dir(SET_ENCRYPTION_POLICY), IOC_READ);
    assert_eq!(ioc_dir(GET_ENCRYPTION_POLICY), IOC_WRITE);
}

#[test]
fn the_encoding_parts_round_trip() {
    let cmd = iowr(MAGIC, 9, MOVE_RANGE_SIZE);
    assert_eq!(ioc_dir(cmd), IOC_READ | IOC_WRITE);
    assert_eq!(ioc_type(cmd), MAGIC);
    assert_eq!(ioc_nr(cmd), 9);
    assert_eq!(ioc_size(cmd), MOVE_RANGE_SIZE);
}

/// The size a command number carries is the C structure's size under natural
/// alignment, padding included. Getting a padded structure's size wrong is
/// the failure this pins: the number stops matching what a caller sends.
#[test]
fn padded_argument_structures_carry_their_padded_size() {
    assert_eq!(ioc_size(GARBAGE_COLLECT_RANGE), 24);
    assert_eq!(ioc_size(MOVE_RANGE), 32);
    assert_eq!(ioc_size(FLUSH_DEVICE), 8);
    assert_eq!(ioc_size(GET_COMPRESS_OPTION), 2);
}
