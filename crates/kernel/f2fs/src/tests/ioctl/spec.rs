//! Which commands exist, who owns each, and how far each argument travels.
//!
//! The shadowing tests are the ones that matter: a raw handler that claimed a
//! command an earlier stage owns would answer ahead of it, and nothing else
//! in the tree would notice.

use crate::ioctl::spec::*;

#[test]
fn every_command_the_surface_lists_has_a_spec() {
    for &cmd in ALL {
        assert!(spec(cmd).is_some(), "no spec for {cmd:#x}");
        assert!(answers(cmd), "not answered: {cmd:#x}");
        assert!(stage(cmd).is_some(), "no stage for {cmd:#x}");
    }
}

#[test]
fn a_command_this_filesystem_does_not_answer_has_no_spec() {
    // A terminal's window size, which no filesystem answers.
    assert_eq!(spec(0x5413), None);
    assert!(!answers(0x5413));
    assert!(!owns(0x5413));
    assert_eq!(stage(0x5413), None);
}

/// The generic stage runs first and owns the flag commands for every
/// filesystem. A raw handler claiming them would answer ahead of it.
#[test]
fn the_flag_commands_belong_to_the_generic_stage_and_not_to_the_raw_handler() {
    for cmd in [FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_FSGETXATTR, FS_IOC_FSSETXATTR] {
        assert_eq!(stage(cmd), Some(Stage::Generic), "{cmd:#x}");
        assert!(!owns(cmd), "raw handler must not claim {cmd:#x}");
    }
}

#[test]
fn the_version_label_and_trim_commands_belong_to_the_typed_stage() {
    for cmd in [FS_IOC_GETVERSION, FS_IOC_SETVERSION, FS_IOC_GETFSLABEL,
                FS_IOC_SETFSLABEL, FITRIM] {
        assert_eq!(stage(cmd), Some(Stage::FileIoctl), "{cmd:#x}");
        assert!(!owns(cmd), "raw handler must not claim {cmd:#x}");
    }
}

#[test]
fn this_filesystems_own_commands_reach_the_raw_handler() {
    for cmd in [START_ATOMIC_WRITE, GARBAGE_COLLECT, SHUTDOWN, ADD_ENCRYPTION_KEY,
                ENABLE_VERITY, SEC_TRIM_FILE, GET_FEATURES] {
        assert_eq!(stage(cmd), Some(Stage::Raw), "{cmd:#x}");
        assert!(owns(cmd), "{cmd:#x}");
    }
}

/// Exactly one stage per command: two owners is two answers.
#[test]
fn no_command_is_owned_by_two_stages() {
    for &cmd in ALL {
        let s = stage(cmd).unwrap();
        let claims = [s == Stage::Generic, s == Stage::FileIoctl, s == Stage::Raw];
        assert_eq!(claims.iter().filter(|c| **c).count(), 1, "{cmd:#x}");
    }
}

#[test]
fn an_argument_free_command_moves_nothing() {
    for cmd in [WRITE_CHECKPOINT, PRECACHE_EXTENTS, COMMIT_ATOMIC_WRITE,
                START_ATOMIC_REPLACE, COMPRESS_FILE, DECOMPRESS_FILE] {
        assert!(takes_no_argument(cmd), "{cmd:#x}");
        assert_eq!(payload_len(cmd), 0);
        assert!(!reads_payload(cmd));
        assert!(!writes_payload(cmd));
    }
}

/// The two oldest encryption commands have direction bits that contradict
/// what they do, so the spec must not agree with the number.
#[test]
fn the_inverted_encryption_directions_are_stated_not_derived() {
    assert_eq!(ioc_dir(SET_ENCRYPTION_POLICY), IOC_READ);
    assert!(reads_payload(SET_ENCRYPTION_POLICY));
    assert!(!writes_payload(SET_ENCRYPTION_POLICY));

    assert_eq!(ioc_dir(GET_ENCRYPTION_POLICY), IOC_WRITE);
    assert!(writes_payload(GET_ENCRYPTION_POLICY));
    assert!(!reads_payload(GET_ENCRYPTION_POLICY));
}

/// Three commands name further buffers through pointers inside the payload,
/// and one carries its key past the size the number encodes. A layer copying
/// only the encoded span would add a key with no bytes and enable verity with
/// no salt.
#[test]
fn the_commands_that_name_further_buffers_say_so() {
    assert_eq!(spec(ENABLE_VERITY).unwrap().indirect, Indirect::VerityEnable);
    assert_eq!(spec(MEASURE_VERITY).unwrap().indirect, Indirect::VerityMeasure);
    assert_eq!(spec(READ_VERITY_METADATA).unwrap().indirect, Indirect::VerityReadMetadata);
    assert_eq!(spec(ADD_ENCRYPTION_KEY).unwrap().indirect, Indirect::AddKeyRaw);
    assert_eq!(spec(FS_IOC_SETFSLABEL).unwrap().indirect, Indirect::LabelString);
    assert_eq!(spec(SET_ENCRYPTION_POLICY).unwrap().indirect, Indirect::PolicyIn);
}

/// The add-key payload stops before the key itself.
#[test]
fn the_add_key_payload_stops_before_the_key() {
    assert_eq!(payload_len(ADD_ENCRYPTION_KEY), ADD_KEY_ARG_SIZE);
    assert_eq!(ADD_KEY_RAW as u32, ADD_KEY_ARG_SIZE);
}

/// The extended policy query's number encodes a stub size, not the structure
/// it actually moves.
#[test]
fn the_extended_policy_query_moves_more_than_its_number_encodes() {
    assert_eq!(ioc_size(GET_ENCRYPTION_POLICY_EX), POLICY_EX_STUB_SIZE);
    assert_eq!(payload_len(GET_ENCRYPTION_POLICY_EX), POLICY_EX_ARG_SIZE);
}
