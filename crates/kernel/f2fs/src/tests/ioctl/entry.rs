//! The whole path, end to end, against a real volume: decode, admit, act.
//!
//! These are the tests a unit test of any one stage cannot replace. Each
//! sends a command exactly as a caller would — the real number, the real
//! argument bytes — and requires the answer the caller would see. A stage
//! wired to the wrong neighbour passes every unit test and fails here.

use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

fn one_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    (v, ino)
}

fn send(v: &mut Volume<MemImage>, ino: u32, cmd: u32, payload: &[u8])
    -> Result<Answer, Errno> {
    handle(v, ino, cmd, payload, &Extra::default(), &root())
}

fn payload_of(a: &Answer) -> &[u8] {
    match a {
        Answer::Done(r) => r.payload.as_deref().expect("a payload"),
        Answer::NotBuilt(u) => match *u {},
    }
}

// ---- the stage split ------------------------------------------------------

/// A command an earlier stage owns must NOT be answered here: answering would
/// shadow that stage, and refusing would invent an errno on its behalf. The
/// raw entry reports no such operation, and the caller carries on.
#[test]
fn a_command_an_earlier_stage_owns_is_not_answered_here() {
    let (mut v, ino) = one_file();
    for cmd in [FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_GETVERSION, FS_IOC_GETFSLABEL,
                FITRIM] {
        assert_eq!(send(&mut v, ino, cmd, &[0u8; 32]).map(|_| ()), Err(Errno::Enotty),
                   "{cmd:#x}");
    }
}

#[test]
fn a_command_this_filesystem_does_not_answer_at_all_reports_no_such_operation() {
    let (mut v, ino) = one_file();
    assert_eq!(send(&mut v, ino, 0x5413, &[]).map(|_| ()), Err(Errno::Enotty));
}

// ---- the prologue reaches every command ----------------------------------

/// The two conditions that stop everything are checked ONCE, ahead of the
/// switch, so no command can forget them. The control is a command that would
/// otherwise succeed: without the prologue it answers, with it it does not.
#[test]
fn a_volume_whose_checkpoint_recorded_an_error_answers_no_command() {
    let (mut v, ino) = one_file();
    assert!(send(&mut v, ino, GET_FEATURES, &[]).is_ok());
    // The condition the prologue reads lives in the checkpoint the mount
    // holds, so it is set there rather than through a helper that would only
    // exist for this test.
    v.cp.flags |= crate::flags::CP_ERROR_FLAG;
    for cmd in [GET_FEATURES, GET_PIN_FILE, WRITE_CHECKPOINT, SHUTDOWN] {
        assert_eq!(send(&mut v, ino, cmd, &[0u8; 8]).map(|_| ()), Err(Errno::Eio),
                   "{cmd:#x}");
    }
}

// ---- the queries ----------------------------------------------------------

#[test]
fn asking_what_the_volume_supports_answers_its_feature_word() {
    let (mut v, ino) = one_file();
    let want = v.ioctl_features();
    let a = send(&mut v, ino, GET_FEATURES, &[]).unwrap();
    assert_eq!(payload_of(&a), want.to_le_bytes());
}

#[test]
fn asking_whether_a_file_stands_for_a_device_answers_no() {
    let (mut v, ino) = one_file();
    let a = send(&mut v, ino, GET_DEV_ALIAS_FILE, &[]).unwrap();
    assert_eq!(payload_of(&a), 0u32.to_le_bytes());
}

// ---- pinning through the whole path --------------------------------------

#[test]
fn pinning_through_the_command_reaches_the_medium() {
    let (mut v, ino) = one_file();
    send(&mut v, ino, SET_PIN_FILE, &1u32.to_le_bytes()).unwrap();
    assert_eq!(v.is_pinned(ino), Ok(true));
    send(&mut v, ino, SET_PIN_FILE, &0u32.to_le_bytes()).unwrap();
    assert_eq!(v.is_pinned(ino), Ok(false));
}

/// The ladder's refusals reach the caller through the whole path, not only in
/// the unit test of the ladder.
#[test]
fn pinning_a_file_that_holds_blocks_is_refused_through_the_whole_path() {
    let (mut v, ino) = one_file();
    v.write_file(ino, 0, &[3u8; 8192]).unwrap();
    assert_eq!(send(&mut v, ino, SET_PIN_FILE, &1u32.to_le_bytes()).map(|_| ()),
               Err(Errno::Efbig));
}

#[test]
fn an_unprivileged_caller_is_refused_the_administrative_commands() {
    let (mut v, ino) = one_file();
    let c = Ctx { cap_sys_admin: false, ..root() };
    for cmd in [WRITE_CHECKPOINT, GARBAGE_COLLECT, SHUTDOWN, RESIZE_FS] {
        let n = crate::ioctl::spec::payload_len(cmd) as usize;
        assert_eq!(handle(&mut v, ino, cmd, &vec![0u8; n], &Extra::default(), &c).map(|_| ()),
                   Err(Errno::Eperm), "{cmd:#x}");
    }
}

// ---- checkpointing --------------------------------------------------------

/// The command reaches the checkpoint writer: the volume's version rises.
#[test]
fn writing_a_checkpoint_advances_the_volumes_version() {
    let (mut v, ino) = one_file();
    let before = v.checkpoint().version;
    send(&mut v, ino, WRITE_CHECKPOINT, &[]).unwrap();
    assert!(v.checkpoint().version > before,
            "version {} did not advance", v.checkpoint().version);
}

// ---- keys through the whole path -----------------------------------------

fn add_key_payload(kind: u32, raw_size: u32) -> Vec<u8> {
    let mut b = vec![0u8; ADD_KEY_ARG_SIZE as usize];
    b[ADD_KEY_SPECIFIER + SPEC_TYPE..ADD_KEY_SPECIFIER + SPEC_TYPE + 4]
        .copy_from_slice(&kind.to_le_bytes());
    b[ADD_KEY_RAW_SIZE..ADD_KEY_RAW_SIZE + 4].copy_from_slice(&raw_size.to_le_bytes());
    b
}

fn encrypting_volume() -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_ENCRYPT;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    (v, ino)
}

/// The key-management machinery was reachable from nothing before this
/// surface existed. This is the test that says it is reachable now.
#[test]
fn a_key_added_through_the_command_is_held_by_the_volume() {
    let (mut v, ino) = encrypting_volume();
    let p = add_key_payload(KEY_SPEC_TYPE_IDENTIFIER, 32);
    let x = Extra { first: vec![0x5a; 32], second: Vec::new() };
    let a = handle(&mut v, ino, ADD_ENCRYPTION_KEY, &p, &x, &root()).unwrap();
    // The name comes back DERIVED from the key, not as the caller sent it.
    let out = payload_of(&a);
    let mut id = [0u8; 16];
    id.copy_from_slice(&out[ADD_KEY_SPECIFIER + SPEC_UNION..ADD_KEY_SPECIFIER + SPEC_UNION + 16]);
    assert_ne!(id, [0u8; 16], "the derived name must not be the zeroes sent in");
    assert!(v.holds_encryption_key(&crate::crypto::KeyId::Identifier(id)));
}

#[test]
fn asking_after_a_key_reports_present_only_once_it_is_added() {
    let (mut v, ino) = encrypting_volume();
    let id = v.add_encryption_key(&[0x77; 32]).unwrap();
    let crate::crypto::KeyId::Identifier(bytes) = id else { panic!("derived name") };

    let mut p = vec![0u8; KEY_STATUS_ARG_SIZE as usize];
    p[KEY_STATUS_SPECIFIER + SPEC_TYPE..KEY_STATUS_SPECIFIER + SPEC_TYPE + 4]
        .copy_from_slice(&KEY_SPEC_TYPE_IDENTIFIER.to_le_bytes());
    p[KEY_STATUS_SPECIFIER + SPEC_UNION..KEY_STATUS_SPECIFIER + SPEC_UNION + 16]
        .copy_from_slice(&bytes);
    let a = send(&mut v, ino, GET_ENCRYPTION_KEY_STATUS, &p).unwrap();
    let out = payload_of(&a);
    assert_eq!(&out[KEY_STATUS_STATUS..KEY_STATUS_STATUS + 4],
               KEY_STATUS_PRESENT.to_le_bytes());

    // A name nothing was added under reports absent, which is the control.
    let mut q = p.clone();
    q[KEY_STATUS_SPECIFIER + SPEC_UNION] ^= 0xff;
    let a = send(&mut v, ino, GET_ENCRYPTION_KEY_STATUS, &q).unwrap();
    let out = payload_of(&a);
    assert_eq!(&out[KEY_STATUS_STATUS..KEY_STATUS_STATUS + 4],
               KEY_STATUS_ABSENT.to_le_bytes());
}

#[test]
fn removing_a_key_that_was_never_added_reports_no_such_key() {
    let (mut v, ino) = encrypting_volume();
    let mut p = vec![0u8; REMOVE_KEY_ARG_SIZE as usize];
    p[REMOVE_KEY_SPECIFIER + SPEC_TYPE..REMOVE_KEY_SPECIFIER + SPEC_TYPE + 4]
        .copy_from_slice(&KEY_SPEC_TYPE_IDENTIFIER.to_le_bytes());
    assert_eq!(send(&mut v, ino, REMOVE_ENCRYPTION_KEY, &p).map(|_| ()), Err(Errno::Enokey));
}

#[test]
fn a_volume_without_the_encryption_feature_answers_no_key_command() {
    let (mut v, ino) = one_file();
    let p = add_key_payload(KEY_SPEC_TYPE_IDENTIFIER, 32);
    let x = Extra { first: vec![0x5a; 32], second: Vec::new() };
    assert_eq!(handle(&mut v, ino, ADD_ENCRYPTION_KEY, &p, &x, &root()).map(|_| ()),
               Err(Errno::Eopnotsupp));
}

// ---- the label and the salt through the whole path -----------------------

#[test]
fn the_password_salt_command_answers_sixteen_stable_bytes() {
    let (mut v, ino) = encrypting_volume();
    let a = send(&mut v, ino, GET_ENCRYPTION_PWSALT, &[]).unwrap();
    let first = payload_of(&a).to_vec();
    assert_eq!(first.len(), PWSALT_SIZE as usize);
    assert!(first.iter().any(|b| *b != 0), "a generated salt must not be zeroes");
    let a = send(&mut v, ino, GET_ENCRYPTION_PWSALT, &[]).unwrap();
    assert_eq!(payload_of(&a), &first[..]);
}

// ---- what is admitted and not yet built ----------------------------------

/// EVERY command this filesystem's own handler owns is answered — with a
/// reply or with an errno the contract defines — and none reports its volume
/// operation as missing.
///
/// Stated as a sweep of the whole command set rather than as a list of the
/// ones that are missing. A list shrinks to nothing and then cannot fail; the
/// sweep goes red the moment any command starts reporting itself unbuilt, and
/// it needs no maintenance when a command is built.
#[test]
fn no_command_this_handler_owns_reports_its_volume_operation_as_missing() {
    let (mut v, ino) = one_file();
    let mut seen = 0usize;
    for &cmd in crate::ioctl::spec::ALL {
        if !crate::ioctl::spec::owns(cmd) { continue; }
        seen += 1;
        let n = crate::ioctl::spec::payload_len(cmd) as usize;
        if let Ok(Answer::NotBuilt(u)) = send(&mut v, ino, cmd, &vec![0u8; n]) {
            match u {}
        }
    }
    // A sweep over an empty set proves nothing.
    assert!(seen > 20, "only {seen} commands reached the sweep");
}

/// Emptying a member is meaningless on a volume with one: there is nowhere
/// for the blocks to go, so the ladder refuses it before the work runs. The
/// sweep above therefore never reaches the work, which is why the spread
/// volume below exists.
#[test]
fn emptying_one_device_of_a_single_device_volume_is_refused_by_the_ladder() {
    let (mut v, ino) = one_file();
    let n = crate::ioctl::spec::payload_len(FLUSH_DEVICE) as usize;
    assert_eq!(send(&mut v, ino, FLUSH_DEVICE, &vec![0u8; n]).map(|_| ()),
               Err(Errno::Einval));
}

/// The same command on a volume that HAS a second member runs — which is the
/// only thing that shows the member count reaching the ladder from the volume
/// rather than from a constant, and the work reaching the volume at all.
#[test]
fn emptying_a_member_of_a_spread_volume_is_carried_out() {
    use crate::test_image::spread;
    let split = [("/dev/a", 12u32), ("/dev/b", 3u32)];
    let mut v = spread::mount(test_image::with_root().devices(&split)).expect("mounts");
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    let n = crate::ioctl::spec::payload_len(FLUSH_DEVICE) as usize;
    let mut arg = vec![0u8; n];
    // Member zero, two segments of it.
    arg[4..8].copy_from_slice(&2u32.to_le_bytes());
    let a = handle(&mut v, ino, FLUSH_DEVICE, &arg, &Extra::default(), &root()).expect("runs");
    assert_eq!(a, Answer::Done(crate::ioctl::reply::Reply::done()));
    // A member the volume does not have is still refused by the ladder.
    let mut bad = vec![0u8; n];
    bad[..4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(handle(&mut v, ino, FLUSH_DEVICE, &bad, &Extra::default(), &root()).map(|_| ()),
               Err(Errno::Einval));
}

/// The volatile-write commands are refused BY THE CONTRACT, not because
/// anything is missing: the format kept their numbers and no implementation
/// anywhere has them. They must not appear as not-built.
#[test]
fn a_volatile_write_is_a_contract_refusal_and_not_a_gap() {
    let (mut v, ino) = one_file();
    for cmd in [START_VOLATILE_WRITE, RELEASE_VOLATILE_WRITE] {
        assert_eq!(send(&mut v, ino, cmd, &[]).map(|_| ()), Err(Errno::Eopnotsupp));
    }
}

/// A refusal the ladder makes is an errno, never a not-built report: the two
/// mean different things and a caller branches on the errno.
#[test]
fn a_ladder_refusal_is_an_errno_even_for_a_command_that_is_not_built() {
    let (mut v, ino) = one_file();
    let c = Ctx { fmode_write: false, ..root() };
    assert_eq!(handle(&mut v, ino, START_ATOMIC_WRITE, &[], &Extra::default(), &c).map(|_| ()),
               Err(Errno::Ebadf));
}
