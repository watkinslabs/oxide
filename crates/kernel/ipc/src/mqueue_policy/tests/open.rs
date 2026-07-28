use crate::mqueue_policy::open::{
    open_fmode, prepare_open, OpenAction, O_CREAT, O_EXCL, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY,
};
use syscall::errno::Errno;

#[test]
fn absent_without_o_creat_is_enoent() {
    assert_eq!(prepare_open(false, O_RDWR), Err(Errno::Enoent));
    assert_eq!(prepare_open(false, O_RDONLY | O_NONBLOCK), Err(Errno::Enoent));
}

#[test]
fn absent_with_o_creat_creates_without_an_accmode_test() {
    // `prepare_open`'s negative arm returns `vfs_mkobj(...)` directly — the
    // `O_ACCMODE == 3` EINVAL only guards the already-exists arm.
    assert_eq!(prepare_open(false, O_CREAT | O_RDWR), Ok(OpenAction::Create));
    assert_eq!(prepare_open(false, O_CREAT | O_EXCL | O_WRONLY), Ok(OpenAction::Create));
    assert_eq!(prepare_open(false, O_CREAT | (O_RDWR | O_WRONLY)), Ok(OpenAction::Create));
}

#[test]
fn existing_with_creat_and_excl_is_eexist() {
    assert_eq!(prepare_open(true, O_CREAT | O_EXCL | O_RDWR), Err(Errno::Eexist));
    // O_CREAT alone on an existing queue is fine — it just opens it.
    assert!(matches!(prepare_open(true, O_CREAT | O_RDWR), Ok(OpenAction::OpenExisting { .. })));
    // O_EXCL alone (no O_CREAT) is not the EEXIST combination.
    assert!(matches!(prepare_open(true, O_EXCL | O_RDWR), Ok(OpenAction::OpenExisting { .. })));
}

#[test]
fn existing_with_accmode_three_is_einval() {
    // `mqueue.c:882-883`.
    assert_eq!(prepare_open(true, O_RDWR | O_WRONLY), Err(Errno::Einval));
}

#[test]
fn eexist_outranks_the_accmode_error() {
    // `mqueue.c:880` is tested before `:882`.
    assert_eq!(prepare_open(true, O_CREAT | O_EXCL | (O_RDWR | O_WRONLY)), Err(Errno::Eexist));
}

#[test]
fn accmode_maps_to_the_linux_open_fmode_pair() {
    assert_eq!(open_fmode(O_RDONLY), (true, false));
    assert_eq!(open_fmode(O_WRONLY), (false, true));
    assert_eq!(open_fmode(O_RDWR), (true, true));
    // `OPEN_FMODE(3)` == 0: neither readable nor writable.
    assert_eq!(open_fmode(O_RDWR | O_WRONLY), (false, false));
    // Flags above O_ACCMODE do not disturb the mapping.
    assert_eq!(open_fmode(O_RDONLY | O_NONBLOCK | O_CREAT), (true, false));
    assert_eq!(open_fmode(O_WRONLY | O_NONBLOCK), (false, true));
}

#[test]
fn the_existing_arm_reports_the_access_mask_the_dac_check_needs() {
    assert_eq!(prepare_open(true, O_RDONLY),
               Ok(OpenAction::OpenExisting { may_read: true, may_write: false }));
    assert_eq!(prepare_open(true, O_WRONLY),
               Ok(OpenAction::OpenExisting { may_read: false, may_write: true }));
    assert_eq!(prepare_open(true, O_RDWR),
               Ok(OpenAction::OpenExisting { may_read: true, may_write: true }));
}
