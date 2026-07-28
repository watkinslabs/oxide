//! `mq_open(2)`'s existence / access-mode ladder — Linux `prepare_open`
//! (`ipc/mqueue.c:861-886`) and `OPEN_FMODE` (`include/linux/fs.h`).

use syscall::errno::Errno;

/// `O_ACCMODE` mask over `oflag`.
pub const O_ACCMODE: i32 = 3;
/// `O_RDONLY`.
pub const O_RDONLY: i32 = 0;
/// `O_WRONLY`.
pub const O_WRONLY: i32 = 1;
/// `O_RDWR`.
pub const O_RDWR: i32 = 2;
/// `O_CREAT`.
pub const O_CREAT: i32 = 0o100;
/// `O_EXCL`.
pub const O_EXCL: i32 = 0o200;
/// `O_NONBLOCK`.
pub const O_NONBLOCK: i32 = 0o4000;

/// What `prepare_open` decided for this `mq_open`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpenAction {
    /// Negative dentry with `O_CREAT`: build the queue (`vfs_mkobj` →
    /// `mqueue_create_attr`). Linux runs NO access-mode check on this arm —
    /// the fresh description's read/write capability comes from `OPEN_FMODE`
    /// alone, so `O_ACCMODE == 3` yields a descriptor that can neither send
    /// nor receive rather than an error.
    Create,
    /// Positive dentry: `inode_permission()` with the mapped access mask.
    OpenExisting { may_read: bool, may_write: bool },
}

/// Linux `OPEN_FMODE(flags)` = `((flags + 1) & O_ACCMODE)`, bit 0 =
/// `FMODE_READ`, bit 1 = `FMODE_WRITE`. `O_ACCMODE` (3) maps to NEITHER.
/// # C: O(1)
pub const fn open_fmode(oflag: i32) -> (bool, bool) {
    let m = (oflag.wrapping_add(1)) & O_ACCMODE;
    (m & 1 != 0, m & 2 != 0)
}

/// Linux `prepare_open` (`ipc/mqueue.c:861-886`), minus the DAC call the
/// caller makes with the mask this returns.
///
/// * absent + no `O_CREAT` → `ENOENT`
/// * present + `O_CREAT|O_EXCL` → `EEXIST`
/// * present + `O_ACCMODE == 3` → `EINVAL` (`mqueue.c:882-883`; only on the
///   already-exists arm — Linux never runs this test when creating)
/// # C: O(1)
pub fn prepare_open(exists: bool, oflag: i32) -> Result<OpenAction, Errno> {
    if !exists {
        if oflag & O_CREAT == 0 { return Err(Errno::Enoent); }
        return Ok(OpenAction::Create);
    }
    if oflag & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) { return Err(Errno::Eexist); }
    if oflag & O_ACCMODE == (O_RDWR | O_WRONLY) { return Err(Errno::Einval); }
    let (may_read, may_write) = open_fmode(oflag);
    Ok(OpenAction::OpenExisting { may_read, may_write })
}
