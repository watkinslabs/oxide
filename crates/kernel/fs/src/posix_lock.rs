// POSIX record locks per `fcntl(2)` F_SETLK / F_GETLK / F_SETLKW plus Linux
// open-file-description locks F_OFD_SETLK / F_OFD_GETLK / F_OFD_SETLKW.
// Work-fn layer (`docs/53`): ABI decode/encode plus the wait policy. The lock
// state itself is inode-owned (`vfs::FileLockContext`, Linux
// `inode->i_flctx.flc_posix`), so it dies with the inode and is released by
// the same `filp_close` / `__fput` paths Linux uses — never by a table this
// module keeps on the side.
//
// `struct flock` (Linux x86_64; aarch64 matches):
//   off  0..2   l_type   (i16: F_RDLCK=0, F_WRLCK=1, F_UNLCK=2)
//   off  2..4   l_whence (i16: SEEK_SET/CUR/END)
//   off  4..8   pad
//   off  8..16  l_start  (i64)
//   off 16..24  l_len    (i64; 0 = "to EOF")
//   off 24..28  l_pid    (i32)
//   off 28..32  pad

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{KResult, RECORD_END_MAX, RecordLock, RecordOwner, RecordTry, VfsError};

pub use vfs::inode::{F_RDLCK, F_UNLCK, F_WRLCK};

/// `struct flock` byte size on Linux x86_64 (aarch64 matches).
pub const FLOCK_BYTES: usize = 32;

/// `l_whence` values (Linux `include/uapi/linux/fs.h` SEEK_*).
const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

/// Decoded `struct flock` after whence resolution. `len == 0` still means "to
/// EOF" here so the resolved end can be Linux's `OFFSET_MAX`.
#[derive(Copy, Clone, Debug)]
pub struct LockReq {
    pub l_type: i16,
    pub start:  i64, // absolute file offset
    pub len:    i64, // 0 = to EOF
    pub pid:    u32,
}

/// Decode the user-supplied `struct flock` bytes. # C: O(1)
pub fn decode_flock(bytes: &[u8; FLOCK_BYTES], cur_pos: u64, file_size: u64) -> KResult<LockReq> {
    let l_type   = i16::from_le_bytes([bytes[0], bytes[1]]);
    let l_whence = i16::from_le_bytes([bytes[2], bytes[3]]);
    let l_start  = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let l_len    = i64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let base = match l_whence {
        SEEK_SET => 0i64,
        SEEK_CUR => cur_pos as i64,
        SEEK_END => file_size as i64,
        _ => return Err(VfsError::Einval),
    };
    let abs_start = base.saturating_add(l_start);
    Ok(LockReq { l_type, start: abs_start, len: l_len, pid: 0 })
}

/// Encode a probe result back into a user `struct flock`. # C: O(1)
pub fn encode_flock(bytes: &mut [u8; FLOCK_BYTES], req: &LockReq) {
    bytes[0..2].copy_from_slice(&req.l_type.to_le_bytes());
    // l_whence = SEEK_SET (absolute offsets are what we report).
    bytes[2..4].copy_from_slice(&SEEK_SET.to_le_bytes());
    bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&req.start.to_le_bytes());
    bytes[16..24].copy_from_slice(&req.len.to_le_bytes());
    bytes[24..28].copy_from_slice(&req.pid.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
}

/// Resolve a decoded request into the inode-owned record shape. An `l_type`
/// outside `F_RDLCK`/`F_WRLCK`/`F_UNLCK`, a negative `l_start`, or a range
/// that does not advance is `EINVAL` per `fcntl(2)`. # C: O(1)
pub fn resolve(req: &LockReq, owner: RecordOwner, pid: u32) -> KResult<RecordLock> {
    if !matches!(req.l_type, F_RDLCK | F_WRLCK | F_UNLCK) { return Err(VfsError::Einval); }
    if req.start < 0 { return Err(VfsError::Einval); }
    let start = req.start as u64;
    let end = if req.len <= 0 { RECORD_END_MAX } else { start.saturating_add(req.len as u64) };
    if start >= end { return Err(VfsError::Einval); }
    Ok(RecordLock { l_type: req.l_type, start, end, owner, pid })
}

/// Owner identity for a record-lock request. Linux `fcntl_setlk`: POSIX locks
/// use `current->files` — every thread of a process is ONE owner — and OFD
/// locks use `filp`. # C: O(1)
pub fn owner_for(is_ofd: bool, file: &Arc<vfs::File>, files_id: usize) -> RecordOwner {
    if is_ofd { RecordOwner::Ofd(Arc::as_ptr(file) as *const u8 as usize) }
    else { RecordOwner::Files(files_id) }
}

/// Linux `check_fmode_for_setlk` (`fs/locks.c:2547`): a read lock needs
/// `FMODE_READ` and a write lock needs `FMODE_WRITE`, else `EBADF`. Applies to
/// the `F_SETLK*` commands only — `F_GETLK` is exempt. # C: O(1)
pub fn fmode_ok_for_setlk(file: &Arc<vfs::File>, l_type: i16) -> bool {
    match l_type {
        F_RDLCK => file.f_mode().contains(vfs::Fmode::READ),
        F_WRLCK => file.f_mode().contains(vfs::Fmode::WRITE),
        _ => true,
    }
}

/// `F_GETLK` / `F_OFD_GETLK` (Linux `fcntl_getlk` → `posix_test_lock`).
/// Returns the blocking lock, or `None` when the request would succeed — the
/// caller then reports `l_type = F_UNLCK`. # C: O(N_records)
pub fn getlk(file: &Arc<vfs::File>, req: &RecordLock) -> Option<LockReq> {
    let blocker = file.inode().file_lock_context().probe_record_lock(req)?;
    let len = if blocker.end == RECORD_END_MAX { 0 } else { (blocker.end - blocker.start) as i64 };
    Some(LockReq { l_type: blocker.l_type, start: blocker.start as i64, len, pid: blocker.pid })
}

/// `F_SETLK` / `F_OFD_SETLK` (Linux `fcntl_setlk` with a non-blocking
/// `vfs_lock_file`): apply or report `EAGAIN`. Never sleeps.
/// # C: O(N_records^2)
pub fn setlk(file: &Arc<vfs::File>, req: &RecordLock) -> i64 {
    let ctx = file.inode().file_lock_context();
    let wait_key = ctx.wait_key();
    match ctx.try_record_lock(req) {
        RecordTry::Acquired { released } => {
            if released { vfs::file_lock_wake(wait_key); }
            0
        }
        RecordTry::Blocked { .. } => -(Errno::Eagain.as_i32() as i64),
    }
}

/// `F_SETLKW` / `F_OFD_SETLKW` (Linux `fcntl_setlk` → `do_lock_file_wait`,
/// `fs/locks.c:2523`): retry until the conflicting holder releases, sleeping
/// on the inode's file-lock wait queue in between.
///
/// Three properties are load-bearing and each was a real defect:
///  - the wait SLEEPS on the inode wait key, and the release paths
///    (`filp_close`, `__fput`, `F_UNLCK`) wake it — Linux
///    `locks_delete_lock_ctx` → `locks_wake_up_blocks` (`fs/locks.c:925`).
///  - the wait is INTERRUPTIBLE. `fs/locks.c` contains no `-EINTR` and no
///    `-ERESTARTSYS`: `do_lock_file_wait` is a bare `wait_event_interruptible`
///    whose value propagates unchanged from `prepare_to_wait_event`
///    (`kernel/sched/wait.c:309`), i.e. `-ERESTARTSYS`. So `SA_RESTART` makes
///    the acquire resume and eventually succeed, its absence surfaces `EINTR`,
///    and a fatal signal always ends the sleep.
///  - a wait cycle is `EDEADLK`, not a hang (Linux `posix_locks_deadlock`,
///    `fs/locks.c:1101`), and OFD callers are exempt from that check
///    (`fs/locks.c:1114`).
/// # C: sleeps; O(N_records^2) per attempt
pub fn setlkw(file: &Arc<vfs::File>, req: &RecordLock) -> i64 {
    let ctx = file.inode().file_lock_context();
    let wait_key = ctx.wait_key();
    loop {
        match ctx.record_lock_or_park(req) {
            RecordTry::Acquired { released } => {
                vfs::record_lock_unblock(req.owner);
                if released { vfs::file_lock_wake(wait_key); }
                return 0;
            }
            RecordTry::Blocked { blocker } => {
                if !req.owner.is_ofd() && vfs::record_lock_block_on(req.owner, blocker) {
                    vfs::record_lock_unblock(req.owner);
                    return -(Errno::Edeadlk.as_i32() as i64);
                }
                vfs::file_lock_schedule();
                if vfs::file_lock_interrupted() {
                    vfs::record_lock_unblock(req.owner);
                    return syscall::restart::restart_sys();
                }
            }
        }
    }
}
