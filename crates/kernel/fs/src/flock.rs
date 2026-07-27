// `flock(2)` — BSD whole-file advisory locks. State belongs to the owning
// VFS inode's `i_flctx`; this module owns only syscall ABI and wait policy.
//
// The lock owner is the OPEN FILE DESCRIPTION (Linux `flock_make_lock`:
// `flc_owner = filp`), so a lock is shared by every `dup(2)` of the fd and
// inherited by `fork(2)` — both keep the same `Arc<vfs::File>` alive and its
// address is the owner key. It is released only when the LAST reference drops
// (`File::Drop` → `locks_remove_file`), never on a `close` of one dup.
use vfs::{FlockKind, FlockTry};

pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;
/// `LOCK_MAND` (with its `LOCK_READ`/`LOCK_WRITE` modifiers). Mandatory flock
/// support was removed from Linux; the request is accepted and IGNORED to
/// preserve legacy behaviour (`SYSCALL_DEFINE2(flock)`), never rejected.
pub const LOCK_MAND: u32 = 32;

/// Apply a flock op for an open File. Returns 0 on success or a
/// negative errno.
/// # C: O(holders)
pub fn flock(file: &alloc::sync::Arc<vfs::File>, op_in: u32) -> i64 {
    use syscall::errno::Errno;
    let op = op_in & !LOCK_NB;
    let nb = (op_in & LOCK_NB) != 0;
    if op != LOCK_SH && op != LOCK_EX && op != LOCK_UN {
        return -(Errno::Einval.as_i32() as i64);
    }
    let file_id  = alloc::sync::Arc::as_ptr(file) as *const u8 as usize;
    let ctx = file.inode().file_lock_context();
    let wait_key = ctx.wait_key();
    if op == LOCK_UN {
        if ctx.unlock_flock(file_id) { vfs::file_lock_wake(wait_key); }
        return 0;
    }
    let want = if op == LOCK_SH { FlockKind::Shared } else { FlockKind::Exclusive };
    loop {
        match if nb { ctx.try_flock(file_id, want) } else { ctx.flock_or_park(file_id, want) } {
            FlockTry::Acquired => return 0,
            FlockTry::Blocked { released } => {
                if released { vfs::file_lock_wake(wait_key); }
                if nb { return -(Errno::Eagain.as_i32() as i64); }
                vfs::file_lock_schedule();
                if vfs::file_lock_interrupted() { return -(Errno::Eintr.as_i32() as i64); }
            }
        }
    }
}

/// Linux `flock_translate_cmd(cmd & ~LOCK_NB)` — the operation is one of
/// `LOCK_SH`/`LOCK_EX`/`LOCK_UN` exactly, so `LOCK_SH|LOCK_EX` and any stray
/// bit (`LOCK_READ`, `LOCK_WRITE` without `LOCK_MAND`) is rejected. # C: O(1)
fn flock_cmd_valid(bare: u32) -> bool { bare == LOCK_SH || bare == LOCK_EX || bare == LOCK_UN }

/// `sys_flock(fd, op)` — slot 73.
///
/// Error ORDER is Linux's and is observable: `LOCK_MAND` short-circuits to
/// success before anything else, then an unrecognised operation is `EINVAL`
/// *before* the fd is looked up (`flock(-1, 99)` is `EINVAL`, not `EBADF`),
/// then a bad fd is `EBADF`, then a description carrying neither `FMODE_READ`
/// nor `FMODE_WRITE` — an `O_PATH` fd — is `EBADF` for any non-unlock op.
/// # C: O(holders)
pub fn sys_flock(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let op = args.a1 as u32;
    if op & LOCK_MAND != 0 { return 0; }
    let bare = op & !LOCK_NB;
    if !flock_cmd_valid(bare) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if bare != LOCK_UN && !file.f_mode().intersects(vfs::Fmode::READ | vfs::Fmode::WRITE) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    flock(&file, op)
}
