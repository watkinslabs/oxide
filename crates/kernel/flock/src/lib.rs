// `flock(2)` — per-inode advisory lock backed by a global registry
// keyed by inode pointer identity. Tracks both the lock kind (SH/EX)
// and the set of File-pointer holders. Last-handle Drop on File
// releases via `vfs::set_drop_hook`.
//
// v1 simplification: no wait queue. Blocking flock without LOCK_NB
// returns EWOULDBLOCK, same as Linux LOCK_NB. Real wait+wake rides
// a follow-up once `inode_times`-style hooks land for sleep+wake.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

use vfs::InodeRef;
use core::sync::atomic::Ordering;

pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;

#[derive(Default)]
struct FlockState {
    /// Either `LOCK_SH` or `LOCK_EX`; `0` shouldn't appear (entry
    /// removed when empty).
    kind: u32,
    /// File-pointer identities currently holding the lock.
    holders: Vec<usize>,
}

static TABLE: Spinlock<BTreeMap<usize, FlockState>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

fn inode_key(inode: &InodeRef) -> usize {
    let raw: *const dyn vfs::Inode = alloc::sync::Arc::as_ptr(inode);
    raw as *const u8 as usize
}

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
    let inode_id = inode_key(file.inode());
    let mut g = TABLE.lock();
    if op == LOCK_UN {
        if let Some(st) = g.get_mut(&inode_id) {
            st.holders.retain(|&id| id != file_id);
            if st.holders.is_empty() { g.remove(&inode_id); }
        }
        file.flock_op.store(0, Ordering::Release);
        return 0;
    }
    let entry = g.entry(inode_id).or_insert_with(FlockState::default);
    let we_hold_already = entry.holders.iter().any(|&id| id == file_id);
    let want_ex = op == LOCK_EX;
    let conflict = if entry.holders.is_empty() {
        false
    } else if we_hold_already && entry.holders.len() == 1 {
        // Only us — free to swap kind.
        false
    } else if want_ex {
        true            // any other holder blocks EX
    } else {
        entry.kind == LOCK_EX
    };
    if conflict {
        // No wait queue v1: NB or not, return EWOULDBLOCK on conflict.
        let _ = nb;
        return -(Errno::Eagain.as_i32() as i64);
    }
    if !we_hold_already { entry.holders.push(file_id); }
    entry.kind = op;
    file.flock_op.store(op, Ordering::Release);
    0
}

/// Drop hook installed on `vfs::File`. Called when the last Arc<File>
/// reference goes away with `flock_op != 0` — release the held lock.
/// # C: O(holders)
fn release_drop(file_id: usize, inode: &InodeRef) {
    let inode_id = inode_key(inode);
    let mut g = TABLE.lock();
    if let Some(st) = g.get_mut(&inode_id) {
        st.holders.retain(|&id| id != file_id);
        if st.holders.is_empty() { g.remove(&inode_id); }
    }
}

/// Wire the `release_drop` hook into vfs at boot. Called once.
/// # C: O(1)
pub fn install_drop_hook() {
    vfs::set_drop_hook(release_drop);
}

/// `sys_flock(fd, op)` — slot 73.
/// # C: O(holders)
pub fn kernel_sys_flock(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let op = args.a1 as u32;
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
    flock(&file, op)
}
