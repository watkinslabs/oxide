// `IORING_REGISTER_RING_FDS` / `IORING_UNREGISTER_RING_FDS` — Linux
// `io_ringfd_register`/`io_ringfd_unregister` (`io_uring/tctx.c`): register a
// ring fd into the calling TASK's registered-ring array so `io_uring_enter`
// can address it by a small index (`IORING_ENTER_REGISTERED_RING`) instead
// of paying a fd-table lookup every call.
//
// The array itself, its bounds and its slot-allocation policy live in
// `sched::task::io_uring` (ungated, hosted-tested); this file is the thin
// per-entry loop: decode one `struct io_uring_rsrc_update`, resolve the fd
// to a ring `File`, install/remove it, encode the result back. Admission
// (the `resv`/`data` field checks and the partial-success convention) lives
// in `io_uring_abi::register_op` (also ungated).

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring_abi::register_op::{ring_fds_reg_admission, ring_fds_result,
                                       ring_fds_unreg_admission, RSRC_UPDATE_BYTES};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// One `struct io_uring_rsrc_update` — {offset:u32, resv:u32, data:u64}.
/// # C: O(1)
fn read_entry(arg: u64) -> Result<(u32, u32, u64), Errno> {
    let mut b = [0u8; RSRC_UPDATE_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return Err(Errno::Efault); }
    let offset = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let resv   = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let data   = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    Ok((offset, resv, data))
}

/// Write the resolved slot back into `.offset` — the caller reads back which
/// index an `IO_RINGFD_ALLOC_ANY` request landed in. # C: O(1)
fn write_offset(arg: u64, offset: u32) -> Result<(), Errno> {
    let mut b = [0u8; RSRC_UPDATE_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return Err(Errno::Efault); }
    b[0..4].copy_from_slice(&offset.to_ne_bytes());
    if uaccess::copy_to_user(arg, &b).is_err() { return Err(Errno::Efault); }
    Ok(())
}

/// Resolve `fd` in the current task's descriptor table to a ring `File`.
/// `EBADF` for no such fd, `EOPNOTSUPP` for a live fd that isn't a ring —
/// Linux `io_ring_add_registered_fd` (`fget` + `io_is_uring_fops`).
/// # C: O(1)
fn ring_file(fd: i32) -> Result<Arc<File>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?;
    let file = fdt.clone().get(fd).map_err(|_| Errno::Ebadf)?;
    crate::io_uring_identity::admit_ring_fd(&file)?;
    Ok(file)
}

/// `IORING_REGISTER_RING_FDS`: install up to `nr` ring fds into the calling
/// task's registered-ring array. Stops at the first entry that fails; every
/// entry committed before that stays committed (Linux never rolls the loop
/// back). # C: O(nr)
pub fn register(arg: u64, nr: u32) -> i64 {
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    let mut committed = 0u32;
    let mut last = Ok(());
    for i in 0..nr as u64 {
        let entry_at = arg + i * RSRC_UPDATE_BYTES;
        let (offset, resv, data) = match read_entry(entry_at) {
            Ok(v) => v, Err(e) => { last = Err(e); break; }
        };
        if let Err(e) = ring_fds_reg_admission(resv) { last = Err(e); break; }
        let file = match ring_file(data as i32) { Ok(f) => f, Err(e) => { last = Err(e); break; } };
        let installed = cur.io_uring_ring_install(offset, file);
        match installed {
            Ok(slot) => {
                if let Err(e) = write_offset(entry_at, slot) {
                    // The registration itself succeeded; only reporting it
                    // back to userspace failed. Undo the install so the slot
                    // doesn't silently hold a ring the caller can't address.
                    let _ = cur.io_uring_ring_remove(slot);
                    last = Err(e);
                    break;
                }
                committed += 1;
            }
            Err(e) => { last = Err(e); break; }
        }
    }
    ring_fds_result(committed, last)
}

/// `IORING_UNREGISTER_RING_FDS`: clear up to `nr` slots. A slot that is
/// already empty is not an error — Linux's sweep over a sparse array must
/// succeed on the holes. `EINVAL` still stops the loop for an out-of-range
/// offset or a non-zero reserved/data field. # C: O(nr)
pub fn unregister(arg: u64, nr: u32) -> i64 {
    // Linux: `tctx = current->io_uring; if (!tctx) return 0;` — no task
    // context yet means nothing has ever been registered, so the whole call
    // is a trivial success rather than an error.
    let Some(cur) = sched::live::current() else { return 0 };
    let mut committed = 0u32;
    let mut last = Ok(());
    for i in 0..nr as u64 {
        let entry_at = arg + i * RSRC_UPDATE_BYTES;
        let (offset, resv, data) = match read_entry(entry_at) {
            Ok(v) => v, Err(e) => { last = Err(e); break; }
        };
        if let Err(e) = ring_fds_unreg_admission(resv, data, offset) { last = Err(e); break; }
        // Clearing an already-empty slot is success, not failure.
        let _ = cur.io_uring_ring_remove(offset);
        committed += 1;
    }
    ring_fds_result(committed, last)
}
