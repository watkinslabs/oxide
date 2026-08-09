// `IORING_REGISTER_NAPI` / `IORING_UNREGISTER_NAPI`: the busy-poll window a
// wait on this ring honours, and the receive queues it drives.
//
// Both opcodes report the ring's CURRENT settings back to the caller before
// they act, so a refused request still tells the caller what the ring was
// doing. That write-back is why the reserved-field check runs first: it must
// not be the failed copy that decides the caller's buffer contents.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::napi::*;
use crate::io_uring_abi::uapi::IORING_SETUP_IOPOLL;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_REGISTER_NAPI`. # C: O(N_ids)
pub fn register(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    // A polled-completion ring reaps by spinning on its own queues; adding a
    // second spin over the receive path has no waiter to serve.
    if inode.flags & IORING_SETUP_IOPOLL != 0 { return err(Errno::Einval); }

    let mut b = [0u8; NAPI_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let req = Napi::from_bytes(&b);
    if let Err(e) = admit_napi(&req) { return err(e); }

    let cur = inode.reg.lock().napi;
    if uaccess::copy_to_user(arg, &cur.to_wire().to_bytes()).is_err() { return err(Errno::Efault); }

    let action = match napi_action(&req, &cur) { Ok(a) => a, Err(e) => return err(e) };
    let mut g = inode.reg.lock();
    match action {
        // A mode change starts the new mode from an empty list: identifiers
        // collected under the old one describe queues the new mode did not
        // choose, and carrying them over would busy-poll queues nobody asked
        // for.
        NapiAction::SetMode(st) => { g.napi_ids.clear(); g.napi = st; 0 }
        NapiAction::AddId(id) => match add_id(&mut g.napi_ids, id) { Ok(()) => 0, Err(e) => err(e) },
        NapiAction::DelId(id) => match del_id(&mut g.napi_ids, id) { Ok(()) => 0, Err(e) => err(e) },
    }
}

/// `IORING_UNREGISTER_NAPI`. A null `arg` is legal and means "do not report
/// the old settings"; the ring stops busy-polling either way. # C: O(1)
pub fn unregister(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    if arg != 0 {
        let cur = inode.reg.lock().napi;
        if uaccess::copy_to_user(arg, &cur.to_wire().to_bytes()).is_err() {
            return err(Errno::Efault);
        }
    }
    let mut g = inode.reg.lock();
    g.napi = NapiState::inactive();
    g.napi_ids.clear();
    0
}
