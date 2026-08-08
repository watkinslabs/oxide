// Ring-wide registrations: personalities, restrictions, enabling a disabled
// ring, the wait clock, cancellation, provided-buffer group status, and
// cross-ring messages.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::ctx::{state, IoUringInode};
use crate::io_uring::personality::snapshot_current;
use crate::io_uring_abi::register_op::*;
use crate::io_uring_abi::restriction::{decode_one, Restrictions, IORING_MAX_RESTRICTIONS,
                                       RESTRICTION_BYTES};
use crate::io_uring_abi::uapi::IORING_SETUP_R_DISABLED;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_REGISTER_PERSONALITY`: freeze the calling task's credentials and
/// hand back the id an SQE names them by. # C: O(N_personalities)
pub fn personality(inode: &IoUringInode) -> i64 {
    let Some(snap) = snapshot_current() else { return err(Errno::Ebadf) };
    let mut g = inode.reg.lock();
    match g.add_personality(Arc::new(snap)) { Ok(id) => id as i64, Err(e) => err(e) }
}

/// `IORING_UNREGISTER_PERSONALITY`. # C: O(1)
pub fn unregister_personality(inode: &IoUringInode, id: u32) -> i64 {
    match inode.reg.lock().remove_personality(id) { Ok(()) => 0, Err(e) => err(e) }
}

/// `IORING_REGISTER_RESTRICTIONS`: allowed only while the ring is still
/// disabled, and only once. A parse failure leaves NOTHING armed, so a
/// half-applied allow-list can never be what a sandbox ends up running under.
/// # C: O(nr)
pub fn restrictions(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if inode.flags & IORING_SETUP_R_DISABLED == 0 { return err(Errno::Ebadfd); }
    if inode.reg.lock().restrictions.registered() { return err(Errno::Ebusy); }
    if arg == 0 || nr > IORING_MAX_RESTRICTIONS { return err(Errno::Einval); }
    let bytes = match (nr as u64).checked_mul(RESTRICTION_BYTES) {
        Some(b) => b as usize, None => return err(Errno::Eoverflow),
    };
    let mut img: Vec<u8> = Vec::new();
    if img.try_reserve_exact(bytes).is_err() { return err(Errno::Enomem); }
    img.resize(bytes, 0);
    if bytes > 0 && uaccess::copy_from_user(&mut img[..], arg).is_err() { return err(Errno::Efault); }

    let mut built = Restrictions::default();
    for i in 0..nr as usize {
        let at = i * RESTRICTION_BYTES as usize;
        let Some((kind, val)) = decode_one(&img[at..]) else { return err(Errno::Einval) };
        if let Err(e) = built.apply(kind, val) { return err(e); }
    }
    if nr == 0 { built.arm_empty(); }
    inode.reg.lock().restrictions = built;
    0
}

/// `IORING_REGISTER_ENABLE_RINGS`: start a ring that was created disabled.
/// # C: O(1)
pub fn enable_rings(inode: &IoUringInode) -> i64 {
    if inode.flags & IORING_SETUP_R_DISABLED == 0 { return err(Errno::Ebadfd); }
    if !inode.clear_state(state::DISABLED) { return err(Errno::Ebadfd); }
    0
}

/// `IORING_REGISTER_CLOCK`: choose the clock the wait timeout is measured
/// against. Only the two clocks a timeout can actually be measured on are
/// accepted; naming any other would silently change the meaning of every
/// later wait. # C: O(1)
pub fn clock(inode: &IoUringInode, arg: u64) -> i64 {
    use crate::io_uring::rsrc::{CLOCK_BOOTTIME, CLOCK_MONOTONIC};
    let mut b = [0u8; CLOCK_REGISTER_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let clockid = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    if b[4..].iter().any(|&x| x != 0) { return err(Errno::Einval); }
    if clockid != CLOCK_MONOTONIC && clockid != CLOCK_BOOTTIME { return err(Errno::Einval); }
    inode.reg.lock().clockid = clockid;
    0
}

/// `IORING_REGISTER_SYNC_CANCEL`: cancel matching in-flight requests and wait
/// for the ones that are already running to finish, up to the caller's own
/// deadline. Finding nothing is a success — the caller asked for those
/// requests to be gone and they are — but a request that stays running past
/// the deadline is ETIME, because that one is genuinely still there.
/// # C: O(N_inflight) per attempt
pub fn sync_cancel(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    use crate::io_uring_abi::cancel::{decode_sync_cancel, sync_cancel_result, SYNC_CANCEL_BYTES};
    let mut b = [0u8; SYNC_CANCEL_BYTES];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let sc = match decode_sync_cancel(&b) { Ok(s) => s, Err(e) => return err(e) };

    let (nr, rv) = crate::io_uring::cancel::cancel(inode, &sc.key);
    if rv != err(Errno::Ealready) {
        return sync_cancel_result(crate::io_uring_abi::cancel::cancel_result(&sc.key, nr, rv));
    }
    let deadline = match sc.timeout {
        None => 0,
        Some((sec, nsec)) => match syscall::time::timespec_to_ns(sec, nsec) {
            Ok(ns) => crate::io_uring::iowq::worker::now_ns().saturating_add(ns),
            Err(e) => return err(e),
        },
    };
    loop {
        // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock.
        let outcome = unsafe {
            sched::live::wait_event(&inode.cq_wait, sched::task::WaitState::Interruptible,
                                    deadline, crate::io_uring::iowq::worker::now_ns,
                                    || inode.inflight_reqs().iter()
                                        .all(|r| !sc.key.matches(r.user_data(), r.sqe.fd, r.opcode())))
        };
        let (nr, rv) = crate::io_uring::cancel::cancel(inode, &sc.key);
        if rv != err(Errno::Ealready) {
            return sync_cancel_result(crate::io_uring_abi::cancel::cancel_result(&sc.key, nr, rv));
        }
        match outcome {
            sched::task::WaitOutcome::Interrupted => return err(Errno::Eintr),
            sched::task::WaitOutcome::TimedOut => return err(Errno::Etime),
            sched::task::WaitOutcome::Ready => {}
        }
    }
}

/// `IORING_REGISTER_PBUF_STATUS`: how many buffers a provided-buffer group
/// still holds. # C: O(N_groups)
pub fn pbuf_status(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; BUF_STATUS_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let gid = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    if b[8..].iter().any(|&x| x != 0) { return err(Errno::Einval); }
    if gid > u16::MAX as u32 { return err(Errno::Einval); }
    let Some(n) = inode.reg.lock().buf_group_len(gid as u16) else { return err(Errno::Enoent) };
    b[4..8].copy_from_slice(&n.to_ne_bytes());
    if uaccess::copy_to_user(arg, &b).is_err() { return err(Errno::Efault); }
    0
}

/// `IORING_REGISTER_SEND_MSG_RING`: execute one `IORING_OP_MSG_RING` entry
/// without a ring of one's own. Only the data form is meaningful — sending a
/// descriptor needs a source ring to send it from. # C: O(1)
pub fn send_msg_ring(arg: u64) -> i64 {
    use crate::io_uring::cqe::Cqe;
    use crate::io_uring::dispatch::ring_ops::IORING_MSG_DATA;
    use crate::io_uring_abi::ops::IORING_OP_MSG_RING;
    use crate::io_uring_sqe::{Sqe, SQE_BYTES};

    let mut b = [0u8; SQE_BYTES];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let sqe = Sqe::from_bytes(&b);
    if sqe.flags != 0 { return err(Errno::Einval); }
    if sqe.opcode != IORING_OP_MSG_RING { return err(Errno::Einval); }
    if sqe.addr != IORING_MSG_DATA { return err(Errno::Einval); }

    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return err(Errno::Ebadf) };
    let file = match fdt.clone().get(sqe.fd) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    if !crate::io_uring_identity::is_io_uring_file(&file) { return err(Errno::Ebadfd); }
    let inode = file.inode().clone();
    let Some(target) = crate::io_uring::ring_ctx(&inode) else { return err(Errno::Ebadfd) };
    target.post_cqe(Cqe::new(sqe.off, sqe.len as i32));
    0
}
