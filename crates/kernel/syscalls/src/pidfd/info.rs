// `PIDFD_GET_INFO` — snapshot the target and copy out `struct pidfd_info`.
//
// Extensible struct: the caller's length says which published version it
// understands, the reply is truncated to it, and the result mask advertises
// only the fields that actually fit. The field offsets and the mask bits are
// owned by `crate::pidfs_ioctl`.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::pidfs_ioctl::*;

/// # C: O(N_tasks)
pub fn get_info(identity: &Arc<sched::pid::PidIdentity>, want: usize, arg: u64) -> i64 {
    if arg == 0 || arg >= hal::USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let mut request_mask = [0u8; 8];
    if uaccess::copy_from_user(&mut request_mask, arg).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let req_mask = u64::from_ne_bytes(request_mask);
    let released = identity.reaped();

    // Linux `pid_in_current_pidns`: a pidfd can be passed to a process in an
    // unrelated pid namespace, which can name neither the target nor anything
    // about it. That is EREMOTE, distinct from a target that is gone (ESRCH) —
    // reporting ESRCH there would say a running process had exited.
    if let Some(task) = identity.task() {
        let reader = sched::registry::reader_pid_ns();
        if sched::registry::vnr_in(&task, &reader).is_none() {
            return -(Errno::Eremote.as_i32() as i64);
        }
    }
    if released && req_mask & PIDFD_INFO_EXIT == 0 {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let Some(snap) = pidfd::snapshot(identity) else {
        return -(Errno::Esrch.as_i32() as i64);
    };

    let mut out = [0u8; PIDFD_INFO_SIZE_VER3];
    let mut mask: u64 = 0;

    if req_mask & PIDFD_INFO_EXIT != 0 {
        mask |= PIDFD_INFO_EXIT;
        put32(&mut out, INFO_OFF_EXIT_CODE, snap.exit_code as u32);
    }
    // The coredump verdict outlives the task: a pidfd holder polls for exit and
    // then asks what happened, by which time nothing is left to inspect.
    if req_mask & PIDFD_INFO_COREDUMP != 0 {
        if let Some(record) = identity.coredump() {
            mask |= PIDFD_INFO_COREDUMP | PIDFD_INFO_COREDUMP_SIGNAL | PIDFD_INFO_COREDUMP_CODE;
            put32(&mut out, INFO_OFF_COREDUMP_MASK, record.mask);
            put32(&mut out, INFO_OFF_COREDUMP_SIGNAL, record.signal);
            put32(&mut out, INFO_OFF_COREDUMP_CODE, record.code);
        }
    }

    if !released {
        // Identifiers and credentials come back whether or not they were asked
        // for; every other field is opt-in.
        mask |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;
        put32(&mut out, INFO_OFF_PID,      snap.pid);
        put32(&mut out, INFO_OFF_PID + 4,  snap.tgid);
        put32(&mut out, INFO_OFF_PID + 8,  snap.ppid);
        put32(&mut out, INFO_OFF_PID + 12, snap.ruid);
        put32(&mut out, INFO_OFF_PID + 16, snap.rgid);
        put32(&mut out, INFO_OFF_PID + 20, snap.euid);
        put32(&mut out, INFO_OFF_PID + 24, snap.egid);
        put32(&mut out, INFO_OFF_PID + 28, snap.suid);
        put32(&mut out, INFO_OFF_PID + 32, snap.sgid);
        put32(&mut out, INFO_OFF_PID + 36, snap.fsuid);
        put32(&mut out, INFO_OFF_PID + 40, snap.fsgid);
        mask |= PIDFD_INFO_CGROUPID;
        put64(&mut out, INFO_OFF_CGROUPID, cgroup::cgroup_of(snap.pid as u64));
        // A live target whose numbers do not resolve is one racing its own
        // teardown; report it gone rather than hand out zeros.
        if snap.pid == 0 || snap.tgid == 0 { return -(Errno::Esrch.as_i32() as i64); }
        // A dump decision the process has not faced still reports the rights a
        // dump WOULD be taken under, which is what a supervisor arms itself
        // with before the crash.
        if req_mask & PIDFD_INFO_COREDUMP != 0 && mask & PIDFD_INFO_COREDUMP == 0 {
            if let Some(task) = identity.task() {
                mask |= PIDFD_INFO_COREDUMP;
                let dumpable = task.dumpable.load(core::sync::atomic::Ordering::Acquire);
                put32(&mut out, INFO_OFF_COREDUMP_MASK,
                      ::fs::coredump::dumpable::coredump_rights_mask(dumpable as i32));
            }
        }
    }

    if req_mask & PIDFD_INFO_SUPPORTED_MASK != 0 {
        mask |= PIDFD_INFO_SUPPORTED_MASK;
        put64(&mut out, INFO_OFF_SUPPORTED_MASK, SUPPORTED_MASK);
    }

    // A field the caller's struct is too short to hold must not be advertised
    // in the mask, or userspace reads a bit whose field it never received.
    let length = core::cmp::min(want, out.len());
    mask &= mask_fitting(length);
    put64(&mut out, INFO_OFF_MASK, mask);
    if uaccess::copy_to_user(arg, &out[..length]).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

/// # C: O(1)
fn put32(out: &mut [u8], off: usize, value: u32) {
    out[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// # C: O(1)
fn put64(out: &mut [u8], off: usize, value: u64) {
    out[off..off + 8].copy_from_slice(&value.to_le_bytes());
}
