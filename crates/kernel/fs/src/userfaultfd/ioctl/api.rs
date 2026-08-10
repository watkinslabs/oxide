// UFFDIO_API: negotiate features and report the fd-level ioctl bitmap.

use core::sync::atomic::Ordering;

use crate::userbuf::validate_user_buf_writable;
use crate::userfaultfd::{policy, uapi::*, UfData};

use syscall::errno::Errno;

use super::structs::{cur_cap_sys_ptrace, err, read_req, write_req, UffdioApi};

/// On ANY error the reply object is ZEROED and written back before the errno
/// is returned, which is how a monitor tells "this kernel is too old for the
/// API I asked for" from "I passed a bad argument".
/// # C: O(1)
pub fn ioc_api(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_API_SIZE, 1) { return rv; }
    let Ok(req) = read_req::<UffdioApi>(arg) else { return err(Errno::Efault) };
    let ctx_features = ufd.features.load(Ordering::Acquire);
    match policy::api_negotiate(req.api, req.features, cur_cap_sys_ptrace(), ctx_features) {
        Ok(reply) => {
            let out = UffdioApi { api: req.api, features: reply.features, ioctls: reply.ioctls };
            // A reply the monitor never receives is not a completed handshake:
            // the failure zeroes the object and reports EFAULT, the same shape
            // as the error arm below.
            if write_req(arg, &out).is_err() { return zero_and_fail(arg, Errno::Efault); }
            ufd.features.store(reply.ctx_features, Ordering::Release);
            0
        }
        Err(e) => zero_and_fail(arg, e),
    }
}

/// The failure tail: ZERO the reply object, then report. A write-back that
/// itself faults turns the reported errno into EFAULT — the monitor cannot be
/// told "too old for that API" through an object it never received.
/// # C: O(1)
fn zero_and_fail(arg: u64, e: Errno) -> i64 {
    if write_req(arg, &UffdioApi::default()).is_err() { return err(Errno::Efault); }
    err(e)
}
