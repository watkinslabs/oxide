// UFFDIO_API: negotiate features and report the fd-level ioctl bitmap.

use core::sync::atomic::Ordering;

use crate::userbuf::validate_user_buf_writable;
use crate::userfaultfd::{policy, uapi::*, UfData};

use super::structs::{cur_cap_sys_ptrace, err, read_req, UffdioApi};

/// On ANY error the reply object is ZEROED and written back before the errno
/// is returned, which is how a monitor tells "this kernel is too old for the
/// API I asked for" from "I passed a bad argument".
/// # C: O(1)
pub fn ioc_api(ufd: &UfData, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_API_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full 24-byte uffdio_api object.
    let req: UffdioApi = unsafe { read_req(arg) };
    let ctx_features = ufd.features.load(Ordering::Acquire);
    match policy::api_negotiate(req.api, req.features, cur_cap_sys_ptrace(), ctx_features) {
        Ok(reply) => {
            let out = UffdioApi { api: req.api, features: reply.features, ioctls: reply.ioctls };
            // SAFETY: same validated uffdio_api object receives the negotiated reply.
            unsafe { core::ptr::write_unaligned(arg as *mut UffdioApi, out); }
            ufd.features.store(reply.ctx_features, Ordering::Release);
            0
        }
        Err(e) => {
            // SAFETY: same validated uffdio_api object; the error path zeroes it.
            unsafe { core::ptr::write_unaligned(arg as *mut UffdioApi, UffdioApi::default()); }
            err(e)
        }
    }
}
