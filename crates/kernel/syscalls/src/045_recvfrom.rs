// recvfrom ABI shim: import one buffer, retain one socket, dispatch one receive.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `recvfrom(fd, buf, len, flags, src, srclen)` slot 45. # C: O(1)
pub fn sys_recvfrom(args: &SyscallArgs) -> i64 {
    let _phase_import = crate::syscost_phase::Phase::start(crate::syscost_phase::PH_RECV_IMPORT);
    let user = crate::recv_user::import_recvfrom(args.a1, args.a2 as usize, args.a4, args.a5);
    if let Err(error) = user.validate_payload_range() { return error; }
    drop(_phase_import);
    let _phase_lookup = crate::syscost_phase::Phase::start(crate::syscost_phase::PH_RECV_LOOKUP);
    let target = match crate::recvmsg::lookup(args.a0) {
        Ok(target) => target,
        Err(error) => return error,
    };
    drop(_phase_lookup);
    crate::recvmsg::recv(&target, &user, args.a3)
}
