/// Handle `PIDFD_GET_INFO` in the ABI layer after pidfd type validation.
/// # C: O(N_tasks)
pub fn handle_pidfd_ioctl(identity: alloc::sync::Arc<sched::pid::PidIdentity>, req: u64, arg: u64) -> i64 {
    use syscall::errno::Errno;

    const PIDFD_GET_INFO_DTN: u64 = 0xC000_FF0B;
    const PIDFD_INFO_PID: u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    const PIDFD_INFO_EXIT: u64 = 1 << 3;
    const PIDFD_INFO_SUPPORTED_MASK: u64 = 1 << 5;
    const SUPPORTED: u64 =
        PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_EXIT | PIDFD_INFO_SUPPORTED_MASK;

    if (req & 0xC000_FFFF) != PIDFD_GET_INFO_DTN {
        return -(Errno::Enotty.as_i32() as i64);
    }
    let want = ((req >> 16) & 0x3FFF) as usize;
    if arg == 0 || arg >= hal::USER_VA_END || want < 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut request_mask = [0u8; 8];
    if uaccess::copy_from_user(&mut request_mask, arg).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let req_mask = u64::from_ne_bytes(request_mask);
    let released = identity.reaped();
    if released && req_mask & PIDFD_INFO_EXIT == 0 {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let info = match pidfd::snapshot(&identity) {
        Some(info) => info,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    let mut out = [0u8; 80];
    let mut mask = 0;
    if !released {
        mask |= PIDFD_INFO_PID | PIDFD_INFO_CREDS;
        out[16..20].copy_from_slice(&info.pid.to_le_bytes());
        out[20..24].copy_from_slice(&info.tgid.to_le_bytes());
        out[24..28].copy_from_slice(&info.ppid.to_le_bytes());
        out[28..32].copy_from_slice(&info.ruid.to_le_bytes());
        out[32..36].copy_from_slice(&info.rgid.to_le_bytes());
        out[36..40].copy_from_slice(&info.euid.to_le_bytes());
        out[40..44].copy_from_slice(&info.egid.to_le_bytes());
        out[44..48].copy_from_slice(&info.suid.to_le_bytes());
        out[48..52].copy_from_slice(&info.sgid.to_le_bytes());
        out[52..56].copy_from_slice(&info.fsuid.to_le_bytes());
        out[56..60].copy_from_slice(&info.fsgid.to_le_bytes());
    }
    if req_mask & PIDFD_INFO_EXIT != 0 {
        mask |= PIDFD_INFO_EXIT;
        out[60..64].copy_from_slice(&info.exit_code.to_le_bytes());
    }
    if req_mask & PIDFD_INFO_SUPPORTED_MASK != 0 && want >= 80 {
        mask |= PIDFD_INFO_SUPPORTED_MASK;
        out[72..80].copy_from_slice(&SUPPORTED.to_le_bytes());
    }
    out[0..8].copy_from_slice(&mask.to_le_bytes());
    let length = core::cmp::min(want, out.len());
    if uaccess::copy_to_user(arg, &out[..length]).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}
