//! Native timerfd itimerspec ABI copies and validation.

use syscall::errno::Errno;

const FIELD_SIZE: usize = core::mem::size_of::<i64>();
const ITIMERSPEC_SIZE: usize = FIELD_SIZE * 4;

pub(super) const TFD_TIMER_ABSTIME: u64 = 1;
pub(super) const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
/// Every flag `timerfd_settime` accepts.
pub(super) const TFD_SETTIME_FLAGS: u64 = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;
pub(super) const TFD_NONBLOCK: u64 = 0o0_004_000;
pub(super) const TFD_CLOEXEC: u64 = 0o2_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawItimerspec {
    pub interval_sec:  i64,
    pub interval_nsec: i64,
    pub value_sec:     i64,
    pub value_nsec:    i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Itimerspec {
    pub interval_ns: u64,
    pub value_ns:    u64,
}

fn decode_field(bytes: &[u8], offset: usize) -> i64 {
    let mut field = [0u8; FIELD_SIZE];
    field.copy_from_slice(&bytes[offset..offset + FIELD_SIZE]);
    i64::from_ne_bytes(field)
}

/// Linux `get_itimerspec64`: import the complete object without validating it.
pub(super) fn read_itimerspec(user: u64) -> Result<RawItimerspec, Errno> {
    let mut bytes = [0u8; ITIMERSPEC_SIZE];
    uaccess::copy_from_user(&mut bytes, user).map_err(|_| Errno::Efault)?;
    Ok(RawItimerspec {
        interval_sec: decode_field(&bytes, 0),
        interval_nsec: decode_field(&bytes, FIELD_SIZE),
        value_sec: decode_field(&bytes, FIELD_SIZE * 2),
        value_nsec: decode_field(&bytes, FIELD_SIZE * 3),
    })
}

/// Linux `do_timerfd_settime`: flags precede `itimerspec64_valid`.
pub(super) fn prepare_itimerspec(
    flags: u64,
    raw: RawItimerspec,
) -> Result<Itimerspec, Errno> {
    if flags & !TFD_SETTIME_FLAGS != 0 {
        return Err(Errno::Einval);
    }
    let interval_ns = syscall::time::timespec_to_ns(raw.interval_sec, raw.interval_nsec)?;
    let value_ns = syscall::time::timespec_to_ns(raw.value_sec, raw.value_nsec)?;
    Ok(Itimerspec { interval_ns, value_ns })
}

fn encode_timespec(bytes: &mut [u8], nanoseconds: u64) {
    let seconds = (nanoseconds / syscall::time::NSEC_PER_SEC) as i64;
    let nanos = (nanoseconds % syscall::time::NSEC_PER_SEC) as i64;
    bytes[..FIELD_SIZE].copy_from_slice(&seconds.to_ne_bytes());
    bytes[FIELD_SIZE..FIELD_SIZE * 2].copy_from_slice(&nanos.to_ne_bytes());
}

/// Linux `put_itimerspec64`: one fault-aware copy of the complete object.
pub(super) fn write_itimerspec(user: u64, spec: Itimerspec) -> Result<(), Errno> {
    let mut bytes = [0u8; ITIMERSPEC_SIZE];
    encode_timespec(&mut bytes[..FIELD_SIZE * 2], spec.interval_ns);
    encode_timespec(&mut bytes[FIELD_SIZE * 2..], spec.value_ns);
    uaccess::copy_to_user(user, &bytes).map_err(|_| Errno::Efault)
}
