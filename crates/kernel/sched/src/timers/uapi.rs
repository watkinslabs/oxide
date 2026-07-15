use syscall::errno::Errno;

pub(super) const TIMER_ABSTIME: u64 = 1;
pub(super) const SIGEV_SIGNAL: i32 = 0;
pub(super) const SIGEV_NONE: i32 = 1;
pub(super) const SIGEV_THREAD_ID: i32 = 4;
pub(super) const SIGALRM: u32 = 14;
pub(super) const SIGNAL_MAX: i32 = 64;
const TIMESPEC_SIZE: u64 = 16;
const ITIMERSPEC_SIZE: u64 = 32;
const SIGEVENT_SIZE: u64 = 64;
const NSEC_PER_SEC: i64 = 1_000_000_000;

#[derive(Copy, Clone)]
pub(super) struct Sigevent {
    pub value: u64,
    pub signo: i32,
    pub notify: i32,
    pub tid: i32,
}

#[derive(Copy, Clone)]
pub(super) struct ItimerSpec { pub interval_ns: u64, pub value_ns: u64 }

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

fn user_range(p: u64, len: u64) -> Result<(), i64> {
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(len).map(|end| end > hal::USER_VA_END).unwrap_or(true)
    {
        return Err(efault());
    }
    Ok(())
}

fn read_timespec_at(bytes: &[u8]) -> Result<u64, i64> {
    let sec = i64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    if sec < 0 || !(0..NSEC_PER_SEC).contains(&nsec) { return Err(einval()); }
    Ok((sec as u64).saturating_mul(NSEC_PER_SEC as u64).saturating_add(nsec as u64))
}

pub(super) fn read_itimerspec(p: u64) -> Result<ItimerSpec, i64> {
    user_range(p, ITIMERSPEC_SIZE)?;
    let mut bytes = [0u8; ITIMERSPEC_SIZE as usize];
    uaccess::copy_from_user(&mut bytes, p).map_err(|_| efault())?;
    Ok(ItimerSpec { interval_ns: read_timespec_at(&bytes[..16])?,
        value_ns: read_timespec_at(&bytes[16..])? })
}

pub(super) fn read_sigevent(p: u64) -> Result<Sigevent, i64> {
    user_range(p, SIGEVENT_SIZE)?;
    let mut bytes = [0u8; SIGEVENT_SIZE as usize];
    uaccess::copy_from_user(&mut bytes, p).map_err(|_| efault())?;
    Ok(Sigevent {
        value: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
        signo: i32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        notify: i32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
        tid: i32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
    })
}

fn write_timespec_at(bytes: &mut [u8], ns: u64) {
    let sec = (ns / NSEC_PER_SEC as u64) as i64;
    let nsec = (ns % NSEC_PER_SEC as u64) as i64;
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    bytes[8..16].copy_from_slice(&nsec.to_ne_bytes());
}

pub(super) fn write_itimerspec(p: u64, spec: crate::timer_model::TimerSetting) -> Result<(), i64> {
    user_range(p, ITIMERSPEC_SIZE)?;
    let mut bytes = [0u8; ITIMERSPEC_SIZE as usize];
    write_timespec_at(&mut bytes[..TIMESPEC_SIZE as usize], spec.interval_ns);
    write_timespec_at(&mut bytes[TIMESPEC_SIZE as usize..], spec.value_ns);
    uaccess::copy_to_user(p, &bytes).map_err(|_| efault())
}

pub(super) fn write_timer_id(p: u64, id: i32) -> Result<(), i64> {
    user_range(p, core::mem::size_of::<i32>() as u64)?;
    uaccess::copy_to_user(p, &id.to_ne_bytes()).map_err(|_| efault())
}
