use crate::linux_device::types::LinuxDevice;

pub(crate) const LINUX_OK: i32 = 0;
pub(crate) const LINUX_FALSE: i32 = 0;
pub(crate) const LINUX_TRUE: i32 = 1;
pub(crate) const LINUX_EINVAL: i32 = 22;
pub(crate) const LINUX_EBUSY: i32 = 16;

pub(crate) const PM_EVENT_ON: i32 = 0x0000;
pub(crate) const PM_EVENT_SUSPEND: i32 = 0x0002;
pub(crate) const PM_EVENT_HIBERNATE: i32 = 0x0004;

pub(crate) const RPM_ACTIVE: i32 = 0;
pub(crate) const RPM_RESUMING: i32 = 1;
pub(crate) const RPM_SUSPENDED: i32 = 2;
pub(crate) const RPM_SUSPENDING: i32 = 3;
pub(crate) const RPM_INITIAL_DISABLE_DEPTH: i32 = 1;
pub(crate) const PM_BUSY_TICK: usize = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct LinuxPmMessage {
    pub(crate) event: i32,
}

pub(crate) type PmCb = unsafe extern "C" fn(*mut LinuxDevice) -> i32;
pub(crate) type PmCompleteCb = unsafe extern "C" fn(*mut LinuxDevice);

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct LinuxDevPmInfo {
    pub(crate) runtime_status: i32,
    pub(crate) disable_depth: i32,
    pub(crate) usage_count: i32,
    pub(crate) runtime_error: i32,
    pub(crate) autosuspend_delay: i32,
    pub(crate) last_busy: usize,
    pub(crate) use_autosuspend: bool,
    pub(crate) can_wakeup: bool,
    pub(crate) wakeup_enabled: bool,
}

impl LinuxDevPmInfo {
    pub(crate) const fn new() -> Self {
        Self {
            runtime_status: RPM_ACTIVE,
            disable_depth: RPM_INITIAL_DISABLE_DEPTH,
            usage_count: 0,
            runtime_error: LINUX_OK,
            autosuspend_delay: 0,
            last_busy: 0,
            use_autosuspend: false,
            can_wakeup: false,
            wakeup_enabled: false,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct LinuxDevPmOps {
    pub(crate) prepare: Option<PmCb>,
    pub(crate) complete: Option<PmCompleteCb>,
    pub(crate) suspend: Option<PmCb>,
    pub(crate) resume: Option<PmCb>,
    pub(crate) freeze: Option<PmCb>,
    pub(crate) thaw: Option<PmCb>,
    pub(crate) poweroff: Option<PmCb>,
    pub(crate) restore: Option<PmCb>,
    pub(crate) suspend_late: Option<PmCb>,
    pub(crate) resume_early: Option<PmCb>,
    pub(crate) runtime_suspend: Option<PmCb>,
    pub(crate) runtime_resume: Option<PmCb>,
    pub(crate) runtime_idle: Option<PmCb>,
}
