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
    pub(crate) power_state: LinuxPmMessage,
    pub(crate) sleep_flags: u8,
    pub(crate) _to_wakeup: [u8; 59],
    pub(crate) wakeup: *mut core::ffi::c_void,
    pub(crate) _pre_runtime: [u8; 144],
    pub(crate) usage_count: i32,
    pub(crate) child_count: i32,
    pub(crate) runtime_flags0: u8,
    pub(crate) runtime_flags1: u8,
    pub(crate) _runtime_flags2: [u8; 2],
    pub(crate) links_count: u32,
    pub(crate) request: i32,
    pub(crate) runtime_status: i32,
    pub(crate) last_status: i32,
    pub(crate) runtime_error: i32,
    pub(crate) autosuspend_delay: i32,
    pub(crate) _pad0: u32,
    pub(crate) last_busy: u64,
    pub(crate) active_time: u64,
    pub(crate) suspended_time: u64,
    pub(crate) accounting_timestamp: u64,
    pub(crate) subsys_data: *mut core::ffi::c_void,
    pub(crate) set_latency_tolerance: *mut core::ffi::c_void,
    pub(crate) qos: *mut core::ffi::c_void,
    pub(crate) detach_power_off: u8,
    pub(crate) _tail: [u8; 7],
}

impl LinuxDevPmInfo {
    pub(crate) const fn new() -> Self {
        Self {
            power_state: LinuxPmMessage { event: PM_EVENT_ON }, sleep_flags: 0, _to_wakeup: [0; 59],
            wakeup: core::ptr::null_mut(), _pre_runtime: [0; 144],
            usage_count: 0,
            child_count: 0, runtime_flags0: RPM_INITIAL_DISABLE_DEPTH as u8, runtime_flags1: 0,
            _runtime_flags2: [0; 2], links_count: 0, request: 0, runtime_status: RPM_ACTIVE,
            last_status: RPM_ACTIVE,
            runtime_error: LINUX_OK,
            autosuspend_delay: 0,
            _pad0: 0, last_busy: 0, active_time: 0, suspended_time: 0, accounting_timestamp: 0,
            subsys_data: core::ptr::null_mut(), set_latency_tolerance: core::ptr::null_mut(),
            qos: core::ptr::null_mut(), detach_power_off: 0, _tail: [0; 7],
        }
    }

    pub(crate) fn disable_depth(&self) -> i32 { (self.runtime_flags0 & 0x07) as i32 }
    pub(crate) fn set_disable_depth(&mut self, depth: i32) {
        self.runtime_flags0 = (self.runtime_flags0 & !0x07) | (depth.clamp(0, 7) as u8);
    }
    pub(crate) fn can_wakeup(&self) -> bool { self.sleep_flags & 0x01 != 0 }
    pub(crate) fn use_autosuspend(&self) -> bool { self.runtime_flags1 & 0x08 != 0 }
    pub(crate) fn set_use_autosuspend(&mut self, enabled: bool) { if enabled { self.runtime_flags1 |= 0x08; } else { self.runtime_flags1 &= !0x08; } }
    pub(crate) fn set_can_wakeup(&mut self, capable: bool) {
        if capable { self.sleep_flags |= 0x01; } else { self.sleep_flags &= !0x01; self.wakeup = core::ptr::null_mut(); }
    }
    pub(crate) fn wakeup_enabled(&self) -> bool { !self.wakeup.is_null() }
    pub(crate) fn set_wakeup_enabled(&mut self, enabled: bool) { self.wakeup = if enabled { core::ptr::dangling_mut() } else { core::ptr::null_mut() }; }
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
