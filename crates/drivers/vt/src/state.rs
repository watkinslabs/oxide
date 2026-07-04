use super::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Busy, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Copy, Clone)]
pub struct VtSlot {
    pub kd_mode: u32,
    pub kb_mode: u32,
    pub vt_mode: VtMode,
    pub owner_vpid: u32,
    pub owner_tid: u32,
    pub leds: u32,
    pub cols: u16,
    pub rows: u16,
    pub locked: bool,
    pub allocated: bool,
}

impl Default for VtSlot {
    fn default() -> Self {
        Self {
            kd_mode: KD_TEXT,
            kb_mode: K_XLATE,
            vt_mode: VtMode { mode: VT_AUTO, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 },
            owner_vpid: 0,
            owner_tid: 0,
            leds: 0,
            cols: 80,
            rows: 25,
            locked: false,
            allocated: false,
        }
    }
}

pub static PENDING_SWITCH: AtomicU8 = AtomicU8::new(0);
pub static SIGNAL_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
pub static OWNER_ALIVE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
pub static ON_SWITCH: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
pub static ACTIVE_VT: AtomicU8 = AtomicU8::new(0);
pub static SLOTS: Spinlock<[VtSlot; MAX_NR_CONSOLES], DriverLockClass> = Spinlock::new([
    VtSlot {
        kd_mode: KD_TEXT,
        kb_mode: K_XLATE,
        vt_mode: VtMode { mode: VT_AUTO, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 },
        owner_vpid: 0,
        owner_tid: 0,
        leds: 0,
        cols: 80,
        rows: 25,
        locked: false,
        allocated: false,
    };
    MAX_NR_CONSOLES
]);

pub fn set_signal_hook(f: fn(pid: u32, signo: u16)) {
    SIGNAL_HOOK.store(f as *mut (), Ordering::Release);
}

pub(super) fn fire_signal(pid: u32, signo: u16) {
    if pid == 0 || signo == 0 { return; }
    let raw = SIGNAL_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    let f: fn(u32, u16) = unsafe { core::mem::transmute::<*mut (), fn(u32, u16)>(raw) };
    f(pid, signo);
}

pub fn set_owner_alive_hook(f: fn(vpid: u32, tid: u32) -> bool) {
    OWNER_ALIVE.store(f as *mut (), Ordering::Release);
}

pub(super) fn owner_alive(vpid: u32, tid: u32) -> bool {
    if vpid == 0 && tid == 0 { return false; }
    let raw = OWNER_ALIVE.load(Ordering::Acquire);
    if raw.is_null() { return true; }
    let f: fn(u32, u32) -> bool =
        unsafe { core::mem::transmute::<*mut (), fn(u32, u32) -> bool>(raw) };
    f(vpid, tid)
}

pub fn set_switch_hook(f: fn(n: u8)) {
    ON_SWITCH.store(f as *mut (), Ordering::Release);
}

pub(super) fn fire_switch(n: u8) {
    let raw = ON_SWITCH.load(Ordering::Acquire);
    if raw.is_null() { return; }
    let f: fn(u8) = unsafe { core::mem::transmute::<*mut (), fn(u8)>(raw) };
    f(n);
}

#[derive(Copy, Clone, Debug)]
pub struct VtSlotSnap {
    pub kd_mode: u32,
    pub kb_mode: u32,
    pub vt_mode: VtMode,
    pub owner_vpid: u32,
    pub owner_tid: u32,
    pub leds: u32,
    pub cols: u16,
    pub rows: u16,
    pub locked: bool,
    pub allocated: bool,
}
