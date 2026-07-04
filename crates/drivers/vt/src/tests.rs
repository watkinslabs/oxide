use super::*;

static STATE_SERIAL: Spinlock<(), DriverLockClass> = Spinlock::new(());

#[must_use]
fn reset() -> sync::Guard<'static, (), DriverLockClass> {
    let ser = STATE_SERIAL.lock();
    ACTIVE_VT.store(0, Ordering::Release);
    PENDING_SWITCH.store(0, Ordering::Release);
    OWNER_ALIVE.store(core::ptr::null_mut(), Ordering::Release);
    ON_SWITCH.store(core::ptr::null_mut(), Ordering::Release);
    {
        let mut g = SLOTS.lock();
        for s in g.iter_mut() {
            *s = VtSlot::default();
        }
    }
    ser
}

static REC: Spinlock<alloc::vec::Vec<(u32, u16)>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

fn rec_hook(pid: u32, signo: u16) { REC.lock().push((pid, signo)); }

#[test]
fn init_makes_tty1_active() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    assert_eq!(active(), 1);
    assert!(slot(1).unwrap().allocated);
}

#[test]
fn openqry_returns_first_free() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    assert_eq!(openqry().unwrap(), 2);
}

#[test]
fn activate_switches_and_allocates() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    activate(3).unwrap();
    assert_eq!(active(), 3);
    assert!(slot(3).unwrap().allocated);
}

#[test]
fn activate_rejects_out_of_range() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    assert!(matches!(activate(0), Err(Error::Inval)));
    assert!(matches!(activate(64), Err(Error::Inval)));
}

#[test]
fn lockswitch_blocks_activate() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    lock_switch(1, true).unwrap();
    assert!(matches!(activate(2), Err(Error::Busy)));
    lock_switch(1, false).unwrap();
    activate(2).unwrap();
}

#[test]
fn kdsetmode_kd_graphics_only_when_valid() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    assert!(set_kd_mode(1, KD_GRAPHICS).is_ok());
    assert!(matches!(set_kd_mode(1, 99), Err(Error::Inval)));
    assert_eq!(slot(1).unwrap().kd_mode, KD_GRAPHICS);
}

#[test]
fn kdskbmode_validates_range() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    assert!(set_kb_mode(1, K_UNICODE).is_ok());
    assert!(matches!(set_kb_mode(1, 99), Err(Error::Inval)));
}

#[test]
fn vt_getstate_reports_allocations() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    activate(5).unwrap();
    let st = get_state();
    assert_eq!(st.v_active, 5);
    assert!(st.v_state & (1 << 1) != 0);
    assert!(st.v_state & (1 << 5) != 0);
}

#[test]
fn disallocate_inactive_only() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    activate(2).unwrap();
    assert!(matches!(disallocate(2), Err(Error::Busy)));
    activate(3).unwrap();
    activate(2).unwrap();
    assert!(disallocate(3).is_ok());
    assert!(!slot(3).unwrap().allocated);
}

#[test]
fn vtmode_size() {
    assert_eq!(core::mem::size_of::<VtMode>(), 8);
}

#[test]
fn set_get_vt_mode_roundtrips() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    let m = VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 12, frsig: 0 };
    set_vt_mode(1, m, 42, 7000).unwrap();
    let s = slot(1).unwrap();
    assert_eq!(s.vt_mode.mode, VT_PROCESS);
    assert_eq!(s.vt_mode.relsig, 10);
    assert_eq!(s.vt_mode.acqsig, 12);
    assert_eq!(s.owner_vpid, 42);
    assert_eq!(s.owner_tid, 7000);
    set_vt_mode(1, VtMode { mode: VT_AUTO, ..Default::default() }, 42, 7000).unwrap();
    assert_eq!(slot(1).unwrap().owner_vpid, 0);
    assert_eq!(slot(1).unwrap().owner_tid, 0);
    assert!(matches!(
        set_vt_mode(1, VtMode { mode: 99, ..Default::default() }, 1, 1),
        Err(Error::Inval)
    ));
}

#[test]
fn process_switch_defers_then_reldisp_completes() {
    let _vts = reset();
    REC.lock().clear();
    set_signal_hook(rec_hook);
    unsafe { init().unwrap(); }
    set_vt_mode(1, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 11, frsig: 0 }, 100, 5000).unwrap();
    set_vt_mode(2, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 20, acqsig: 21, frsig: 0 }, 200, 6000).unwrap();
    activate(2).unwrap();
    assert_eq!(active(), 1);
    assert_eq!(*REC.lock().last().unwrap(), (100u32, 10u16));
    reldisp(1, 100, 5000).unwrap();
    assert_eq!(active(), 2);
    assert_eq!(*REC.lock().last().unwrap(), (200u32, 21u16));
    set_signal_hook(|_, _| {});
}

#[test]
fn process_switch_reldisp_refuse_stays() {
    let _vts = reset();
    REC.lock().clear();
    set_signal_hook(rec_hook);
    unsafe { init().unwrap(); }
    set_vt_mode(1, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 11, frsig: 0 }, 100, 5000).unwrap();
    activate(3).unwrap();
    assert_eq!(active(), 1);
    reldisp(0, 100, 5000).unwrap();
    assert_eq!(active(), 1);
    set_signal_hook(|_, _| {});
}

#[test]
fn set_leds_stored() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    set_leds(1, 0b101).unwrap();
    assert_eq!(slot(1).unwrap().leds, 0b101);
}

#[test]
fn resize_stores_grid_rejects_zero() {
    let _vts = reset();
    unsafe { init().unwrap(); }
    resize(1, 50, 160).unwrap();
    let s = slot(1).unwrap();
    assert_eq!((s.rows, s.cols), (50, 160));
    assert!(matches!(resize(1, 0, 80), Err(Error::Inval)));
    assert!(matches!(resize(1, 24, 0), Err(Error::Inval)));
}

static SW_REC: Spinlock<alloc::vec::Vec<u8>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

fn sw_hook(n: u8) { SW_REC.lock().push(n); }

#[test]
fn reldisp_wrong_caller_refused_stays() {
    let _vts = reset();
    REC.lock().clear();
    set_signal_hook(rec_hook);
    unsafe { init().unwrap(); }
    set_vt_mode(1, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 11, frsig: 0 }, 100, 5000).unwrap();
    activate(2).unwrap();
    assert_eq!(active(), 1);
    assert!(matches!(reldisp(1, 100, 9999), Err(Error::Perm)));
    assert_eq!(active(), 1);
    assert!(matches!(reldisp(1, 999, 5000), Err(Error::Perm)));
    assert_eq!(active(), 1);
    reldisp(1, 100, 5000).unwrap();
    assert_eq!(active(), 2);
    set_signal_hook(|_, _| {});
}

#[test]
fn dead_owner_does_not_defer() {
    let _vts = reset();
    REC.lock().clear();
    set_signal_hook(rec_hook);
    set_owner_alive_hook(|_v, _t| false);
    unsafe { init().unwrap(); }
    set_vt_mode(1, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 11, frsig: 0 }, 100, 5000).unwrap();
    activate(2).unwrap();
    assert_eq!(active(), 2);
    assert!(REC.lock().is_empty());
    set_signal_hook(|_, _| {});
}

#[test]
fn alive_owner_defers() {
    let _vts = reset();
    REC.lock().clear();
    set_signal_hook(rec_hook);
    set_owner_alive_hook(|_v, _t| true);
    unsafe { init().unwrap(); }
    set_vt_mode(1, VtMode { mode: VT_PROCESS, waitv: 0, relsig: 10, acqsig: 11, frsig: 0 }, 100, 5000).unwrap();
    activate(2).unwrap();
    assert_eq!(active(), 1);
    assert_eq!(*REC.lock().last().unwrap(), (100u32, 10u16));
    set_signal_hook(|_, _| {});
}

#[test]
fn switch_hook_fires_on_do_switch() {
    let _vts = reset();
    SW_REC.lock().clear();
    set_switch_hook(sw_hook);
    unsafe { init().unwrap(); }
    activate(4).unwrap();
    assert_eq!(active(), 4);
    assert_eq!(*SW_REC.lock().last().unwrap(), 4u8);
    set_switch_hook(|_n| {});
}
