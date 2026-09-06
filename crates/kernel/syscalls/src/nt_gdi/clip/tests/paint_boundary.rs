//! Hosted boundary fixture compiles the production paint module unchanged.
extern crate alloc;
use std::sync::{LazyLock, Mutex};
use ipc::win32_gdi::{GdiManager, Rect};
use ipc::win32_window::{PaintSession, PaintSessionError, WindowId, WindowManager, WindowRect};
use syscall::{nt::NtService, SyscallArgs};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000000d;
const PS: u64 = 0x10000;
const HWND: u64 = 1;

struct State {
    gdi: GdiManager, region: Option<WindowRect>, ps: [u8; 80], setter_calls: usize,
    presents: usize, ended: usize, deletes: usize, retains: usize, reject_clip: bool, reject_copy: bool, milestones: usize,
    windows: WindowManager, window: WindowId,
    seed_layout: Option<ipc::win32_gdi::PaintBacking>, seed_calls: usize,
}
impl State {
    fn new(region: WindowRect) -> Self {
        let mut windows = WindowManager::new();
        let window = windows.create(9, None, 0x1234).unwrap();
        windows.set_rect(window, WindowRect { left: 0, top: 0, right: 4, bottom: 4 }).unwrap();
        if region.right > region.left && region.bottom > region.top { windows.invalidate(window, Some(region)).unwrap(); }
        Self { gdi: GdiManager::new(), region: Some(region), ps: [0; 80], setter_calls: 0,
            presents: 0, ended: 0, deletes: 0, retains: 0, reject_clip: false, reject_copy: false, milestones: 0, windows, window, seed_layout: None, seed_calls: 0 }
    }
}
static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::new(region(0, 0, 0, 0))));
static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
fn region(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }
fn win_bool(status: u64) -> u64 { u64::from(status == STATUS_SUCCESS) }

mod nt_window {
    use super::*;
    pub(crate) use crate::paint_prepare_adapter as paint_prepare;
    pub mod caret { pub mod paint { pub(crate) use crate::paint_prepare_adapter::caret::{begin_for_current, end_for_current}; } }
    pub fn window_rect_for_current(hwnd: u32) -> Option<(WindowRect, ())> {
        (hwnd as u64 == HWND).then_some((region(0, 0, 4, 4), ()))
    }
    pub mod paint {
        use super::*;
        pub fn reserve_for_current(hwnd: u64) -> Result<WindowRect, u64> {
            if hwnd != HWND { return Err(STATUS_INVALID_PARAMETER); }
            let mut state = STATE.lock().unwrap();
            let window = state.window;
            state.windows.begin_paint_rect(window).map_err(|_| STATUS_INVALID_PARAMETER)
        }
        pub fn current_region(hwnd: u64) -> Option<ipc::win32_window::PaintRegion> {
            if hwnd != HWND { return None; }
            let state = STATE.lock().unwrap();
            state.windows.paint_region(state.window).ok()
        }
        pub fn current_rect(hwnd: u64) -> Option<WindowRect> {
            if hwnd != HWND { return None; }
            let state = STATE.lock().unwrap();
            state.windows.paint_session(state.window).ok().map(|session| session.damage.unwrap_or(region(0, 0, 0, 0)))
        }
    }
    pub mod paintlease {
        use super::*;
        pub fn bind_paint_dc_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
            let mut state = STATE.lock().unwrap();
            state.windows.bind_paint_dc(WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?, dc)
        }
        pub fn validate_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
            let state = STATE.lock().unwrap();
            state.windows.validate_paint_session(WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?, dc)
        }
        pub fn end_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
            let mut state = STATE.lock().unwrap();
            state.windows.end_paint_session(WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?, dc)
        }
    }
}
#[path = "../../../nt_window/paint_prepare/raw_boundary.rs"]
pub(crate) mod paint_prepare_adapter;
mod nt_gdi {
    use super::*;
    pub fn set_paint_region_for_current(dc: u64, region: ipc::win32_window::PaintRegion) -> Result<(), u64> {
        let mut state = STATE.lock().unwrap(); state.setter_calls += 1;
        if state.reject_clip { return Err(STATUS_INVALID_PARAMETER); }
        state.gdi.set_paint_region(dc as u32, region).map_err(|_| STATUS_INVALID_PARAMETER)
    }
    pub fn seed_paint_for_current(hwnd: u32, dc: u32) -> Result<(), u64> {
        let mut state = STATE.lock().unwrap();
        let layout = state.seed_layout.unwrap_or(ipc::win32_gdi::PaintBacking { width: 4, height: 4,
            client: Rect { left: 0, top: 0, right: 4, bottom: 4 } });
        state.seed_calls += 1;
        state.gdi.seed_paint(hwnd, dc, layout).map_err(|_| STATUS_INVALID_PARAMETER)
    }
    pub fn retain_erase_for_current(hwnd: u32, dc: u32, region: &ipc::win32_window::PaintRegion,
        layout: ipc::win32_gdi::PaintBacking) -> Result<(), u64> {
        let mut state = STATE.lock().unwrap();
        state.retains += 1;
        state.gdi.retain_paint_region(hwnd, dc, region, layout).map(|_| ()).map_err(|_| STATUS_INVALID_PARAMETER)
    }
    pub fn acquire_window_dc_for_current(hwnd: u32, width: i32, height: i32) -> u64 {
        STATE.lock().unwrap().gdi.acquire_window_dc(hwnd, width, height)
            .map(u64::from).unwrap_or(STATUS_INVALID_PARAMETER)
    }
}
mod nt_milestone { pub fn paint_begin() {} pub fn paint_present() { super::STATE.lock().unwrap().milestones += 1; } }
mod uaccess {
    use super::*;
    pub fn copy_to_user(address: u64, bytes: &[u8]) -> Result<(), ()> {
        let mut state = STATE.lock().unwrap();
        if state.reject_copy && address == PS { return Err(()); }
        let offset = address.checked_sub(PS).ok_or(())? as usize;
        let out = state.ps.get_mut(offset..offset.checked_add(bytes.len()).ok_or(())?).ok_or(())?;
        out.copy_from_slice(bytes); Ok(())
    }
    pub fn get_user_u64(address: u64) -> Result<u64, ()> {
        if address != PS { return Err(()); }
        Ok(u64::from_le_bytes(STATE.lock().unwrap().ps[..8].try_into().unwrap()))
    }
}

#[path = "../../../nt_wine_window/paint.rs"]
mod production;

#[path = "../../../nt_gdi/frame.rs"]
mod nt_gdi_frame;

fn native(service: NtService, _: SyscallArgs) -> u64 {
    let mut state = STATE.lock().unwrap();
    match service {
        NtService::BeginWindowPaint => {
            let window = state.window;
            let expected = state.region.filter(|region| region.right > region.left && region.bottom > region.top);
            assert_eq!(state.windows.begin_paint(window), Ok(expected));
            // Deliberately forge PS.rcPaint: production must use admitted region instead.
            for (index, value) in [0i32, 0, 4, 4].into_iter().enumerate() {
                state.ps[12 + index * 4..16 + index * 4].copy_from_slice(&value.to_le_bytes());
            }
            STATUS_SUCCESS
        }
        NtService::EndWindowPaint => {
            state.ended += 1;
            state.region = None;
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}
fn gdi(service: NtService, args: SyscallArgs) -> u64 {
    let mut state = STATE.lock().unwrap();
    match service {
        NtService::CreateCompatibleDc => state.gdi.create_dc(args.a0 as i32, args.a1 as i32).unwrap() as u64,
        NtService::DeleteGdiObject => { state.gdi.delete_object(args.a0 as u32).unwrap(); state.deletes += 1; STATUS_SUCCESS }
        NtService::PresentGdiWindowRegion => {
            let r = state.region.unwrap();
            assert_eq!([args.a2 as i32, args.a3 as i32, args.a4 as i32, args.a5 as i32], [r.left, r.top, r.right, r.bottom]);
            state.presents += 1; STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

#[test]
fn production_begin_end_paint_hooks_constrain_pixels_and_cleanup() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
    for admitted in [region(1, 1, 3, 3), region(0, 0, 0, 0)] {
        *STATE.lock().unwrap() = State::new(admitted);
        let dc = production::begin_paint(&args, native, gdi);
        assert_ne!(dc, 0);
        {
            let mut state = STATE.lock().unwrap();
            assert_eq!(state.setter_calls, 1);
            let r = Rect { left: 2, top: 0, right: 4, bottom: 4 };
            state.gdi.intersect_clip_rect(dc as u32, r).unwrap();
            state.gdi.fill_rect(dc as u32, Rect { left: 0, top: 0, right: 4, bottom: 4 }, 0xffffff).unwrap();
            let mut expected = [0; 16];
            if admitted.right != 0 { expected[6] = 0xffffff; expected[10] = 0xffffff; }
            assert_eq!(state.gdi.pixels(dc as u32).unwrap(), expected);
        }
        assert_eq!(production::end_paint(&args, native, gdi), 1);
        let state = STATE.lock().unwrap();
        assert_eq!(state.presents, usize::from(admitted.right != 0));
        assert_eq!((state.ended, state.deletes), (0, 1));
        assert!(!state.gdi.contains_object(dc as u32));
    }
    for reject_copy in [false, true] {
        let mut state = State::new(region(1, 1, 3, 3));
        state.reject_clip = !reject_copy; state.reject_copy = reject_copy;
        *STATE.lock().unwrap() = state;
        assert_eq!(production::begin_paint(&args, native, gdi), 0);
        let state = STATE.lock().unwrap();
        assert_eq!((state.ended, state.deletes, state.presents), (1, 1, 0));
    }
}

#[test]
fn zero_or_unknown_hwnd_never_enters_native_paint_or_default_surface() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    for hwnd in [0, 0xfeed] {
        *STATE.lock().unwrap() = State::new(region(1, 1, 3, 3));
        let baseline = STATE.lock().unwrap().gdi.live_handles();
        let mut args = [0; 17]; args[0] = hwnd; args[1] = PS;
        assert_eq!(production::begin_paint(&args, native, gdi), 0);
        let state = STATE.lock().unwrap();
        assert_eq!((state.ended, state.deletes, state.presents, state.seed_calls), (0, 0, 0, 0));
        assert_eq!(state.gdi.live_handles(), baseline);
    }
}

#[test]
fn forged_end_dc_validates_before_present_and_keeps_session_active() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = State::new(region(1, 1, 3, 3));
    let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
    let dc = production::begin_paint(&args, native, gdi);
    assert_ne!(dc, 0);
    STATE.lock().unwrap().ps[..8].copy_from_slice(&(dc + 1).to_le_bytes());
    assert_eq!(production::end_paint(&args, native, gdi), 0);
    let state = STATE.lock().unwrap();
    assert_eq!((state.presents, state.ended, state.deletes), (0, 0, 0));
    assert_eq!(state.windows.paint_session(state.window).unwrap().dc, dc as u32);
    assert!(state.gdi.contains_object(dc as u32));
}

#[test]
fn null_paintstruct_runs_terminal_cleanup_and_retains_nonempty_pixels_without_copyout() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = State::new(region(1, 1, 3, 3));
    let (before, backing, before_pixels) = { let mut state = STATE.lock().unwrap();
        let backing = state.gdi.acquire_window_dc(HWND as u32, 4, 4).unwrap();
        (state.ps, backing, state.gdi.pixels(backing).unwrap().to_vec()) };
    let mut args = [0; 17]; args[0] = HWND;
    assert_eq!(production::begin_paint(&args, native, gdi), 0);
    let state = STATE.lock().unwrap();
    assert_eq!(state.ps, before);
    assert_eq!((state.retains, state.ended, state.deletes), (1, 1, 1));
    assert_eq!(state.gdi.window_dc(HWND as u32), Some(backing));
    assert_eq!(state.gdi.pixels(backing).unwrap(), before_pixels.as_slice());
}

#[path = "../../../nt_gdi/nonclient_scroll/paint_boundary.rs"]
mod retention_tests;

#[test]
fn retained_output_finishes_paint_without_claiming_presentation_or_callback() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    for status in [STATUS_SUCCESS, 0x103, STATUS_INVALID_PARAMETER] {
        *STATE.lock().unwrap() = State::new(region(1, 1, 3, 3));
        let mut args = [0; 17]; args[0] = HWND; args[1] = PS;
        let dc = production::begin_paint(&args, native, gdi);
        assert_ne!(dc, 0);
        let submit = |service, args| if service == NtService::PresentGdiWindowRegion { status } else { gdi(service, args) };
        assert_eq!(production::end_paint(&args, native, submit), u64::from(status != STATUS_INVALID_PARAMETER));
        let state = STATE.lock().unwrap();
        assert_eq!(state.milestones, usize::from(status == STATUS_SUCCESS));
        assert_eq!(state.deletes, 1);
        assert!(!state.gdi.contains_object(dc as u32));
        assert!(state.windows.paint_session(state.window).is_err());
    }
}
