use super::{codec::*, policy::{self, Owner}};
use super::Context;
use alloc::{vec, vec::Vec};
use ipc::win32_window::{WindowManager, WindowId, WindowRect};
use syscall::nt_compositor::{Monitor, Rect};

const TID: u64 = 37;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
struct Env { windows: WindowManager, hwnd: WindowId, style: u32, ex_style: u32,
    monitors: Option<Vec<Monitor>>, startup: Result<Option<u32>, ()>, fail_rect: bool, fail_show: bool, mutations: usize, invalid_parameter: bool }
impl Env {
    fn new() -> Self {
        let mut windows = WindowManager::new(); let hwnd = windows.create(TID, None, 0).unwrap();
        windows.set_rect(hwnd, WindowRect { left: 2, top: 3, right: 52, bottom: 63 }).unwrap();
        let monitor = Monitor { monitor: Rect { x: 0, y: 0, width: 1920, height: 1080 },
            workarea: Rect { x: 0, y: 24, width: 1920, height: 1056 } };
        Self { windows, hwnd, style: 0, ex_style: 0, monitors: Some(vec![monitor]), startup: Ok(None),
            fail_rect: false, fail_show: false, mutations: 0, invalid_parameter: false }
    }
    fn raw(&self) -> u64 { self.hwnd.raw() as u64 }
    fn rect(&self) -> WindowRect { self.windows.rect(self.hwnd).unwrap() }
    fn visible(&self) -> bool { self.windows.get(self.hwnd).unwrap().visible }
}
impl Owner for Env {
    fn context(&mut self, hwnd: u64) -> Option<Context> {
        let hwnd = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
        self.windows.get(hwnd)?;
        Some(Context { rect: self.windows.rect(hwnd)?, style: self.style, ex_style: self.ex_style })
    }
    fn desktop(&mut self) -> Option<Vec<Monitor>> { self.monitors.clone() }
    fn startup_show(&mut self) -> Result<Option<u32>, ()> { self.startup }
    fn set_rect(&mut self, hwnd: u64, rect: WindowRect) -> u64 {
        self.mutations += 1;
        if self.fail_rect { return STATUS_INVALID_HANDLE; }
        let id = WindowId::from_raw(hwnd as u32).unwrap();
        if self.windows.set_rect(id, rect).is_ok() { 0 } else { STATUS_INVALID_HANDLE }
    }
    fn show(&mut self, hwnd: u64, command: u32) -> u64 {
        self.mutations += 1;
        if self.fail_show { return STATUS_INVALID_HANDLE; }
        self.windows.show(TID, WindowId::from_raw(hwnd as u32).unwrap(), command != SW_HIDE).map(u64::from).unwrap_or(STATUS_INVALID_HANDLE)
    }
    fn invalid_parameter(&mut self) { self.invalid_parameter = true; }
}
fn notepad(show: u32) -> Placement {
    Placement { flags: 0, show, min: (-1,-1), max: (-1,-1),
        normal: WindowRect { left: 100, top: 100, right: 900, bottom: 700 } }
}
fn apply(env: &mut Env, placement: Placement) -> u64 { let hwnd = env.raw(); policy::apply(env, hwnd, &placement.encode()) }

#[test]
fn notepad_normal_placement_shows_hidden_window_and_reports_true() {
    let mut env = Env::new(); assert!(!env.visible());
    assert_eq!(apply(&mut env, notepad(SW_SHOWNORMAL)), 1); assert!(env.visible());
    assert_eq!(env.rect(), WindowRect { left: 100, top: 100, right: 900, bottom: 700 });
    assert_eq!(env.mutations, 2);
}
#[test]
fn default_show_uses_startup_or_normal_without_making_up_maximize_geometry() {
    let mut env = Env::new(); assert_eq!(apply(&mut env, notepad(SW_SHOWDEFAULT)), 1); assert!(env.visible());
    env.startup = Ok(Some(SW_HIDE)); assert_eq!(apply(&mut env, notepad(SW_SHOWDEFAULT)), 1); assert!(!env.visible());
    let old = env.rect(); env.mutations = 0; env.startup = Ok(Some(3));
    assert_eq!(apply(&mut env, notepad(SW_SHOWDEFAULT)), 0); assert_eq!(env.rect(), old); assert_eq!(env.mutations, 0);
}
#[test]
fn placement_layout_is_44_bytes_showcmd_at8_and_points_at12_and20() {
    let value = notepad(SW_SHOWNORMAL); let bytes = value.encode();
    assert_eq!(bytes.len(), 44); assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
    assert_eq!(&bytes[12..28], &[0xff; 16]); assert_eq!(Placement::decode(&bytes), Some(value));
}
#[test]
fn invalid_structure_hwnd_and_pointer_preserve_canonical_state() {
    let mut env = Env::new(); let old = env.rect(); let hwnd = env.raw();
    let bytes = notepad(1).encode();
    for cut in 0..BYTES { assert_eq!(policy::apply(&mut env, hwnd, &bytes[..cut]), 0); }
    let mut bad = bytes; bad[0..4].copy_from_slice(&48u32.to_le_bytes()); assert_eq!(policy::apply(&mut env, hwnd, &bad), 0);
    assert_eq!(policy::apply(&mut env, u64::MAX, &bytes), 0);
    assert_eq!(policy::read_apply(&mut env, hwnd, 0, |_,_| panic!("null copied")), 0);
    assert_eq!(policy::read_apply(&mut env, hwnd, u64::MAX, |_,_| panic!("overflow copied")), 0);
    assert_eq!(policy::read_apply(&mut env, hwnd, 4096, |out,_| { out[..4].copy_from_slice(&bytes[..4]); false }), 0);
    assert_eq!(env.rect(), old); assert!(!env.visible()); assert_eq!(env.mutations, 0);
    assert!(env.invalid_parameter);
}
#[test]
fn native_geometry_or_show_failure_returns_false_not_ntstatus() {
    let mut env = Env::new(); env.fail_rect = true; assert_eq!(apply(&mut env, notepad(1)), 0); assert_eq!(env.mutations, 1);
    env.fail_rect = false; env.fail_show = true; assert_eq!(apply(&mut env, notepad(1)), 0); assert!(!env.visible());
    assert_eq!(policy::show_result(STATUS_INVALID_HANDLE), 0); assert_eq!(policy::show_result(0), 0); assert_eq!(policy::show_result(1), 1);
}
#[test]
fn get_normal_hidden_window_reports_shownormal_without_workarea_offset() {
    let mut env = Env::new(); let hwnd = env.raw();
    let bytes = policy::query(&mut env, hwnd).unwrap(); let p = Placement::decode(&bytes).unwrap();
    assert_eq!(p.show, SW_SHOWNORMAL); assert_eq!(p.min, (-1,-1)); assert_eq!(p.max, (-1,-1)); assert!(!env.visible());
    assert_eq!(p.normal,env.rect());
    assert_eq!(apply(&mut env, notepad(1)), 1);
    assert_eq!(Placement::decode(&policy::query(&mut env, hwnd).unwrap()).unwrap().normal, notepad(1).normal);
}
#[test]
fn child_and_tool_placement_do_not_add_workarea_origin() {
    for (style, ex_style) in [(WS_CHILD, 0), (0, WS_EX_TOOLWINDOW)] {
        let mut env = Env::new(); env.style = style; env.ex_style = ex_style;
        assert_eq!(apply(&mut env, notepad(1)), 1); assert_eq!(env.rect(), notepad(1).normal);
    }
}
#[test]
fn offscreen_rectangle_moves_to_real_workarea_preserving_size() {
    let mut env = Env::new(); let mut p = notepad(1);
    p.normal = WindowRect { left: 3000, top: 2000, right: 3800, bottom: 2600 };
    assert_eq!(apply(&mut env, p), 1);
    assert_eq!(env.rect(), WindowRect { left: 1120, top: 480, right: 1920, bottom: 1080 });
}
#[test]
fn missing_desktop_invalid_rect_and_non_normal_states_cannot_mutate() {
    let mut env = Env::new(); env.monitors = None; assert_eq!(apply(&mut env, notepad(1)), 0); assert_eq!(env.mutations, 0);
    for (left,right) in [(100,99), (i32::MIN,i32::MAX)] {
        let mut p = notepad(1); p.normal.left = left; p.normal.right = right;
        let mut env = Env::new(); assert_eq!(apply(&mut env,p),0); assert_eq!(env.mutations,0);
    }
    for style in [WS_MINIMIZE, WS_MAXIMIZE] { let mut env = Env::new(); env.style = style; assert_eq!(apply(&mut env,notepad(1)),0); assert_eq!(env.mutations,0); }
}
#[test]
fn zero_normal_extent_is_valid_and_show_returns_previous_visibility() {
    let mut env = Env::new(); let mut p = notepad(1); p.normal.right = p.normal.left; p.normal.bottom = p.normal.top;
    assert_eq!(apply(&mut env,p),1); assert_eq!(env.rect().right,env.rect().left);
    let hwnd = env.raw(); assert_eq!(policy::show(&mut env,hwnd,SW_HIDE),1); assert!(!env.visible());
    assert_eq!(policy::show(&mut env,hwnd,SW_SHOWNORMAL),0); assert!(env.visible());
}

#[test]
fn get_checks_caller_length_and_returns_true_only_after_copyout() {
    let mut env = Env::new(); let hwnd = env.raw();
    for length in [0u32, 43, 45, u32::MAX] {
        assert_eq!(policy::read_query(&mut env, hwnd, 4096,
            |out,_| { out.copy_from_slice(&length.to_le_bytes()); true }, |_,_| panic!("invalid length copied")), 0);
    }
    let read = |out: &mut [u8],_: u64| { out.copy_from_slice(&(BYTES as u32).to_le_bytes()); true };
    assert_eq!(policy::read_query(&mut env, u64::MAX, 4096, read, |_,_| panic!("invalid HWND copied")), 0);
    let mut result = [0; BYTES];
    assert_eq!(policy::read_query(&mut env, hwnd, 4096, read, |address, bytes| { assert_eq!(address,4096); result.copy_from_slice(bytes); true }), 1);
    assert_eq!(Placement::decode(&result).unwrap().show, SW_SHOWNORMAL);
    assert_eq!(policy::read_query(&mut env, hwnd, 4096, read, |_,_| false), 0);
    assert_eq!(policy::read_query(&mut env, hwnd, 4096, |_,_| false, |_,_| panic!("bad pointer copied")), 0);
    assert_eq!(env.mutations,0); assert!(!env.visible());
}
