//! Standalone hosted execution of the production raw window adapter.
//! Signature verified against Fedora-prepared Wine 10.20 include/ntuser.h;
//! DWORD/INT padding and NULL HWND failures are independent of NTSTATUS.
#![allow(dead_code)]

use std::cell::RefCell;
#[path = "../geometry.rs"] mod geometry;
#[path = "../metrics.rs"] mod metrics;
#[path = "../create_context.rs"] mod create_context_contract;
#[path = "../../nt_window_policy.rs"] mod nt_window_policy;
#[path = "../../nt_window/create_lifecycle.rs"] mod create_lifecycle;
const STATUS_INVALID_PARAMETER: u64 = 0xc000000d;
const STATUS_SUCCESS: u64 = 0;
#[derive(Clone, Copy, Default)]
struct SyscallArgs { a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64 }
enum NtService { SetWindowRectValues, DestroyWindow }
struct NtCall { service: NtService, args: SyscallArgs }
#[derive(Default)]
struct State {
    stack: [u64; 17], fault: Option<usize>, reads: Vec<usize>, rect: Option<[i32; 4]>,
    class: Option<(u16, u64)>, menu: Option<u32>, destroyed: usize,
    fail_class: bool, fail_title: bool, fail_menu: bool, fail_rect: bool,
    hwnd: u64,
    placement: geometry::Defaults,
    creation: Option<create_lifecycle::CreateStructArgs>,
    lifecycle_result: Option<u64>,
    lifecycle_enabled: bool,
    lifecycle_calls: usize,
    metadata: Option<(u64, u32, u32, u64)>, control_id: Option<(u64, u64)>,
    registered: Option<(Vec<u16>, u64, i32)>, wndclass: u64, extra: i32,
    registered_unicode: Option<bool>, instance: Option<u64>,
    class_style: u32, registered_style: Option<u32>, registered_background: Option<u64>,
    user_reads: Vec<u64>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
mod create_context {
    pub fn defaults() -> super::geometry::Defaults { super::STATE.with(|s| s.borrow().placement) }
}
mod klog {
    pub fn write_raw(_: &[u8]) {}
    pub fn write_hex_u64(_: u64) {}
}
mod uaccess {
    pub fn get_user_u32(address: u64) -> Result<u32, ()> {
        super::STATE.with(|s| { let mut s = s.borrow_mut(); s.user_reads.push(address);
            if address == s.wndclass { Ok(80) }
            else if address == s.wndclass + 4 { Ok(s.class_style) }
            else if address == s.wndclass + 20 { Ok(s.extra as u32) } else { Err(()) } })
    }
    pub fn get_user_u64(_: u64) -> Result<u64, ()> { Ok(0x1400042c0) }
}
mod nt_dispatch {
    pub fn stack_argument(index: usize) -> Option<u64> {
        super::STATE.with(|s| { let mut s = s.borrow_mut(); s.reads.push(index);
            if s.fault == Some(index) { None } else { Some(s.stack[index]) } })
    }
}
fn read_unicode_string(pointer: u64) -> Option<Vec<u16>> {
    (pointer == 0x7ffe4ba0a3d0).then_some(vec![78])
}
fn read_optional_unicode_string(pointer: u64) -> Option<Vec<u16>> {
    (pointer == 0x7ffe4ba0a3f0 || pointer == 0).then_some(vec![78])
}
mod nt_window {
    use super::*;
    pub(crate) use create_lifecycle::CreateStructArgs;
    pub enum CreateReturnConvention { RawHandle }
    pub fn begin_create_lifecycle_for_current(hwnd: u64, params: CreateStructArgs, _: CreateReturnConvention) -> u64 {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.lifecycle_calls += 1;
            if !s.lifecycle_enabled { return hwnd; }
            assert_eq!(s.instance, Some(params.instance));
            s.creation = Some(params);
            let result = s.lifecycle_result.unwrap_or(hwnd);
            if result == 0 { s.destroyed += 1; }
            result
        })
    }
    pub fn register_class_with_extra_for_current(name: &[u16], wndproc: u64, extra: i32) -> Option<u64> {
        STATE.with(|s| s.borrow_mut().registered = Some((name.to_vec(), wndproc, extra)));
        Some(21)
    }
    pub fn register_class_with_encoding_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool) -> Option<u64> {
        STATE.with(|s| s.borrow_mut().registered_unicode = Some(unicode));
        register_class_with_extra_for_current(name, wndproc, extra)
    }
    pub fn register_class_with_background_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool, style: u32, background: u64) -> Option<u64> {
        STATE.with(|s| s.borrow_mut().registered_background = Some(background));
        register_class_with_style_for_current(name, wndproc, extra, unicode, style)
    }
    pub fn register_class_with_style_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool, style: u32) -> Option<u64> {
        STATE.with(|s| s.borrow_mut().registered_style = Some(style));
        register_class_with_encoding_for_current(name, wndproc, extra, unicode)
    }
    pub fn set_creation_metadata_current(hwnd: u64, style: u32, ex_style: u32, owner: u64, instance: u64) -> Result<(), ()> {
        STATE.with(|s| s.borrow_mut().instance = Some(instance));
        STATE.with(|s| s.borrow_mut().metadata = Some((hwnd, style, ex_style, owner))); Ok(())
    }
    pub fn set_control_id_for_current(hwnd: u64, id: u64) -> Result<(), ()> {
        STATE.with(|s| s.borrow_mut().control_id = Some((hwnd, id))); Ok(())
    }
    pub fn create_class_window_by_atom_for_current(atom: u16, parent: u64) -> Option<u64> {
        STATE.with(|s| { let mut s = s.borrow_mut(); s.class = Some((atom, parent));
            (!s.fail_class).then_some(s.hwnd) })
    }
    pub fn create_class_window_for_current(_: &[u16], parent: u64) -> Option<u64> {
        create_class_window_by_atom_for_current(21, parent)
    }
    pub fn set_window_menu_for_current(_: u64, menu: Option<u32>) -> Result<(), ()> {
        STATE.with(|s| { let mut s = s.borrow_mut(); s.menu = menu;
            if s.fail_menu { Err(()) } else { Ok(()) } })
    }
    pub fn set_window_text_for_current(_: u64, _: &[u16]) -> Result<(), ()> {
        STATE.with(|s| if s.borrow().fail_title { Err(()) } else { Ok(()) })
    }
    pub fn dispatch(call: NtCall) -> Option<u64> {
        STATE.with(|s| { let mut s = s.borrow_mut(); match call.service {
            NtService::DestroyWindow => { s.destroyed += 1; Some(0) }
            NtService::SetWindowRectValues => {
                s.rect = Some([call.args.a1 as i32, call.args.a2 as i32, call.args.a3 as i32, call.args.a4 as i32]);
                Some(if s.fail_rect { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS })
            }
        } })
    }
}
#[path = "../raw_class.rs"] mod raw_class;
#[path = "../create_abi.rs"] mod create_abi;

fn input() -> SyscallArgs {
    STATE.with(|s| { let mut s = s.borrow_mut(); *s = State::default();
        s.lifecycle_enabled = true;
        s.hwnd = 42; s.stack[6] = 20; s.stack[7] = 640; s.stack[8] = 480; });
    SyscallArgs { a1: 0x7ffe4ba0a3d0, a3: 0x7ffe4ba0a3f0, a4: 0xcf0000, a5: 10, ..Default::default() }
}

#[test]
fn production_create_enters_lifecycle_with_windows_payload_and_preserves_pending() {
    let args = input();
    STATE.with(|s| { let mut s = s.borrow_mut();
        s.stack[11] = 0x140000000; s.stack[12] = 0x7ffe12340000;
        s.stack[14] = 0x180000000; s.stack[15] = 0x140008840;
        s.lifecycle_result = Some(0x103);
    });
    assert_eq!(raw_class::create_window(args), 0x103);
    STATE.with(|s| {
        let s = s.borrow();
        let created = s.creation.expect("canonical create lifecycle must be called");
        assert_eq!(created.instance, 0x180000000);
        assert_eq!(created.lp_create_params, 0x7ffe12340000);
        assert_eq!(created.class, 0x140008840);
        assert_eq!(created.name, 0x1400042c0);
        assert_ne!(created.name, args.a3, "CREATESTRUCT name is the string buffer, not its descriptor");
        assert_eq!((created.x, created.y, created.cx, created.cy), (10, 20, 640, 480));
        assert!((6..=16).all(|index| s.reads.contains(&index)), "production hook must consume every stack-backed tail slot");
    });
}

#[test]
fn zero_child_status_bar_style_is_accepted_by_raw_create_path() {
    let mut args = input();
    args.a4 = 0x4000_0000; // WS_CHILD; zero coordinates are valid for the child path.
    STATE.with(|s| s.borrow_mut().stack[9] = 7);
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.class, Some((21, 7)));
        assert_eq!(s.rect, Some([10, 20, 650, 500]));
        assert_eq!(s.lifecycle_calls, 1);
    });
}

#[test]
fn raw_lifecycle_failure_returns_null_and_rolls_back_created_window() {
    let args = input();
    STATE.with(|s| s.borrow_mut().lifecycle_result = Some(0));
    assert_eq!(raw_class::create_window(args), 0);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.lifecycle_calls, 1);
        assert!(s.creation.is_some());
        assert_eq!(s.destroyed, 1);
    });
}

#[test]
fn negative_control_without_lifecycle_hook_is_not_an_accepted_create() {
    let args = input();
    STATE.with(|s| s.borrow_mut().lifecycle_enabled = false);
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.lifecycle_calls, 1);
        assert!(s.creation.is_none(), "removing the production hook must remove lifecycle acceptance");
    });
}

#[test]
fn null_instance_uses_class_instance_for_create_callback() {
    let args = input();
    STATE.with(|s| s.borrow_mut().stack[11] = 0x140000000);
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| assert_eq!(s.borrow().creation.unwrap().instance, 0x140000000));
}

#[test]
fn unreadable_create_payload_does_not_allocate_a_window() {
    for index in [11, 12, 14, 15] {
        let args = input();
        STATE.with(|s| s.borrow_mut().fault = Some(index));
        assert_eq!(raw_class::create_window(args), 0);
        STATE.with(|s| { let s = s.borrow(); assert!(s.class.is_none()); assert!(s.creation.is_none()); });
    }
}

#[test]
fn descriptor_create_uses_the_same_lifecycle_without_reading_raw_stack() {
    let args = input();
    let mut values = STATE.with(|s| s.borrow().stack);
    values[..6].copy_from_slice(&[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5]);
    values[12] = 0x123456789abcdef0;
    STATE.with(|s| s.borrow_mut().fault = Some(6));
    assert_eq!(raw_class::create_window_descriptor(&values), 42);
    STATE.with(|s| {
        let s = s.borrow();
        assert!(s.reads.is_empty());
        assert_eq!(s.creation.unwrap().lp_create_params, values[12]);
        assert_eq!(s.rect, Some([10, 20, 650, 500]));
    });
}

#[test]
fn scalar_slots_ignore_padding_but_pointers_and_handles_do_not() {
    for index in 0..17 {
        let raw = 0x7fa680000000;
        let expected = match index { 0 | 4 | 13 => 0x80000000,
            5..=8 | 16 => 0xffffffff80000000, _ => raw };
        assert_eq!(create_abi::argument(index, raw), expected, "slot {index}");
    }
}

#[test]
fn production_adapter_preserves_negative_coordinates_and_ignores_upper_padding() {
    let mut args = input();
    args.a5 = 0x7fa6fffffff6;
    args.a4 |= 0x7fa600000000;
    STATE.with(|s| { let mut s = s.borrow_mut(); for i in 6..=8 { s.stack[i] |= 0x7fa600000000; } });
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| assert_eq!(s.borrow().rect, Some([-10, 20, 630, 500])));
}

#[test]
fn atom_and_full_width_parent_reach_the_canonical_owner() {
    let mut args = input(); args.a1 = 21;
    STATE.with(|s| s.borrow_mut().stack[9] = 0xffffffffffffffff);
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| { let s = s.borrow();
        assert_eq!(s.class, Some((21, 0)));
        assert_eq!(s.metadata, Some((42, args.a4 as u32, 0, u64::MAX)));
        assert_eq!(s.creation.unwrap().parent, u64::MAX);
    });
}

#[test]
fn full_width_menu_is_not_silently_truncated() {
    let args = input(); STATE.with(|s| s.borrow_mut().stack[10] = 0x100000001);
    assert_eq!(raw_class::create_window(args), 0);
    STATE.with(|s| assert_eq!(s.borrow().destroyed, 1));
}

#[test]
fn backend_failures_return_null_and_destroy_only_created_windows() {
    for phase in 0..4 {
        let args = input(); STATE.with(|s| { let mut s = s.borrow_mut(); match phase {
            0 => s.fail_class = true, 1 => s.fail_title = true,
            2 => { s.fail_menu = true; s.stack[10] = 1; }, _ => s.fail_rect = true,
        } });
        assert_eq!(raw_class::create_window(args), 0, "phase {phase}");
        STATE.with(|s| assert_eq!(s.borrow().destroyed, usize::from(phase != 0)));
    }
}

#[test]
fn required_stack_faults_return_null_before_window_creation() {
    for index in 6..=10 {
        let args = input(); STATE.with(|s| s.borrow_mut().fault = Some(index));
        assert_eq!(raw_class::create_window(args), 0);
        STATE.with(|s| assert!(s.borrow().class.is_none()));
    }
}

#[test]
fn malformed_title_returns_null_before_window_creation() {
    let mut args = input(); args.a3 = 0x100000001;
    assert_eq!(raw_class::create_window(args), 0);
    STATE.with(|s| assert!(s.borrow().class.is_none()));
}

#[test]
fn canonical_u32_handle_is_not_reinterpreted_as_ntstatus() {
    let args = input(); STATE.with(|s| s.borrow_mut().hwnd = STATUS_INVALID_PARAMETER);
    assert_eq!(raw_class::create_window(args), STATUS_INVALID_PARAMETER);
    STATE.with(|s| assert_eq!(s.borrow().rect, Some([10, 20, 650, 500])));
}

#[path = "create_geometry.rs"] mod create_geometry;
#[path = "create_metadata_hosted.rs"] mod create_metadata_hosted;
