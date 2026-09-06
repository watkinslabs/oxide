use super::*;
use geometry::{Coordinates, Defaults, Error, Rect};

fn work() -> Rect { Rect { left: 50, top: 40, right: 1250, bottom: 840 } }
fn defaults() -> Defaults { Defaults { work_area: Some(work()), ..Defaults::default() } }
fn notepad_size(base: i32) -> (i32, i32) {
    let width = (f64::from(base) * 0.95) as i32;
    (width, width.wrapping_mul(3) / 4)
}

fn desktop_metric(index: u64, dimensions: Option<(u32, u32)>) -> u64 {
    metrics::query(index, || dimensions.filter(|&(w, h)| w != 0 && h != 0).map(|(width, height)| {
        let rect = syscall::nt_compositor::Rect { x: 0, y: 0, width, height };
        vec![syscall::nt_compositor::Monitor { monitor: rect, workarea: rect }]
    }))
}

#[test]
fn notepad_captured_dimensions_exactly_reproduce_ntstatus_as_metric() {
    let (width, height) = notepad_size(0xc0000002u32 as i32);
    assert_eq!((width as u32, height as u32), (0xc3333336, 0x12666668));
    assert_eq!(i32::MIN.checked_add(width), None);
}

#[test]
fn primary_metrics_fix_notepad_dimensions_before_default_placement() {
    assert_eq!(nt_window_policy::CALL_ONE_PARAM_GET_SYSTEM_METRICS, 9);
    let mut args = input();
    let metric = |index| desktop_metric(index, Some((800, 600))) as i32;
    assert_eq!((metric(0), metric(1)), (800, 600));
    let (width, height) = notepad_size(metric(0).min(metric(1)));
    assert_eq!((width, height), (570, 427));
    args.a5 = 0x7fa680000000;
    STATE.with(|s| { let mut s = s.borrow_mut();
        s.stack[6] = 0x7fa680000000; s.stack[7] = width as u64; s.stack[8] = height as u64;
        s.placement = defaults(); });
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| assert_eq!(s.borrow().rect, Some([50, 40, 620, 467])));
}

#[test]
fn metrics_do_not_fabricate_display_size_or_return_status_as_int() {
    assert_eq!(desktop_metric(0, None), 0);
    assert_eq!(desktop_metric(1, Some((800, 0))), 0);
    assert_eq!(desktop_metric(u64::MAX, Some((800, 600))), 0);
    assert_eq!(desktop_metric(0x7fa600000001, Some((1280, 720))), 720);
    assert_eq!(desktop_metric(78, Some((1280, 720))), 1280);
}

#[test]
fn captured_raw_slots_reach_clamped_rectangle_after_default_resolution() {
    let mut args = input(); args.a4 = 0x7fa600cf0000; args.a5 = 0x7fa680000000;
    STATE.with(|s| { let mut s = s.borrow_mut(); s.stack[6] = 0x7fa680000000;
        s.stack[7] = 0x7fa6c3333336; s.stack[8] = 0x7ffe12666668; s.placement = defaults(); });
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| {
        assert_eq!(s.borrow().rect, Some([50, 40, 50, 308700816]));
        assert_eq!(s.borrow().destroyed, 0);
    });
}

#[test]
fn missing_work_area_fails_before_class_mutation_not_at_overflow() {
    let mut args = input(); args.a5 = i32::MIN as u64;
    assert_eq!(raw_class::create_window(args), 0);
    STATE.with(|s| assert!(s.borrow().class.is_none()));
}

#[test]
fn child_and_popup_defaults_need_no_monitor_and_accept_both_sentinels() {
    for style in [0x40000000, 0x80000000] {
        for sentinel in [i32::MIN, 0x8000] {
            let c = Coordinates { x: sentinel, y: 99, width: sentinel, height: 88 };
            assert_eq!(geometry::fix(style, c, || panic!("child queried monitor")),
                Ok((Coordinates { x: 0, y: 0, width: 0, height: 0 }, 5)));
        }
    }
}

#[test]
fn overlapped_defaults_use_work_area_and_y_as_show_command() {
    let c = Coordinates { x: i32::MIN, y: 3, width: i32::MIN, height: -12 };
    assert_eq!(geometry::fix(0, c, defaults),
        Ok((Coordinates { x: 50, y: 40, width: 850, height: 560 }, 3)));
}

#[test]
fn startup_position_and_size_override_only_default_fields() {
    let d = Defaults { position: Some((-10, 20)), size: Some((300, 400)), work_area: None };
    let c = Coordinates { x: i32::MIN, y: i32::MIN, width: i32::MIN, height: 99 };
    assert_eq!(geometry::fix(0, c, || d),
        Ok((Coordinates { x: -10, y: 20, width: 300, height: 400 }, 5)));
    let explicit = Coordinates { x: 10, y: 20, width: 30, height: 40 };
    assert_eq!(geometry::fix(0, explicit, || panic!("explicit queried defaults")), Ok((explicit, 5)));
}

#[test]
fn height_only_default_uses_work_area_not_startup_size() {
    let c = Coordinates { x: 10, y: 20, width: 300, height: i32::MIN };
    let d = Defaults { size: Some((1, 2)), ..defaults() };
    assert_eq!(geometry::fix(0, c, || d), Ok((Coordinates { height: 580, ..c }, 5)));
    let y_only = Coordinates { y: i32::MIN, height: 10, ..c };
    assert_eq!(geometry::fix(0, y_only, || panic!("y alone is not a default trigger")), Ok((y_only, 5)));
}

#[test]
fn final_rectangle_clamps_negative_sizes_and_saturates_positive_endpoints() {
    let c = Coordinates { x: i32::MAX - 10, y: -20, width: 20, height: -100 };
    assert_eq!(geometry::rect(c), Rect { left: i32::MAX - 10, top: -20, right: i32::MAX, bottom: -20 });
    let c = Coordinates { x: i32::MIN, y: 0, width: 1, height: 1 };
    assert_eq!(geometry::fix(0, c, Defaults::default), Err(Error::MissingWorkArea));
}

#[test]
fn startup_fields_follow_the_canonical_peb_pointer_and_window_flag_offsets() {
    let d = create_context_contract::read_startup(0x1000, |p| {
        assert_eq!(p, 0x1020); Some(0x9000)
    }, |p| match p {
        0x90a4 => Some(6), 0x9088 => Some((-10i32) as u32), 0x908c => Some(20),
        0x9090 => Some(300), 0x9094 => Some(400), _ => panic!("unexpected field {p:x}"),
    }).unwrap();
    assert_eq!(d.position, Some((-10, 20)));
    assert_eq!(d.size, Some((300, 400)));
    assert_eq!(d.work_area, None);
}

#[test]
fn disabled_startup_fields_are_not_read_and_bad_pointers_do_not_fabricate_values() {
    let d = create_context_contract::read_startup(0x1000, |_| Some(0x9000), |p| {
        assert_eq!(p, 0x90a4); Some(0)
    }).unwrap();
    assert_eq!(d.position, None); assert_eq!(d.size, None);
    assert!(create_context_contract::read_startup(u64::MAX, |_| panic!("wrapped"), |_| None).is_none());
    assert!(create_context_contract::read_startup(0x1000, |_| Some(0), |_| panic!("null")).is_none());
    assert!(create_context_contract::read_startup(0x1000, |_| Some(0x9000), |_| None).is_none());
}
