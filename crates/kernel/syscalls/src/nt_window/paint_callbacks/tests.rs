use super::*;
fn completion() -> Completion { Completion::Callback { token: 9, finish: |_,r| u64::from(r.unwrap()) } }
fn resources() -> Resources { Resources { hwnd: 1, dc: 2, nc_region: 3, erase: true, delayed: false, empty_clip: false } }
#[test]
fn nonclient_then_erase_uses_exact_resources_and_zero_retains_erase() {
    for result in [0, 1, u64::MAX, 0x103] {
        let mut q = Queue::new(); let token = q.admit(7, resources(), completion()).unwrap();
        assert!(q.step(8,token,0).is_none());
        assert!(matches!(q.step(7,token,0),Some(Step::Send{message:WM_NCPAINT,wparam:3,..})));
        assert!(matches!(q.step(7,token,0),Some(Step::Send{message:WM_ERASEBKGND,wparam:2,..})));
        assert!(matches!(q.step(7,token,result),Some(Step::Finish(_,needed)) if needed==(result==0)));
        assert!(q.step(7,token,0).is_none());
    }
}
#[test]
fn empty_clip_suppresses_erase_and_retains_delayed_requirement() {
    let mut q = Queue::new(); let mut r = resources(); r.nc_region=0; r.empty_clip=true; r.delayed=true;
    let token=q.admit(7,r,completion()).unwrap();
    assert!(matches!(q.step(7,token,0),Some(Step::Finish(_,true))));
}
#[test]
fn callback_failure_nested_ownership_and_bounded_admission() {
    let mut q=Queue::new(); let outer=q.admit(7,resources(),completion()).unwrap();
    let inner=q.admit(7,resources(),completion()).unwrap();
    assert!(q.fail(8,inner).is_none()); assert!(q.fail(7,inner).is_some());
    assert!(matches!(q.step(7,outer,0),Some(Step::Send{message:WM_NCPAINT,..})));
    for _ in 1..MAX_PREPARATIONS { q.admit(7,resources(),completion()).unwrap(); }
    assert!(q.admit(7,resources(),completion()).is_none()); while q.take_thread(7).is_some(){} assert!(q.pending.is_empty());
}

#[test]
fn drawing_lease_survives_window_cancellation_until_its_own_return() {
    let mut q = Queue::new();
    let token = q.hold(7, resources(), completion()).unwrap();
    q.cancel_window(1);
    assert!(q.take_window(1).is_none());
    assert!(q.step(7, token, 0).is_none());
    assert!(q.release_held(8, token).is_none());
    assert!(q.release_held(7, token + 1).is_none());
    assert!(matches!(q.release_held(7, token), Some((_, true))));
    assert!(q.release_held(7, token).is_none());
}

#[test]
fn ordinary_preparation_cannot_be_consumed_as_a_drawing_return() {
    let mut q = Queue::new();
    let preparing = q.admit(7, resources(), completion()).unwrap();
    let drawing = q.hold(7, resources(), completion()).unwrap();
    assert!(q.release_held(7, preparing).is_none());
    assert!(matches!(q.release_held(7, drawing), Some((_, false))));
    assert!(matches!(q.step(7, preparing, 0), Some(Step::Send { message: WM_NCPAINT, .. })));
}

#[test]
fn control_paint_dc_remains_leased_until_callback_release() {
    let prepared = crate::nt_window::paint_prepare::Prepared {
        hwnd: 1, dc: 2, destination: 0, nc_region: 0, tid: 7, kernel: true,
    };
    let mut q = Queue::new();
    let token = q.hold(7, resources(), Completion::ControlPaint(prepared)).unwrap();
    assert!(q.holds_dc(2)); assert!(!q.holds_dc(3));
    q.cancel_window(1);
    assert!(q.holds_dc(2)); assert!(q.take_window(1).is_none());
    assert!(matches!(q.release_held(7, token), Some((Completion::ControlPaint(_), true))));
    assert!(!q.holds_dc(2));
}
