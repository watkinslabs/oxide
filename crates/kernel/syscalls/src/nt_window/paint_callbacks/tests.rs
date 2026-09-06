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
