use super::*;
use crate::win32_window::WindowId;
fn setup()->(WindowManager,WindowId,u64){
    let mut state=WindowManager::new();let hwnd=state.create(7,None,0).unwrap();
    state.create_caret(7,hwnd,2,3).unwrap();let shown=state.show_caret(7,Some(hwnd)).unwrap();
    state.arm_current_caret_blink(7,hwnd,shown.generation,0,500).unwrap();(state,hwnd,shown.generation)
}
#[test]fn successive_expiry_toggles_and_replay_cannot_toggle_twice(){
    let (mut state,hwnd,generation)=setup();let expired=state.expire_current_caret_blink(7,500_000_000).unwrap().unwrap();
    let off=state.apply_expired_caret(7,expired).unwrap();assert_eq!(off.generation,generation+1);
    assert!(off.transition.old_visible);assert!(!off.transition.new_visible);assert_eq!(off.transition.hwnd,Some(hwnd));
    assert!(state.apply_expired_caret(7,expired).is_none());
    let next=state.expire_current_caret_blink(7,1_000_000_000).unwrap().unwrap();assert_eq!(next.generation,off.generation);
    let on=state.apply_expired_caret(7,next).unwrap();assert!(!on.transition.old_visible);assert!(on.transition.new_visible);
}
#[test]fn owner_hide_move_replace_destroy_and_clear_invalidate_expired_commit(){
    for action in 0..7 {
        let (mut state,hwnd,_)=setup();let expired=state.expire_current_caret_blink(7,500_000_000).unwrap().unwrap();
        match action {
            0=>{assert!(state.apply_expired_caret(8,expired).is_none());continue;}
            1=>{state.hide_caret(7,Some(hwnd)).unwrap();}
            2=>{state.set_caret_pos(7,1,2).unwrap();}
            3=>{state.create_caret(7,hwnd,2,3).unwrap();}
            4=>{state.destroy_caret(7).unwrap();}
            5=>{state.clear_current_caret_blink(7,Some(hwnd)).unwrap();}
            _=>{state.destroy(hwnd).unwrap();}
        }
        assert!(state.apply_expired_caret(7,expired).is_none());
    }
}
#[test]fn generation_exhaustion_does_not_mutate_phase(){
    let (mut state,hwnd,_)=setup();let queue=&mut state.queues.iter_mut().find(|(tid,_)|*tid==7).unwrap().1;
    queue.caret_generation=u64::MAX;queue.caret_blink.generation=u64::MAX;
    let before=queue.caret;let expired=ExpiredCaretCommit{owner_tid:7,hwnd,generation:u64::MAX};
    assert!(state.apply_expired_caret(7,expired).is_none());
    assert_eq!(state.queues.iter().find(|(tid,_)|*tid==7).unwrap().1.caret,before);
}
