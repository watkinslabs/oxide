use super::*;
fn message(hwnd:u64)->Message{Message{hwnd,message:0x30,wparam:u64::MAX,lparam:0x1234}}
#[test]
fn every_lresult_bit_pattern_is_a_completed_value(){
    for value in [0,1,2,0x103,u64::MAX,1<<63]{let r=Reply::new();assert_eq!(r.result(),None);r.complete(value);assert_eq!(r.result(),Some(value));r.cancel();r.complete(!value);assert_eq!(r.result(),Some(value));}
}
#[test]
fn cancelled_reply_cannot_be_revived(){let r=Reply::new();r.cancel();r.complete(123);assert_eq!(r.result(),Some(0));}
#[test]
fn recipient_only_fifo_and_full_width_message(){
    let mut q=Queue::new();let (a,_)=q.admit(1,2,message(7)).unwrap();let (b,_)=q.admit(1,3,message(8)).unwrap();
    let (c,_)=q.admit(1,2,message(9)).unwrap();assert!(q.start(1,Resume::Direct,None).is_none());
    let w=q.start(2,Resume::Retrieval,None).unwrap();assert_eq!(w.token,a);assert_eq!(w.message.wparam,u64::MAX);
    assert_eq!(w.message.message,0x30);assert_eq!(w.message.lparam,0x1234);
    assert_eq!(q.start(2,Resume::Retrieval,None).unwrap().token,c);assert_eq!(q.start(3,Resume::Retrieval,None).unwrap().token,b);
    assert!(!q.has_for_tid(2));
}
#[test]
fn pending_control_flow_is_distinct_from_lresult_103(){assert_ne!(Outcome::Pending,Outcome::Complete(0x103));}
#[test]
fn typed_completion_distinguishes_failure_from_all_success_values(){
    for value in [0,0x103,u64::MAX]{let r=Reply::new();r.complete(value);assert_eq!(r.outcome(),Some(Ok(value)));assert_ne!(SendOutcome::Complete(value),SendOutcome::Failed);}
    let r=Reply::new();assert_eq!(r.outcome(),None);r.cancel();assert_eq!(r.outcome(),Some(Err(())));assert_ne!(SendOutcome::Pending,SendOutcome::Complete(0x103));
}
#[test]
fn queued_plus_active_share_bound_and_completion_reclaims_capacity(){
    let mut q=Queue::new();for _ in 0..LIMIT{q.admit(1,2,message(7)).unwrap();}
    let w=q.start(2,Resume::Retrieval,None).unwrap();assert!(q.admit(1,2,message(7)).is_none());
    assert!(q.finish(1,w.token,Some(42)).is_none());assert_eq!(w.reply.result(),None);
    assert!(q.finish(2,w.token,Some(42)).is_some());assert_eq!(w.reply.result(),Some(42));assert!(q.admit(1,2,message(7)).is_some());
}
#[test]
fn destroy_cancels_queued_and_retains_active_continuation(){
    let mut q=Queue::new();let (_,a)=q.admit(1,2,message(7)).unwrap();let (_,b)=q.admit(1,2,message(7)).unwrap();
    let active=q.start(2,Resume::Retrieval,None).unwrap();q.cancel_window(7);
    assert_eq!(a.result(),None);assert_eq!(b.result(),Some(0));assert!(!q.has_for_tid(2));assert_eq!(q.work.len(),1);
    assert!(matches!(q.finish(2,active.token,Some(99)),Some((Resume::Retrieval,_))));assert_eq!(a.result(),Some(0));assert!(q.work.is_empty());
}
#[test]
fn recipient_exit_removes_active_and_wakes_replies(){
    let mut q=Queue::new();let (_,reply)=q.admit(1,2,message(7)).unwrap();q.start(2,Resume::Retrieval,None);q.cancel_thread(2);
    assert_eq!(reply.result(),Some(0));assert!(q.work.is_empty());
}
#[test]
fn sender_exit_cancels_only_its_work_and_keeps_surviving_callback(){
    let mut q=Queue::new();let (_,a)=q.admit(1,2,message(7)).unwrap();let (_,b)=q.admit(3,2,message(7)).unwrap();
    let active=q.start(2,Resume::Retrieval,None).unwrap();q.cancel_thread(1);assert_eq!(a.result(),None);assert_eq!(b.result(),None);assert_eq!(q.work.len(),2);
    assert!(q.has_foreign_active(1,7));q.finish(2,active.token,Some(99));assert_eq!(a.outcome(),Some(Err(())));assert!(!q.has_foreign_active(1,7));
}
#[test]
fn nested_wait_continuation_survives_reply_completion(){
    let mut q=Queue::new();let outer=Arc::new(Reply::new());let (token,_)=q.admit(2,1,message(7)).unwrap();
    q.start(1,Resume::Wait(outer.clone()),None);
    match q.finish(1,token,Some(u64::MAX)).unwrap().0{Resume::Wait(r)=>assert!(Arc::ptr_eq(&r,&outer)),_=>unreachable!()}
}
