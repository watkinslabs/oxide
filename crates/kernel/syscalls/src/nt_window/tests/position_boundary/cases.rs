use super::*;
use crate::environment::{self as env,ENV,SERIAL};
use position::{Continuation,Outcome,position_apply_resumable_for_current as apply,complete_position_callback as complete};
use crate::nt_wine_window::position::Request;
use ipc::win32_window::{WindowId,WindowRect};
const FRAME_FLAGS:u32=0x0437;
#[path="resize.rs"]mod resize;
fn setup(wndproc:u64)->Request {
    let group=Arc::new(crate::thread_group::ThreadGroup);
    ENV.with(|e|*e.borrow_mut()=env::Env{task:Some(env::Task{tid:1,thread_group:group.clone()}),..Default::default()});
    let mut state=WindowManager::new();let id=state.create(1,None,wndproc).unwrap();
    env::nt_gdi::reset(&group);
    *GUI.lock()=vec![Entry{group:Arc::downgrade(&group),state,pending_positions:Vec::new(),remote_positions:Vec::new(),next_create:1,foreground:false,wait:Arc::new(Wait)}];
    Request{hwnd:id.raw() as u64,rect:WindowRect{left:0,top:0,right:100,bottom:50},order:None,visible:None,flags:FRAME_FLAGS}
}
fn caller(token:u64)->Option<Continuation>{Some(Continuation{token,resume:env::resume})}
fn cb(index:usize)->crate::nt_callback::Completion{ENV.with(|e|e.borrow().callbacks[index].completion)}
fn count()->usize{ENV.with(|e|e.borrow().resumes.len())}
#[test]fn immediate_and_admission_failures_never_invoke_caller(){
    let _serial=SERIAL.lock().unwrap();let request=setup(0);
    assert_eq!(apply(request,caller(90)),Outcome::Complete(true));assert_eq!(count(),0);
    let mut invalid=request;invalid.hwnd=u64::MAX;assert_eq!(apply(invalid,caller(91)),Outcome::Failed);
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=2);assert_eq!(apply(request,caller(92)),Outcome::Failed);assert_eq!(count(),0);
    let request=setup(5);ENV.with(|e|e.borrow_mut().fail_install=true);
    assert_eq!(apply(request,caller(93)),Outcome::Failed);assert!(GUI.lock()[0].pending_positions.is_empty());assert_eq!(count(),0);
}
#[test]fn real_nccalc_commit_changed_chain_resumes_after_publication_once(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);assert_eq!(apply(request,caller(99)),Outcome::Pending);
    ENV.with(|e|assert_eq!(e.borrow().callbacks[0].message,0x83));assert_eq!(count(),0);
    assert_eq!(complete(cb(0),u64::MAX),STATUS_PENDING);assert_eq!(count(),0);
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();assert_eq!(GUI.lock()[0].state.rect(id),Some(request.rect));
    ENV.with(|e|assert_eq!(e.borrow().callbacks[1].message,0x47));
    assert_eq!(complete(cb(1),STATUS_PENDING),99);assert_eq!(complete(cb(1),0),0);
    ENV.with(|e|assert_eq!(e.borrow().resumes,vec![(99,Outcome::Complete(true),1,1)]));
}
#[test]fn cancellation_waits_for_original_thread_and_exit_drops_continuation(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);assert_eq!(apply(request,caller(70)),Outcome::Pending);
    let group=crate::live::current().unwrap().thread_group;
    position::cancel_position_window(&group,request.hwnd);assert_eq!(count(),0);
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=2);assert_eq!(complete(cb(0),0),0);assert_eq!(count(),0);
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=1);assert_eq!(complete(cb(0),0),70);
    ENV.with(|e|assert_eq!(e.borrow().resumes[0].1,Outcome::Failed));
    assert_eq!(apply(request,caller(71)),Outcome::Pending);position::cancel_position_thread(&group,1);
    assert_eq!(complete(cb(1),0),0);assert_eq!(count(),1);assert!(GUI.lock()[0].pending_positions.is_empty());
}
#[test]fn chained_install_copy_and_publication_failure_resume_failed(){
    let _serial=SERIAL.lock().unwrap();
    for failure in 0..3 {
        let request=setup(5);assert_eq!(apply(request,caller(80)),Outcome::Pending);
        ENV.with(|e|{let mut e=e.borrow_mut();e.fail_install=failure==0;e.fail_copy=failure==1;e.fail_publish=failure==2;});
        assert_eq!(complete(cb(0),0),80);assert_eq!(complete(cb(0),0),0);
        ENV.with(|e|assert_eq!(e.borrow().resumes[0].1,Outcome::Failed));assert_eq!(count(),1);
    }
}
#[test]fn nested_position_callbacks_keep_distinct_original_caller_tokens(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);
    assert_eq!(apply(request,caller(10)),Outcome::Pending);let outer=cb(0);
    assert_eq!(apply(request,caller(20)),Outcome::Pending);assert_eq!(complete(cb(1),0),STATUS_PENDING);
    assert_eq!(complete(cb(2),0),20);assert_eq!(complete(outer,0),STATUS_PENDING);assert_eq!(complete(cb(3),0),10);
    ENV.with(|e|assert_eq!(e.borrow().resumes.iter().map(|r|r.0).collect::<Vec<_>>(),vec![20,10]));
}
#[test]fn scroll_frame_flags_run_changing_nccalc_changed_before_full_width_caller_return(){
    let _serial=SERIAL.lock().unwrap();
    for result in [0,STATUS_PENDING,u64::MAX] {
        let mut request=setup(5);request.flags=0x0037;
        let id=WindowId::from_raw(request.hwnd as u32).unwrap();
        GUI.lock()[0].state.apply_position(1,ipc::win32_window::WindowPosition{window:id,rect:request.rect,client:None,order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
        assert_eq!(apply(request,caller(result)),Outcome::Pending);
        ENV.with(|e|assert_eq!(e.borrow().callbacks[0].message,0x46));
        assert_eq!(complete(cb(0),u64::MAX),STATUS_PENDING);assert_eq!(count(),0);
        ENV.with(|e|{let mut e=e.borrow_mut();let payload=&mut e.callbacks[1];assert_eq!(payload.message,0x83);
            for (i,n) in [2i32,3,90,40].into_iter().enumerate(){payload.bytes[i*4..i*4+4].copy_from_slice(&n.to_le_bytes());}
        });
        assert_eq!(complete(cb(1),0),STATUS_PENDING);assert_eq!(count(),0);
        assert_eq!(GUI.lock()[0].state.get(id).unwrap().client_rect,Some(WindowRect{left:2,top:3,right:90,bottom:40}));
        ENV.with(|e|assert_eq!(e.borrow().callbacks[2].message,0x47));
        assert_eq!(complete(cb(2),u64::MAX),result);assert_eq!(count(),1);
        ENV.with(|e|assert_eq!(e.borrow().resumes[0],(result,Outcome::Complete(true),1,1)));
    }
}
