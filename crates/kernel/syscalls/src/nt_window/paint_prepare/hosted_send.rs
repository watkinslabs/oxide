//! Real sent-work/reply owner; instrument only recipient callback installation.
#[path="../send/work.rs"]mod work;
pub(crate) use work::{Queue,Continuation,SendOutcome};
use std::{cell::RefCell,sync::Arc};
thread_local!{static ACTIVE:RefCell<Option<(u64,u64,Arc<work::Reply>)>>=const{RefCell::new(None)};}
pub fn send_resumable_current(hwnd:u64,message:u32,wparam:u64,lparam:u64,c:Continuation)->SendOutcome{
    assert!(super::GUI.0.try_lock().is_ok());
    let immediate=super::ENV.with(|e|{let mut e=e.borrow_mut();e.messages.push((hwnd,message,wparam));
        if e.fail_send{Some(SendOutcome::Failed)}else{e.immediate.map(SendOutcome::Complete)}});
    if let Some(outcome)=immediate{return outcome;}
    let sender=super::live::current().unwrap().tid as u64;
    let mut entries=super::GUI.lock();let entry=&mut entries[0];
    let target=entry.state.get(ipc::win32_window::WindowId::from_raw(hwnd as u32).unwrap()).unwrap().owner_tid;
    let(token,reply)=entry.sent.admit_resumable(sender,target,work::Message{hwnd,message,wparam,lparam},Some(c)).unwrap();
    entry.sent.start(target,work::Resume::Retrieval,Some(token)).unwrap();drop(entries);
    ACTIVE.with(|a|*a.borrow_mut()=Some((target,token,reply)));
    super::ENV.with(|e|e.borrow_mut().send=Some(c));SendOutcome::Pending
}
pub fn return_callback(result:Result<u64,()>)->u64{
    let(target,token,reply)=ACTIVE.with(|a|a.borrow_mut().take().unwrap());
    super::GUI.lock()[0].sent.finish(target,token,result.ok());
    super::paint_callbacks::reap_retired_current();
    super::ENV.with(|e|e.borrow_mut().send.take());let c=reply.continuation.unwrap();(c.resume)(c.token,reply.outcome().unwrap())
}
pub fn cancel_sender(tid:u64){super::GUI.lock()[0].sent.cancel_thread(tid);super::paint_callbacks::reap_retired_current();}
pub fn cancel_window(hwnd:u64){super::GUI.lock()[0].sent.cancel_window(hwnd);}
pub fn reply_pending()->bool{ACTIVE.with(|a|a.borrow().as_ref().unwrap().2.outcome().is_none())}
