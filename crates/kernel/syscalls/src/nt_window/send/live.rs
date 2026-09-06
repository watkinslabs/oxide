//! Recipient callbacks and sender continuations; no GUI lock across usercopy or waiting.
use alloc::sync::Arc;
use super::{work::{Message,Work},Queue,Reply,Resume,Outcome,Continuation,SendOutcome};
use super::super::{GUI,STATUS_PENDING};
use ipc::win32_window::WindowId;
const CALLBACK_SEND:u64=0x40;
pub(crate) struct Context {pub tid:u64,pub wndproc:u64}
/// Same-process canonical lookup, shared with raw client-param publication. # C: O(processes + windows)
pub(crate) fn context_current(hwnd:u64)->Option<Context>{
    let cur=sched::live::current()?;if !cur.is_nt_personality(){return None;}
    let id=WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let entries=GUI.lock();let e=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let r=e.state.get(id)?;Some(Context{tid:r.owner_tid,wndproc:r.wndproc})
}
/// Zero on failed admission/execution; internal pending only after callback installation. # C: O(sends + windows); # Sleeps: yes
pub(crate) fn send_for_current(hwnd:u64,message:u32,wparam:u64,lparam:u64)->u64{
    raw_send(send(hwnd,message,wparam,lparam,None))
}
/// Immediate outcomes return directly; suspended completion invokes the caller continuation on its thread.
/// # C: O(sends + windows); # Sleeps: yes
pub(crate) fn send_resumable_current(hwnd:u64,message:u32,wparam:u64,lparam:u64,continuation:Continuation)->SendOutcome{
    send(hwnd,message,wparam,lparam,Some(continuation))
}
fn send(hwnd:u64,message:u32,wparam:u64,lparam:u64,continuation:Option<Continuation>)->SendOutcome{
    let Some(cur)=sched::live::current()else{return SendOutcome::Failed;};if !cur.is_nt_personality(){return SendOutcome::Failed;}
    let Some(id)=u32::try_from(hwnd).ok().and_then(WindowId::from_raw)else{return SendOutcome::Failed;};
    let (token,reply,same,wait)={
        let mut entries=GUI.lock();let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return SendOutcome::Failed;};
        let Some(r)=e.state.get(id)else{return SendOutcome::Failed;};let target=r.owner_tid;
        let Some((token,reply))=e.sent.admit_resumable(cur.tid as u64,target,Message{hwnd,message,wparam,lparam},continuation)else{return SendOutcome::Failed;};
        (token,reply,target==cur.tid as u64,Arc::clone(&e.wait))
    };
    wait.wake_all();
    if same{match pump(Resume::Direct,Some(token)){Some(Outcome::Pending)=>SendOutcome::Pending,_=>SendOutcome::Failed}}else{wait_outcome(reply)}
}
fn raw_send(outcome:SendOutcome)->u64{match outcome{SendOutcome::Pending=>STATUS_PENDING,SendOutcome::Complete(value)=>value,SendOutcome::Failed=>0}}
/// Acquires GUI; do not call from GUI-locked predicates. # C: O(processes + sends)
pub(crate) fn has_current()->bool{
    let Some(cur)=sched::live::current()else{return false;};let entries=GUI.lock();
    entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))).is_some_and(|e|e.sent.has_for_tid(cur.tid as u64))
}
/// Caller saves retrieval context before pumping. # C: O(processes + sends)
pub(crate) fn pump_current()->Option<Outcome>{pump_with_resume(Resume::Retrieval)}
fn pump_with_resume(resume:Resume)->Option<Outcome>{pump(resume,None)}
fn pump(resume:Resume,token:Option<u64>)->Option<Outcome>{
    let cur=sched::live::current()?;
    let (work,wndproc)={
        let mut entries=GUI.lock();let e=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        let work=e.sent.start(cur.tid as u64,resume,token)?;
        let wndproc=u32::try_from(work.message.hwnd).ok().and_then(WindowId::from_raw)
            .and_then(|id|e.state.get(id)).filter(|r|r.owner_tid==cur.tid as u64).map(|r|r.wndproc);
        (work,wndproc)
    };
    let result=if work.reply.result().is_some(){0}else{wndproc.filter(|p|*p!=0).map_or(0,|wndproc|install(&work,wndproc))};
    if result==STATUS_PENDING{return Some(Outcome::Pending);}
    let _=finish(work.token,None);Some(Outcome::Complete(0))
}
fn install(work:&Work,wndproc:u64)->u64{
    let m=work.message;
    crate::nt_rtl::begin_wndproc_callback_with_completion(m.hwnd,m.message as u64,m.wparam,m.lparam,wndproc,
        sched::nt_callback::Completion{kind:CALLBACK_SEND,argument:work.token})
}
fn finish(token:u64,result:Option<u64>)->Option<(Resume,Arc<Reply>)>{
    let cur=sched::live::current()?;
    let (resume,wait)={let mut entries=GUI.lock();let e=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        (e.sent.finish(cur.tid as u64,token,result)?,Arc::clone(&e.wait))};
    wait.wake_all();super::super::paint_callbacks::reap_retired_current();Some(resume)
}
/// # C: O(1)
pub(crate) fn handles_callback(kind:u64)->bool{kind==CALLBACK_SEND}
/// Full LRESULT publication precedes restoration of the interrupted owner operation. # C: O(sends); # Sleeps: yes
pub(crate) fn complete_callback(completion:sched::nt_callback::Completion,result:u64)->u64{
    if !handles_callback(completion.kind){return 0;}
    finish(completion.argument,Some(result)).map_or(0,|(resume,reply)|resume_current(resume,reply))
}
/// Resume a saved owner operation after a sent or position callback. # C: O(sends); # Sleeps: yes
fn resume_current(resume:Resume,reply:Arc<Reply>)->u64{match resume{
    Resume::Direct=>resume_reply(&reply,reply.outcome().unwrap_or(Err(()))),Resume::Retrieval=>super::super::resume_position_message_current(),
    Resume::Wait(reply)=>wait_reply(reply),
}}
/// Service sent work while waiting, with a saved reply for each nested callback. # C: O(sends); # Sleeps: yes
pub(crate) fn wait_reply(reply:Arc<Reply>)->u64{
    match wait_outcome(reply.clone()){SendOutcome::Pending=>STATUS_PENDING,SendOutcome::Complete(n)=>resume_reply(&reply,Ok(n)),SendOutcome::Failed=>resume_reply(&reply,Err(()))}
}
fn resume_reply(reply:&Reply,result:Result<u64,()>)->u64{reply.continuation.map_or_else(||result.unwrap_or(0),|c|(c.resume)(c.token,result))}
fn wait_outcome(reply:Arc<Reply>)->SendOutcome{
    let Some(cur)=sched::live::current()else{return SendOutcome::Failed;};
    let wait={let entries=GUI.lock();let Some(e)=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return SendOutcome::Failed;};Arc::clone(&e.wait)};
    loop{
        if let Some(value)=reply.outcome(){return value.map_or(SendOutcome::Failed,SendOutcome::Complete);}
        if let Some(outcome)=pump_with_resume(Resume::Wait(reply.clone())){if outcome==Outcome::Pending{return SendOutcome::Pending;}continue;}
        if let Some(result)=super::super::position::pump_for_reply(reply.clone()){if result==STATUS_PENDING{return SendOutcome::Pending;}continue;}
        // SAFETY: wait_reply retains owned reply/wait references and rechecks
        // completion plus canonical sent readiness without holding the GUI lock.
        unsafe{sched::live::wait_event_uninterruptible(&wait,||reply.result().is_some()||has_current()||super::super::position::has_remote_for_current());}
    }
}
fn cancel(group:&Arc<sched::thread_group::ThreadGroup>,f:impl FnOnce(&mut Queue)){
    let wait={let mut entries=GUI.lock();let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(group)))else{return;};
        f(&mut e.sent);Arc::clone(&e.wait)};wait.wake_all();super::super::paint_callbacks::reap_retired_current();
}
/// After canonical thread revocation, outside GUI. # C: O(processes + sends)
pub(crate) fn cancel_thread(group:&Arc<sched::thread_group::ThreadGroup>,tid:u64){cancel(group,|q|q.cancel_thread(tid));}
/// Active callbacks retain continuation tombstones until return. # C: O(processes + sends)
pub(crate) fn cancel_window(group:&Arc<sched::thread_group::ThreadGroup>,hwnd:u64){cancel(group,|q|q.cancel_window(hwnd));}
