//! Bounded internal position work belongs to the process GUI owner, not a window registry.
use alloc::sync::Arc;
use super::super::GUI;
use ipc::win32_window::WindowId;
use super::work;
const ASYNCWINDOWPOS:u32=0x4000;
/// Retrieval readiness before saving a continuation; acquires GUI itself. # C: O(processes + requests)
pub(crate) fn has_remote_for_current()->bool {
    let Some(cur)=sched::live::current()else{return false;};
    let entries=GUI.lock();
    entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
        .is_some_and(|e|work::has_remote_for_tid(&e.remote_positions,cur.tid as u64))
}
/// None means same-thread execution; Some is the completed admission BOOL. # C: O(processes + windows)
pub(crate) fn queue_position_for_current(args:&[u64;7])->Option<u64> {
    let cur=sched::live::current()?;
    if !cur.is_nt_personality(){return Some(0);}
    let Some(id)=u32::try_from(args[0]).ok().and_then(WindowId::from_raw)else{return Some(0);};
    let (wait,reply)={
        let mut entries=GUI.lock();let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return Some(0);};
        let Some(record)=e.state.get(id)else{return Some(0);};
        if record.owner_tid==cur.tid as u64{return None;}
        let reply=(args[6] as u32&ASYNCWINDOWPOS==0).then(||Arc::new(work::Reply::new()));
        if !work::admit(&mut e.remote_positions,record.owner_tid,*args,reply.clone()){return Some(0);}
        (Arc::clone(&e.wait),reply)
    };
    wait.wake_all();Some(reply.map_or(1,wait_reply))
}
/// Run before Get/PeekMessage filtering. Caller preserves retrieval continuation before entry.
/// Some(PENDING) installed a callback; other Some values mean consume internal work and retry retrieval.
/// # C: O(processes + queued requests + windows); # Sleeps: yes
pub(crate) fn pump_position_current()->Option<u64> {
    pump(None)
}
/// Preserve the shared reply while a position callback interrupts a GUI wait. # C: O(requests + windows)
pub(crate) fn pump_for_reply(reply:Arc<work::Reply>)->Option<u64>{pump(Some(reply))}
fn pump(resume_send:Option<Arc<work::Reply>>)->Option<u64> {
    let cur=sched::live::current()?;
    let work={
        let mut entries=GUI.lock();let e=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        work::take(&mut e.remote_positions,cur.tid as u64)?
    };
    let reply=work.reply.clone();
    let result=match crate::nt_wine_window::position::plan_current(&work.args){
        Err(())=>0,Ok(None)=>1,Ok(Some(request))=>super::live::start(request,true,reply.clone(),resume_send)
    };
    if result!=super::super::STATUS_PENDING{finish_reply(reply.as_ref(),result);}
    Some(result)
}
pub(super) fn finish_reply(reply:Option<&Arc<work::Reply>>,result:u64){
    let Some(reply)=reply else{return;};reply.complete(result);
    let Some(cur)=sched::live::current()else{return;};
    let wait={let entries=GUI.lock();entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))).map(|e|Arc::clone(&e.wait))};
    if let Some(wait)=wait{wait.wake_all();}
}
/// Wait without timeout; service incoming internal sends so reply cycles can make progress.
/// # C: O(queued requests + callbacks); # Sleeps: yes; no GUI lock across wait
pub(super) fn wait_reply(reply:Arc<work::Reply>)->u64 {
    super::super::send::wait_reply(reply)
}
/// Invoke after canonical HWND revocation, outside GUI lock. # C: O(processes + pending)
pub(crate) fn cancel_position_thread(group:&Arc<sched::thread_group::ThreadGroup>,tid:u64) {
    let mut entries=GUI.lock();
    if let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(group))){
        for p in &e.pending_positions {if p.tid==tid {if let Some(reply)=&p.reply{reply.complete(0);}}}
        e.pending_positions.retain(|p|p.tid!=tid);work::cancel_thread(&mut e.remote_positions,tid);
        let wait=Arc::clone(&e.wait);drop(entries);wait.wake_all();
    }
}
/// Invoke for each HWND in canonical destruction order, outside GUI lock. # C: O(processes + pending)
pub(crate) fn cancel_position_window(group:&Arc<sched::thread_group::ThreadGroup>,hwnd:u64) {
    let mut entries=GUI.lock();
    if let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(group))){
        for p in &mut e.pending_positions {if p.request.hwnd==hwnd {p.cancelled=true;if let Some(reply)=&p.reply{reply.complete(0);}}}
        work::cancel_window(&mut e.remote_positions,hwnd);
        let wait=Arc::clone(&e.wait);drop(entries);wait.wake_all();
    }
}
