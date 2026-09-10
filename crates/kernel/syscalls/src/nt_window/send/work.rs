//! One bounded inbox including active callbacks; HWND semantics remain in WindowManager.
use alloc::{sync::Arc,vec::Vec};
#[path="reply.rs"] mod reply;
pub(crate) use reply::{Reply,Continuation,SendOutcome};
const LIMIT:usize=64;
#[derive(Clone)]
pub(crate) enum Resume {Direct,Retrieval,Wait(Arc<Reply>)}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Outcome {Complete(u64),Pending}
#[derive(Clone,Copy)]
pub(super) struct Message {pub hwnd:u64,pub message:u32,pub wparam:u64,pub lparam:u64}
pub(super) struct Event {pub hook:ipc::win32_hook::Hook,pub thread:u32,pub time:u32,pub cancel_on_destroy:bool}
#[derive(Clone)]
pub(super) struct Work {pub token:u64,pub sender:u64,pub target:u64,pub message:Message,pub event:Option<Arc<Event>>,pub reply:Arc<Reply>,pub resume:Option<Resume>,cancelled:bool}
// Per-recipient status shares the existing sent-owner thread lifetime records.
struct Thread {tid:u64,changed:bool,exiting:bool}
pub(crate) struct Queue {next:u64,work:Vec<Work>,threads:Vec<Thread>}
impl Queue {
    /// # C: O(1)
    pub(crate) fn new()->Self{Self{next:1,work:Vec::new(),threads:Vec::new()}}
    /// GUI-locked readiness; takes no additional lock. # C: O(sends)
    pub(crate) fn has_for_tid(&self,tid:u64)->bool{self.work.iter().any(|w|w.target==tid&&w.resume.is_none())}
    /// Report queued sent work and clear only the requested changed class. # C: O(N_work + N_changed)
    pub(crate) fn queue_status(&mut self,tid:u64,flags:u32)->u32{
        use ipc::win32_window::queue_status::{QS_SENDMESSAGE,queue_status_result};
        let wake=if self.has_for_tid(tid){QS_SENDMESSAGE}else{0};
        let changed=if self.threads.iter().any(|thread|thread.tid==tid&&thread.changed){QS_SENDMESSAGE}else{0};
        if flags&QS_SENDMESSAGE!=0{self.threads.retain_mut(|thread|{if thread.tid==tid{thread.changed=false;}thread.changed||thread.exiting});}
        queue_status_result(changed,wake,flags)
    }
    fn clear_drained(&mut self){
        self.threads.retain_mut(|thread|{
            if !self.work.iter().any(|work|work.target==thread.tid&&work.resume.is_none()){thread.changed=false;}
            thread.changed||thread.exiting
        });
    }
    /// A retiring sender cannot free resources used by a surviving recipient callback.
    /// # C: O(sends); caller holds canonical GUI ownership
    pub(crate) fn has_foreign_active(&self,sender:u64,hwnd:u64)->bool{
        self.work.iter().any(|w|w.event.is_none()&&w.sender==sender&&w.target!=sender&&w.message.hwnd==hwnd&&w.resume.is_some())
    }
    #[cfg(test)]
    pub(super) fn admit(&mut self,sender:u64,target:u64,message:Message)->Option<(u64,Arc<Reply>)>{
        self.admit_resumable(sender,target,message,None)
    }
    /// Announce that one thread is exiting; sends to it stop being admitted.
    /// # C: O(N_exiting)
    pub(crate) fn mark_exiting(&mut self,tid:u64){
        if let Some(thread)=self.threads.iter_mut().find(|thread|thread.tid==tid){thread.exiting=true;return;}
        if self.threads.try_reserve(1).is_err(){return;}
        self.threads.push(Thread{tid,changed:false,exiting:true});
    }
    pub(super) fn admit_resumable(&mut self,sender:u64,target:u64,message:Message,continuation:Option<Continuation>)->Option<(u64,Arc<Reply>)>{
        let thread=self.threads.iter().position(|thread|thread.tid==target);
        if thread.is_some_and(|index|self.threads[index].exiting){return None;}
        let next=self.next.checked_add(1)?;
        if thread.is_none()&&self.threads.try_reserve(1).is_err(){return None;}
        if self.work.len()>=LIMIT||self.work.try_reserve(1).is_err(){return None;}
        let reply=Arc::new(Reply::with_continuation(continuation));let token=self.next;self.next=next;
        self.work.push(Work{token,sender,target,message,event:None,reply:reply.clone(),resume:None,cancelled:false});
        if let Some(index)=thread{self.threads[index].changed=true;}
        else{self.threads.push(Thread{tid:target,changed:true,exiting:false});}Some((token,reply))
    }
    /// Queue a copied event without waiting for its announcing thread. # C: O(N_work + allocation)
    pub(super) fn admit_event(&mut self,target:u64,message:Message,event:Event)->Option<u64>{
        let (token,_)=self.admit_resumable(event.thread as u64,target,message,None)?;
        self.work.last_mut()?.event=Some(Arc::new(event));Some(token)
    }
    /// The send this thread is currently receiving, as the in-send-message
    /// thread-state class describes it. # C: O(sends)
    pub(crate) fn received_send(&self,tid:u64)->Option<ipc::win32_window::ReceivedSend>{
        self.work.iter().find(|w|w.target==tid&&w.resume.is_some()&&w.event.is_none()).map(|w|ipc::win32_window::ReceivedSend{
            inter_thread:w.sender!=w.target,replied:matches!(w.reply.outcome(),Some(Ok(_)))})
    }
    /// The reply of the message this thread is currently receiving. # C: O(sends)
    #[cfg(target_os = "oxide-kernel")]
    pub(crate) fn active_reply(&self,tid:u64)->Option<Arc<Reply>>{
        self.work.iter().find(|w|w.target==tid&&w.resume.is_some()&&w.event.is_none()).map(|w|Arc::clone(&w.reply))
    }
    pub(super) fn start(&mut self,tid:u64,resume:Resume,token:Option<u64>)->Option<Work>{
        let w=self.work.iter_mut().find(|w|w.target==tid&&w.resume.is_none()&&token.is_none_or(|t|w.token==t))?;
        w.resume=Some(resume);let work=w.clone();self.clear_drained();Some(work)
    }
    pub(super) fn finish(&mut self,tid:u64,token:u64,result:Option<u64>)->Option<(Resume,Arc<Reply>)>{
        let i=self.work.iter().position(|w|w.target==tid&&w.token==token&&w.resume.is_some())?;
        let w=self.work.remove(i);if let Some(result)=result.filter(|_|!w.cancelled){w.reply.complete(result);}else{w.reply.cancel();}Some((w.resume?,w.reply))
    }
    pub(super) fn cancel_thread(&mut self,tid:u64){
        self.threads.retain(|thread|thread.tid!=tid);
        self.work.retain_mut(|w|{
            if w.target==tid{w.reply.cancel();return false;}
            if w.sender==tid&&w.event.is_none(){if w.resume.is_some(){w.cancelled=true;return true;}w.reply.cancel();return false;}true
        });self.clear_drained();
    }
    pub(super) fn cancel_window(&mut self,hwnd:u64){
        self.work.retain_mut(|w|{if w.message.hwnd!=hwnd||w.event.as_ref().is_some_and(|event|!event.cancel_on_destroy){return true;}if w.resume.is_some(){w.cancelled=true;true}else{w.reply.cancel();false}});self.clear_drained();
    }
}
#[cfg(test)]
#[path="tests/work.rs"]mod tests;

#[cfg(test)]
#[path="tests/status.rs"]mod status_tests;
