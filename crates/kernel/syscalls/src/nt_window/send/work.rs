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
#[derive(Clone)]
pub(super) struct Work {pub token:u64,pub sender:u64,pub target:u64,pub message:Message,pub reply:Arc<Reply>,pub resume:Option<Resume>,cancelled:bool}
pub(crate) struct Queue {next:u64,work:Vec<Work>}
impl Queue {
    /// # C: O(1)
    pub(crate) fn new()->Self{Self{next:1,work:Vec::new()}}
    /// GUI-locked readiness; takes no additional lock. # C: O(sends)
    pub(crate) fn has_for_tid(&self,tid:u64)->bool{self.work.iter().any(|w|w.target==tid&&w.resume.is_none())}
    /// A retiring sender cannot free resources used by a surviving recipient callback.
    /// # C: O(sends); caller holds canonical GUI ownership
    pub(crate) fn has_foreign_active(&self,sender:u64,hwnd:u64)->bool{
        self.work.iter().any(|w|w.sender==sender&&w.target!=sender&&w.message.hwnd==hwnd&&w.resume.is_some())
    }
    #[cfg(test)]
    pub(super) fn admit(&mut self,sender:u64,target:u64,message:Message)->Option<(u64,Arc<Reply>)>{
        self.admit_resumable(sender,target,message,None)
    }
    pub(super) fn admit_resumable(&mut self,sender:u64,target:u64,message:Message,continuation:Option<Continuation>)->Option<(u64,Arc<Reply>)>{
        let next=self.next.checked_add(1)?;
        if self.work.len()>=LIMIT||self.work.try_reserve(1).is_err(){return None;}
        let reply=Arc::new(Reply::with_continuation(continuation));let token=self.next;self.next=next;
        self.work.push(Work{token,sender,target,message,reply:reply.clone(),resume:None,cancelled:false});Some((token,reply))
    }
    pub(super) fn start(&mut self,tid:u64,resume:Resume,token:Option<u64>)->Option<Work>{
        let w=self.work.iter_mut().find(|w|w.target==tid&&w.resume.is_none()&&token.is_none_or(|t|w.token==t))?;
        w.resume=Some(resume);Some(w.clone())
    }
    pub(super) fn finish(&mut self,tid:u64,token:u64,result:Option<u64>)->Option<(Resume,Arc<Reply>)>{
        let i=self.work.iter().position(|w|w.target==tid&&w.token==token&&w.resume.is_some())?;
        let w=self.work.remove(i);if let Some(result)=result.filter(|_|!w.cancelled){w.reply.complete(result);}else{w.reply.cancel();}Some((w.resume?,w.reply))
    }
    pub(super) fn cancel_thread(&mut self,tid:u64){
        self.work.retain_mut(|w|{
            if w.target==tid{w.reply.cancel();return false;}
            if w.sender==tid{if w.resume.is_some(){w.cancelled=true;return true;}w.reply.cancel();return false;}true
        });
    }
    pub(super) fn cancel_window(&mut self,hwnd:u64){
        self.work.retain_mut(|w|{if w.message.hwnd!=hwnd{return true;}if w.resume.is_some(){w.cancelled=true;true}else{w.reply.cancel();false}});
    }
}
#[cfg(test)]
#[path="tests/work.rs"]mod tests;
