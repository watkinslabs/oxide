//! Owned internal requests, bounded independently of application messages.
use alloc::vec::Vec;
use alloc::sync::Arc;
#[cfg(target_os="oxide-kernel")]
pub(super) use crate::nt_window::send::Reply;
#[cfg(not(target_os="oxide-kernel"))]
#[path="../send/reply.rs"] mod reply;
#[cfg(not(target_os="oxide-kernel"))]
pub(super) use reply::Reply;
const MAX_REMOTE:usize=64;
#[derive(Clone)]
pub(crate) struct RemotePosition {pub(super) target:u64,pub(super) args:[u64;7],pub(super) reply:Option<Arc<Reply>>}
impl RemotePosition {
    /// Caller may already hold GUI; this predicate takes no locks. # C: O(1)
    pub(crate) fn targets(&self,tid:u64)->bool {self.target==tid}
}
/// Caller holds canonical GUI lock; no nested locking. # C: O(requests)
pub(crate) fn has_remote_for_tid(work:&[RemotePosition],tid:u64)->bool {work.iter().any(|r|r.targets(tid))}
pub(super) fn admit(work:&mut Vec<RemotePosition>,target:u64,args:[u64;7],reply:Option<Arc<Reply>>)->bool {
    if work.len()>=MAX_REMOTE||work.try_reserve(1).is_err(){return false;}
    work.push(RemotePosition {target,args,reply});true
}
pub(super) fn take(work:&mut Vec<RemotePosition>,tid:u64)->Option<RemotePosition> {
    let index=work.iter().position(|r|r.target==tid)?;Some(work.remove(index))
}
pub(super) fn cancel_thread(work:&mut Vec<RemotePosition>,tid:u64){work.retain(|r|{if r.target!=tid{return true;}if let Some(reply)=&r.reply{reply.complete(0);}false});}
pub(super) fn cancel_window(work:&mut Vec<RemotePosition>,hwnd:u64){work.retain(|r|{if r.args[0]!=hwnd{return true;}if let Some(reply)=&r.reply{reply.complete(0);}false});}
#[cfg(test)]
#[path="../tests/position_work.rs"]mod tests;
