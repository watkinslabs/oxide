//! Apply an expired canonical phase then publish after releasing GUI.
use alloc::sync::Arc;
use ipc::win32_window::ExpiredCaretCommit;
use super::{CaretRenderSink,publish_transition};
use super::super::GUI;

/// Current-thread identity and canonical generation protect against stale timer work.
/// # C: O(processes + windows + queues); # Sleeps: yes (publication outside GUI)
pub(crate) fn apply_for_current<S:CaretRenderSink+?Sized>(expired:ExpiredCaretCommit,sink:&mut S)->bool{
    let Some(cur)=sched::live::current()else{return false;};
    let tid=cur.tid as u64;if !cur.is_nt_personality()||tid!=expired.owner_tid{return false;}
    let commit={
        let mut entries=GUI.lock();
        let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return false;};
        entry.state.apply_expired_caret(tid,expired)
    };
    commit.is_some_and(|commit|publish_transition(sink,tid,commit.transition,commit.generation))
}
