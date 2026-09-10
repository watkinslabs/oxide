//! Queue classes accepted by a message wait, shared before and after parking.
use ipc::win32_window::queue_status::QS_SENDMESSAGE;

/// # C: O(queued messages + windows + sent work)
pub(super) fn queue(entry:&super::super::GuiEntry,tid:u64,mask:u32)->bool{
    entry.state.queue_satisfies(tid,mask)||(mask&QS_SENDMESSAGE!=0&&entry.sent.has_for_tid(tid))
}
