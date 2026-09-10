//! Public queue status observes both canonical inbox owners under the process GUI lock.
use super::super::owner::{current_tid,with_entry};

/// Validate masks before either owner clears changed bits. # C: O(N_processes + N_queues + N_messages)
pub(crate) fn queue_status_for_current(flags:u32)->Option<u32>{
    let tid=current_tid()?;
    with_entry(|entry|{
        let posted=entry.state.queue_status(tid,flags)?;
        Some(posted|entry.sent.queue_status(tid,flags))
    })?
}
