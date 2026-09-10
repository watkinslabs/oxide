//! Retrieval acknowledges selected arrivals after sent callbacks and before scanning.
use super::super::*;

/// Invalid window filters leave changed bits intact. # C: O(N_processes + N_queues + N_windows)
#[inline(never)]
pub(super) fn acknowledge(hwnd:u64,first:u32,last:u32,flags:u32)->Option<u64>{
    let Some(current)=sched::live::current() else{return Some(STATUS_INVALID_PARAMETER);};
    let mut entries=GUI.lock();
    let index=owner::entry_index(&mut entries,&current.thread_group);
    let state=&mut entries[index].state;
    let Some(filter)=message_filter(state,hwnd,first,last) else{return Some(STATUS_INVALID_HANDLE);};
    state.acknowledge_retrieval(current.tid as u64,flags,filter);
    None
}
