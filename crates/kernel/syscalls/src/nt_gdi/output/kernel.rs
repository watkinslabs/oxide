// One bounded process-output pass; GUI/GDI locks never cross transport waits.
use super::{flush_one,reserve_snapshot,reserve_prepared,PrepareError,PreparedFrame,publish_prepared};
use super::super::{GDI,Arc,STATUS_SUCCESS};
use super::transport::submit_frame;
const STATUS_PENDING:u64=0x103;

/// Call after releasing GDI; explicit paint and pump share the same reservation owner.
/// # C: transport + process/DC lookup
pub(crate) fn submit_prepared_for_current(prepared:Result<PreparedFrame,u64>)->u64{
    let prepared=match prepared{Ok(prepared)=>prepared,Err(status)=>return status};
    let Some(current)=sched::live::current()else{return super::super::STATUS_INVALID_HANDLE;};
    let group=Arc::downgrade(&current.thread_group);
    let prepared={
        let mut entries=GDI.lock();
        let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group))else{return super::super::STATUS_INVALID_HANDLE;};
        match reserve_prepared(&mut entry.state,prepared){Ok(prepared)=>prepared,
            Err(PrepareError::Settled)=>return STATUS_SUCCESS,
            Err(PrepareError::Busy)=>return STATUS_PENDING,Err(_)=>return super::super::STATUS_INVALID_HANDLE}
    };
    let mut retained=false;
    let status=publish_prepared(prepared,|frame|submit_frame(Ok(frame)),|token,presented|{
        let mut entries=GDI.lock();
        if let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group)){
            entry.state.finish_output(token,presented);
            retained=entry.state.pending_output(token.hwnd,token.dc).is_some();
        }
    });
    if status!=STATUS_SUCCESS&&retained{STATUS_PENDING}else{status}
}

/// Main calls outside GUI/client locks before message-pump blocking. # C: O(windows + dirty frame pixels + transport)
pub(crate) fn flush_pending_for_current(idle:bool){
    let Some(current)=sched::live::current().filter(|task|task.is_nt_personality())else{return;};
    let group=Arc::downgrade(&current.thread_group);
    let candidates={
        let mut entries=GDI.lock();
        let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group))else{return;};
        if !entry.output_pump.allow(idle,timekeeper::monotonic_ns()){return;}
        let Ok(tokens)=entry.state.pending_outputs()else{return;};tokens
    };
    for candidate in candidates{
        // Window liveness belongs to GUI; hidden windows retain frames without mapping.
        if crate::nt_window::window_rect_for_current(candidate.hwnd).is_none(){continue;}
        let _=flush_one(||{
            let mut entries=GDI.lock();
            let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group))else{return Ok::<_,()>(None);};
            let Some(current)=entry.state.pending_output(candidate.hwnd,candidate.dc)else{return Ok(None);};
            reserve_snapshot(&mut entry.state,current)
        },|frame|submit_frame(Ok(frame))==STATUS_SUCCESS,|token,presented|{
            let mut entries=GDI.lock();
            if let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group)){
                entry.state.finish_output(token,presented);
            }
        });
    }
}
