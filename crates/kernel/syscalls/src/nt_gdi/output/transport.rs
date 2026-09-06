//! Only a terminal protocol Presented completion is a desktop acknowledgement.
const STATUS_SUCCESS:u64=0;
const STATUS_INVALID_PARAMETER:u64=0xc000000d;
const ACK_TIMEOUT_NS:u64=5_000_000_000;

/// # C: bounded queue lookup + acknowledged transport wait; # Sleeps: yes, no owner locks
pub(crate) fn submit_frame(frame:Result<syscall::nt_compositor::Record,u64>)->u64{
    let frame=match frame{Ok(frame)=>frame,Err(status)=>return status};
    let ticket=match crate::nt_compositor::enqueue_current(frame.header.opcode,frame.header.hwnd,frame.payload){
        Ok(ticket)=>ticket,Err(_)=>return STATUS_INVALID_PARAMETER,
    };
    match crate::nt_compositor::wait_completion_current(ticket,ACK_TIMEOUT_NS){
        Ok(crate::nt_compositor::Completion::Presented)=>{crate::nt_milestone::desktop_ack();STATUS_SUCCESS}
        _=>STATUS_INVALID_PARAMETER,
    }
}
