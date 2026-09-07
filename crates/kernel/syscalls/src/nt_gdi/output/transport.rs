//! A drawing submission is handed over, not transacted with the desktop.
const STATUS_SUCCESS:u64=0;
const STATUS_INVALID_PARAMETER:u64=0xc000000d;

/// Hand one frame to the desktop and return. The reference resets a window
/// surface's accumulated bounds when its driver accepts the flush, not when
/// the display server answers for it: a paint that waits for that answer
/// stops the application for a round trip it has no use for, and the answer
/// arrives long after the pixels the next paint already wants to replace.
/// # C: bounded queue lookup; # Sleeps: no
pub(crate) fn submit_frame(frame:Result<syscall::nt_compositor::Record,u64>)->u64{
    let frame=match frame{Ok(frame)=>frame,Err(status)=>return status};
    match crate::nt_compositor::submit_current(frame.header.opcode,frame.header.hwnd,frame.payload){
        Ok(_)=>STATUS_SUCCESS,
        Err(_)=>STATUS_INVALID_PARAMETER,
    }
}
