//! Incoming display geometry enters the existing owner-thread position queue.
use alloc::vec::Vec;
use ipc::win32_window::{WindowId,WindowManager,WindowRect};
use super::work::{self,RemotePosition};
const NOSIZE:u32=0x0001;
const NOMOVE:u32=0x0002;
const NOZORDER:u32=0x0004;
const NOACTIVATE:u32=0x0010;

/// Queue callbacks without changing canonical geometry in the display worker.
/// Windows without a procedure retain the immediate geometry path. # C: O(windows + queued requests)
pub(crate) fn queue_compositor(state:&mut WindowManager,positions:&mut Vec<RemotePosition>,id:WindowId,next:WindowRect)->bool {
    let Some(record)=state.get(id)else{return false;};
    if record.wndproc==0{return state.configure_compositor_window(id,next).is_ok();}
    let Ok(next)=state.compositor_parent_space(id,next)else{return false;};
    let Some(width)=next.right.checked_sub(next.left).filter(|v|*v>=0)else{return false;};
    let Some(height)=next.bottom.checked_sub(next.top).filter(|v|*v>=0)else{return false;};
    let args=[id.raw() as u64,0,next.left as u32 as u64,next.top as u32 as u64,width as u64,height as u64,(NOZORDER|NOACTIVATE) as u64];
    work::admit_compositor(positions,record.owner_tid,args)
}

/// Compare at consumption, after preceding queued positions have committed. # C: O(1)
pub(super) fn plan(args:&mut [u64;7],old:WindowRect)->bool {
    let (Some(right),Some(bottom))=((args[2] as i32).checked_add(args[4] as i32),(args[3] as i32).checked_add(args[5] as i32))else{return false;};
    let next=WindowRect{left:args[2] as i32,top:args[3] as i32,right,bottom};
    let mut flags=NOZORDER|NOACTIVATE;
    if (old.left,old.top)==(next.left,next.top){flags|=NOMOVE;}
    if (old.right as i64-old.left as i64,old.bottom as i64-old.top as i64)==(next.right as i64-next.left as i64,next.bottom as i64-next.top as i64){flags|=NOSIZE;}
    if flags&(NOMOVE|NOSIZE)==NOMOVE|NOSIZE{return false;}
    args[6]=flags as u64;true
}
