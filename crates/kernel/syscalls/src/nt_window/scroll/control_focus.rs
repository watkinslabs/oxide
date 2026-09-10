//! Scrollbar focus uses the canonical queue caret and update-region owners.
use alloc::sync::Arc;
use ipc::win32_window::{CaretPattern,WindowId,WindowRect};
use crate::nt_window::{GUI,caret};
use super::proc_abi::SBS_VERT;

/// Caret calls keep their ordering even when an earlier operation fails. # C: O(owner work)
pub(crate) fn for_current(hwnd:u64,gained:bool)->u64{
    let Some(g)=super::control_geometry::for_current(hwnd)else{return 0;};
    let vertical=g.style&SBS_VERT!=0;let mut sink=caret::publish::Current;
    if gained{
        let(width,height,x,y)=if vertical{(g.rect.right-g.rect.left-2,g.layout.thumb_size-2,g.rect.top+1,g.layout.thumb_pos+1)}
            else{(g.layout.thumb_size-2,g.rect.bottom-g.rect.top-2,g.layout.thumb_pos+1,g.rect.top+1)};
        let _=caret::live::create_pattern_for_current(hwnd,width,height,CaretPattern::Gray,&mut sink);
        let _=caret::live::set_caret_pos_for_current(x,y,&mut sink);
        let _=caret::live::show_caret_for_current(hwnd,&mut sink);
    }else{
        let mut rect=WindowRect{left:g.rect.left,top:g.rect.top,right:g.rect.right,bottom:g.rect.bottom};
        if vertical{rect.top=g.layout.thumb_pos+1;rect.bottom=rect.top+g.layout.thumb_size;}
        else{rect.left=g.layout.thumb_pos+1;rect.right=rect.left+g.layout.thumb_size;}
        let _=caret::live::hide_caret_for_current(hwnd,&mut sink);
        invalidate(hwnd,rect);
        let _=caret::live::destroy_caret_for_current(&mut sink);
    }0
}
fn invalidate(hwnd:u64,rect:WindowRect){
    let Some(cur)=sched::live::current()else{return;};
    let Some(window)=u32::try_from(hwnd).ok().and_then(WindowId::from_raw)else{return;};
    let mut entries=GUI.lock();
    let Some(entry)=entries.iter_mut().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return;};
    if entry.state.invalidate(window,Some(rect)).is_ok(){entry.wait.wake_all();}
}
