//! Lifetime-gated shared-state admission and canonical raster invocation.
use super::super::*;
use ipc::win32_gdi::{Rect,GdiError};

/// # C: O(processes + objects + clipped major-axis span)
pub(crate) fn pen_line_for_current(dc:u64,x:i32,y:i32)->u64{draw(dc,Some((x,y)),None)}
/// # C: O(processes + objects + clipped area)
pub(crate) fn pen_rectangle_for_current(dc:u64,rect:Rect)->u64{draw(dc,None,Some(rect))}

fn draw(dc:u64,end:Option<(i32,i32)>,rect:Option<Rect>)->u64{
    let Ok(dc)=u32::try_from(dc)else{return 0;};
    let Ok(_gate)=lifecycle::ClientGate::acquire_current()else{return 0;};
    let Ok((_,binding))=text::snapshot_binding(u64::from(dc))else{return 0;};
    let shared=if let Some(binding)=binding{
        let Ok(bytes)=binding.read_dc_attr(dc)else{return 0;};
        let Ok(state)=super::shared::decode(&bytes,dc)else{return 0;};Some(state)
    }else{None};
    let Some(current)=sched::live::current()else{return 0;};
    let result={let mut entries=GDI.lock();
        let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&current.thread_group)))else{return 0;};
        match (end,rect){(Some(end),None)=>entry.state.pen_line_to(dc,end,shared),
            (None,Some(rect))=>entry.state.pen_rectangle(dc,rect,shared),_=>Err(GdiError::InvalidDimensions)}
    };
    if result.is_err(){return 0;}
    if let (Some(binding),Some(end))=(binding,end){if binding.set_text_position(dc,end).is_err(){return 0;}}
    1
}
