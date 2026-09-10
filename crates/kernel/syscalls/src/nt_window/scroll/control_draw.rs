//! Canonical control geometry serialized into the drawing callback record.
use ipc::win32_gdi::ScrollLayout;
use super::proc_abi::*;

/// # C: O(processes + windows² + scrollbar layout)
pub(super) fn record(hwnd:u64,dc:u64,arrows:bool,interior:bool)->Option<[u8;DRAW_BYTES]>{
    let geometry=super::control_geometry::for_current(hwnd)?;
    let rect=geometry.rect;
    if !geometry.drawable||rect.left>=rect.right||rect.top>=rect.bottom{return None;}
    let size_box=geometry.style&(SBS_SIZEBOX|SBS_SIZEGRIP)!=0;
    let vertical=!size_box&&geometry.style&SBS_VERT!=0;
    let layout=if size_box{ScrollLayout{arrow_size:0,thumb_pos:0,thumb_size:0}}else{geometry.layout};
    Some(draw_record(hwnd,dc,rect,layout,geometry.flags,vertical,arrows,interior))
}
