//! Real GDI storage behind process lookup boundary; no display transport in this fixture.
pub(crate) use crate::nt_window::{delete_paint_dc_current,set_paint_region_for_current,create_region_for_current};
use ipc::{win32_window::{PaintRegion,WindowId},win32_gdi::{PaintBacking,Rect}};
use crate::nt_window::{GDI,GUI};
fn layout(hwnd:u32)->Result<PaintBacking,u64>{
    let entries=GUI.lock();let id=WindowId::from_raw(hwnd).ok_or(0u64)?;let r=entries[0].state.get(id).ok_or(0u64)?;
    let b=entries[0].state.rect(id).ok_or(0u64)?;let c=r.client_rect.unwrap_or(b);
    Ok(PaintBacking{width:b.right-b.left,height:b.bottom-b.top,client:Rect{left:c.left-b.left,top:c.top-b.top,right:c.right-b.left,bottom:c.bottom-b.top}})
}
pub fn acquire_window_dc_for_current(hwnd:u32,w:i32,h:i32)->u64{GDI.lock().unwrap().as_mut().unwrap().acquire_window_dc(hwnd,w,h).map(u64::from).unwrap_or(0xc000000d)}
pub fn create_paint_dc_for_current(w:i32,h:i32)->Result<u32,u64>{GDI.lock().unwrap().as_mut().unwrap().create_dc(w,h).map_err(|_|0)}
pub fn seed_paint_for_current(hwnd:u32,dc:u32)->Result<(),u64>{let l=layout(hwnd)?;GDI.lock().unwrap().as_mut().unwrap().seed_paint(hwnd,dc,l).map_err(|_|0)}
pub fn release_window_dc_for_current(hwnd:u32,dc:u32)->u64{GDI.lock().unwrap().as_ref().unwrap().release_window_dc(hwnd,dc).map_or(0xc000000d,|_|0)}
pub fn region_snapshot_for_current(r:u64)->Result<PaintRegion,u64>{GDI.lock().unwrap().as_ref().unwrap().region_snapshot(r as u32).map_err(|_|0)}
pub fn delete_region_for_current(r:u64)->Result<(),u64>{delete_paint_dc_current(r as u32).map_err(|_|0)}
pub fn retain_erase_for_current(hwnd:u32,dc:u32,r:&PaintRegion,l:PaintBacking)->Result<(),u64>{
    if layout(hwnd)?!=l{return Err(0);}GDI.lock().unwrap().as_mut().unwrap().retain_paint_region(hwnd,dc,r,l).map(|_|()).map_err(|_|0)
}
