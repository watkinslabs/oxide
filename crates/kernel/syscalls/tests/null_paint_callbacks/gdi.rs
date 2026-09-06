//! Process lookup seams use canonical IPC storage; retention precedes temporary resource deletion.
use super::*;
use ipc::win32_gdi::PaintBacking;
pub(crate) fn create_region_for_current(region:PaintRegion)->Result<u32,u64>{
    assert!(GUI.0.try_lock().is_ok());GDI.lock().unwrap().as_mut().unwrap().create_region(region).map_err(|_|STATUS_INVALID_HANDLE)
}
pub(crate) fn set_paint_region_for_current(dc:u64,region:PaintRegion)->Result<(),u64>{
    assert!(GUI.0.try_lock().is_ok());GDI.lock().unwrap().as_mut().unwrap().set_paint_region(dc as u32,region).map_err(|_|STATUS_INVALID_HANDLE)
}
pub(crate) fn delete_paint_dc_current(handle:u32)->Result<(),u64>{
    assert!(GUI.0.try_lock().is_ok());let mut gdi=GDI.lock().unwrap();let state=gdi.as_mut().unwrap();
    let event=if state.region_snapshot(handle).is_ok(){Event::DeleteRegion}else{Event::DeleteDc};
    state.delete_object(handle).map_err(|_|STATUS_INVALID_HANDLE)?;ENV.with(|e|e.borrow_mut().events.push(event));Ok(())
}
pub(crate) fn retain_erase_for_current(hwnd:u32,dc:u32,region:&PaintRegion,layout:PaintBacking)->Result<(),u64>{
    assert!(GUI.0.try_lock().is_ok());
    let entries=GUI.lock();assert!(entries[0].state.paint_session(WindowId::from_raw(hwnd).unwrap()).is_ok());drop(entries);
    GDI.lock().unwrap().as_mut().unwrap().retain_paint_region(hwnd,dc,region,layout).map_err(|_|STATUS_INVALID_HANDLE)?;
    ENV.with(|e|e.borrow_mut().events.push(Event::Retain));Ok(())
}
