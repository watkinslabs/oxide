//! Callback installation seam; DC acquisition/release uses real canonical GUI/GDI owners.
use super::*;
use win32_gdi::{GdiManager,DcLeaseRequest};
#[derive(Clone)] pub(crate) struct Call {pub bytes:Vec<u8>,pub completion:nt_callback::Completion}
pub(crate) struct State {pub gdi:GdiManager,pub calls:Vec<Call>,pub released:Vec<u32>,pub acquired:Vec<(u32,u32,u32)>,pub fail_dc:bool,pub fail_callback:bool}
impl Default for State {fn default()->Self{Self{gdi:GdiManager::new(),calls:Vec::new(),released:Vec::new(),acquired:Vec::new(),fail_dc:false,fail_callback:false}}}
thread_local!{pub(crate) static STATE:RefCell<State>=RefCell::new(State::default());}
pub(crate) fn reset(){STATE.with(|s|*s.borrow_mut()=State::default());}
pub(crate) fn get_dc_ex_for_current(hwnd:u32,region:u32,flags:u32)->u64{
    assert!(nt_window::GUI.0.try_lock().is_ok());
    STATE.with(|s|s.borrow_mut().acquired.push((hwnd,region,flags)));
    if STATE.with(|s|s.borrow().fail_dc){return 0;}
    let context={let entries=nt_window::GUI.lock();let Some(window)=win32_window::WindowId::from_raw(hwnd)else{return 0;};
        let Ok(context)=entries[0].state.dc_lease_context(window,flags)else{return 0;};context};
    STATE.with(|s|{let mut s=s.borrow_mut();let g=&mut s.gdi;
        let backing=g.acquire_window_dc(context.backing_hwnd,context.backing_width,context.backing_height).unwrap();
        g.acquire_dc_lease(DcLeaseRequest{hwnd,backing_hwnd:context.backing_hwnd,backing,origin:context.origin,
            screen_origin:context.screen_origin,width:context.logical_width,height:context.logical_height,
            flags:context.flags,owner:context.owner,visible:context.visible,clip_handle:region}).unwrap()as u64})
}
pub(crate) fn release_dc_lease_for_current(dc:u32)->bool{
    assert!(nt_window::GUI.0.try_lock().is_ok());
    STATE.with(|s|{let mut s=s.borrow_mut();s.released.push(dc);s.gdi.release_dc_lease(dc).is_ok()})
}
pub(crate) fn begin_user_callback(id:u32,input:nt_user_callback::Input<'_>,completion:nt_callback::Completion)->u64{
    assert!(nt_window::GUI.0.try_lock().is_ok());assert_eq!(id,8);
    let nt_user_callback::Input::Record(bytes)=input;
    STATE.with(|s|{let mut s=s.borrow_mut();s.calls.push(Call{bytes:bytes.to_vec(),completion});
        if s.fail_callback{0xc000000d}else{nt_window::STATUS_PENDING}})
}
pub(crate) fn latest()->Call{STATE.with(|s|s.borrow().calls.last().unwrap().clone())}
pub(crate) fn complete(result:u64)->u64{nt_window::complete_callback(latest().completion,result)}
