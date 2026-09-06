//! Production position/GDI adapter; fixture supplies process lookup and lifetime-gate boundary.
use std::sync::{Arc,Weak,Mutex};
use crate::nt_window::Lock;
use ipc::win32_window::WindowRect;
struct Entry{group:Weak<crate::thread_group::ThreadGroup>,state:ipc::win32_gdi::GdiManager,client:Option<Binding>}
#[derive(Clone,Copy)]struct Binding;
impl Binding{fn update_dc_dimensions(&self,dc:u32,width:i32,height:i32)->Result<(),()>{
    assert!(GDI.0.try_lock().is_ok());assert!(crate::nt_window::GUI.0.try_lock().is_ok());
    super::ENV.with(|e|e.borrow_mut().dimensions.push((dc,width,height)));Ok(())
}}
static GDI:Lock<Vec<Entry>>=Lock(Mutex::new(Vec::new()));
const STATUS_INVALID_HANDLE:u64=0xc0000008;
const STATUS_INVALID_PARAMETER:u64=0xc000000d;
mod lifecycle{
    pub struct ClientGate;
    impl ClientGate{pub fn acquire_current()->Result<Self,()>{assert!(crate::nt_window::GUI.0.try_lock().is_ok());Ok(Self)}}
}
#[path="../../../nt_gdi/position_preserve.rs"]mod live;
pub fn position_preserve_for_current(hwnd:u32,old:WindowRect,new:WindowRect,valid:Option<[WindowRect;2]>,flags:u32)->Result<(),u64>{
    live::position_preserve_for_current(hwnd,old,new,valid,flags)?;
    super::ENV.with(|e|e.borrow_mut().preservation.push((hwnd,old,new,valid)));Ok(())
}
pub fn reset(group:&Arc<crate::thread_group::ThreadGroup>){*GDI.lock()=vec![Entry{group:Arc::downgrade(group),state:ipc::win32_gdi::GdiManager::new(),client:Some(Binding)}];}
pub fn seed(hwnd:u32,w:i32,h:i32,color:u32)->u32{
    let mut entries=GDI.lock();let state=&mut entries[0].state;let dc=state.acquire_window_dc(hwnd,w,h).unwrap();
    state.fill_rect(dc,ipc::win32_gdi::Rect{left:0,top:0,right:w,bottom:h},color).unwrap();dc
}
pub fn pixels(dc:u32)->Vec<u32>{GDI.lock()[0].state.pixels(dc).unwrap().to_vec()}
pub fn pending(hwnd:u32,dc:u32)->Option<ipc::win32_gdi::OutputToken>{GDI.lock()[0].state.pending_output(hwnd,dc)}
pub fn ack(token:ipc::win32_gdi::OutputToken)->bool{GDI.lock()[0].state.acknowledge_output(token)}
pub fn reserve(token:ipc::win32_gdi::OutputToken)->bool{GDI.lock()[0].state.reserve_output(token)}
pub fn finish(token:ipc::win32_gdi::OutputToken,presented:bool)->bool{GDI.lock()[0].state.finish_output(token,presented)}
pub fn draw(dc:u32,rect:ipc::win32_gdi::Rect){GDI.lock()[0].state.fill_rect(dc,rect,0x654321).unwrap();}
