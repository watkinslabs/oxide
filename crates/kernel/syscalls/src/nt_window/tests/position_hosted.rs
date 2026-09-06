use std::sync::{Arc,Weak,Mutex,MutexGuard};
use ipc::win32_window::WindowManager;
pub(crate) const STATUS_PENDING:u64=0x103;
pub(crate) struct Lock<T>(pub(crate) Mutex<T>);
impl<T> Lock<T>{pub fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
pub(crate) struct Wait;
impl Wait {pub fn wake_all(&self){}}
pub(crate) struct Entry {
    pub group:Weak<crate::thread_group::ThreadGroup>,pub state:WindowManager,
    pub pending_positions:Vec<position::PendingPosition>,pub remote_positions:Vec<position::RemotePosition>,
    pub next_create:u64,pub foreground:bool,pub wait:Arc<Wait>,
}
pub(crate) static GUI:Lock<Vec<Entry>>=Lock(Mutex::new(Vec::new()));
#[path="../position.rs"] pub(crate) mod position;
pub(crate) use position::{position_context_for_current,position_apply_for_current};
pub(crate) mod bridge {
    pub fn publish_geometry_current(_:u64)->Result<(),()>{crate::environment::publish()}
    pub fn publish_visibility_current(_:u64)->Result<(),()>{crate::environment::publish()}
    pub fn publish_position_current(_:u64,_:Option<u64>,_:bool)->Result<(),()>{crate::environment::publish()}
}
pub(crate) fn resume_position_message_current()->u64{panic!("unexpected retrieval boundary")}
pub(crate) fn window_rect_for_current(hwnd:u32)->Option<(ipc::win32_window::WindowRect,bool)>{
    let entries=GUI.lock();let state=&entries[0].state;let id=ipc::win32_window::WindowId::from_raw(hwnd)?;Some((state.rect(id)?,state.get(id)?.visible))
}
pub(crate) mod send {
    pub fn wait_reply<T>(_:std::sync::Arc<T>)->u64{panic!("unexpected cross-thread reply boundary")}
}
#[path="position_boundary/cases.rs"] mod cases;
