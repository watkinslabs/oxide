//! Production live adapter with real IPC/GDI owners and instrumented scheduler/copy/callback installation.
use std::{sync::{Arc,Weak,Mutex,MutexGuard},cell::RefCell};
use ipc::{win32_window::{WindowManager,PaintRegion},win32_gdi::GdiManager};
#[path="hosted_adapter.rs"]mod paint_prepare;
#[path="hosted_callbacks.rs"]mod paint_callbacks;
#[path="hosted_redraw.rs"]mod redraw;
#[path="hosted_gdi.rs"]pub(crate) mod gdi_adapter;
pub mod thread_group{pub struct ThreadGroup;}
#[derive(Clone)]pub struct Task{pub tid:usize,pub thread_group:Arc<thread_group::ThreadGroup>}
impl Task{pub fn is_nt_personality(&self)->bool{true}}
pub mod live{pub fn current()->Option<super::Task>{super::ENV.with(|e|e.borrow().task.clone())}}
#[derive(Default)]struct Env{task:Option<Task>,pending:Option<(paint_callbacks::Resources,paint_prepare::Prepared)>,bytes:Vec<u8>,copy_fault:bool,
    send:Option<send::Continuation>,messages:Vec<(u64,u32,u64)>,fail_send:bool,milestones:usize,immediate:Option<u64>,
    erase_finished:Vec<(u64,Result<u64,()>)>,deletions:Vec<u32>}
thread_local!{static ENV:RefCell<Env>=RefCell::new(Env::default());}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
struct Entry{group:Weak<thread_group::ThreadGroup>,state:WindowManager,paint_callbacks:paint_callbacks::Queue,sent:send::Queue}
static GUI:Lock<Vec<Entry>>=Lock(Mutex::new(Vec::new()));
static GDI:Mutex<Option<GdiManager>>=Mutex::new(None);
static SERIAL:Mutex<()>=Mutex::new(());
pub(crate) fn milestone(){ENV.with(|e|e.borrow_mut().milestones+=1);}
const STATUS_PENDING:u64=0x103;
#[path="hosted_send.rs"]mod send;
pub fn copy_to_user(_:u64,bytes:&[u8])->Result<(),()>{
    assert!(GUI.0.try_lock().is_ok());ENV.with(|e|{let mut e=e.borrow_mut();e.bytes=bytes.to_vec();if e.copy_fault{Err(())}else{Ok(())}})
}
pub(crate) fn delete_paint_dc_current(dc:u32)->Result<(),()>{
    assert!(GUI.0.try_lock().is_ok());ENV.with(|e|e.borrow_mut().deletions.push(dc));GDI.lock().unwrap().as_mut().unwrap().delete_object(dc).map_err(|_|())
}
pub(crate) fn set_paint_region_for_current(dc:u64,region:PaintRegion)->Result<(),()>{
    assert!(GUI.0.try_lock().is_ok());GDI.lock().unwrap().as_mut().unwrap().set_paint_region(dc as u32,region).map_err(|_|())
}
pub(crate) fn create_region_for_current(region:PaintRegion)->Result<u32,u64>{
    assert!(GUI.0.try_lock().is_ok());GDI.lock().unwrap().as_mut().unwrap().create_region(region).map_err(|_|0)
}
fn run(resources:paint_callbacks::Resources,p:paint_prepare::Prepared)->u64{
    assert!(GUI.0.try_lock().is_ok());ENV.with(|e|e.borrow_mut().pending=Some((resources,p)));0x103
}
#[path="live_tests.rs"]mod tests;
