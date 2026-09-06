use std::{sync::{Arc,Weak,Mutex,MutexGuard},cell::RefCell};
use ipc::{win32_window::{WindowManager,WindowId,WindowRect,PaintRegion},win32_gdi::GdiManager};
#[path="../../src/nt_window/paint_prepare/hosted_adapter.rs"]mod paint_prepare;
#[path="../../src/nt_window/paint_prepare/hosted_callbacks.rs"]mod paint_callbacks;
mod default_paint{pub(crate) fn finish_for_current(_:super::paint_prepare::Prepared,_:Result<bool,()>)->u64{unreachable!("default paint is a kernel-only path")}}
#[path="../../src/nt_window/paint.rs"]mod paint;
#[path="../../src/nt_window/redraw/erase.rs"]mod erase_contract;
mod redraw{pub mod erase{
    pub(crate) use super::super::erase_contract::ErasePrepared;
    pub(crate) fn finish_for_current(_:ErasePrepared,_:Result<bool,()>)->u64{panic!("unexpected redraw completion")}
    pub(crate) fn discard_for_current(_:ErasePrepared){panic!("unexpected redraw discard")}
}}
#[path="send.rs"]mod send;
#[path="gdi.rs"]pub(crate) mod gdi;
#[path="tests.rs"]mod tests;
pub mod thread_group{pub struct ThreadGroup;}
#[derive(Clone)]pub struct Task{pub tid:usize,pub thread_group:Arc<thread_group::ThreadGroup>}
impl Task{pub fn is_nt_personality(&self)->bool{true}}
pub mod live{pub fn current()->Option<super::Task>{super::ENV.with(|e|e.borrow().task.clone())}}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]enum Event{Nc,Erase,Retain,Copy,DeleteDc,DeleteRegion}
#[derive(Default)]struct Env{task:Option<Task>,pending:Option<(u32,u64,send::Continuation)>,events:Vec<Event>,copies:Vec<(u64,Vec<u8>)>,milestones:usize}
thread_local!{static ENV:RefCell<Env>=RefCell::new(Env::default());}
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
struct Entry{group:Weak<thread_group::ThreadGroup>,state:WindowManager,paint_callbacks:paint_callbacks::Queue,sent:send::Queue}
static GUI:Lock<Vec<Entry>>=Lock(Mutex::new(Vec::new()));
static GDI:Mutex<Option<GdiManager>>=Mutex::new(None);
static SERIAL:Mutex<()>=Mutex::new(());
const STATUS_PENDING:u64=0x103;
const STATUS_SUCCESS:u64=0;
const STATUS_INVALID_HANDLE:u64=0xc0000008;
const OMIT_CALLBACK_PIXELS_CONTROL:bool=false;
pub(crate) fn milestone(){ENV.with(|e|e.borrow_mut().milestones+=1);}
pub fn copy_to_user(destination:u64,bytes:&[u8])->Result<(),()>{
    assert!(GUI.0.try_lock().is_ok());assert!(GDI.try_lock().is_ok());
    ENV.with(|e|{let mut e=e.borrow_mut();e.events.push(Event::Copy);e.copies.push((destination,bytes.to_vec()));});Err(())
}
fn valid_window(hwnd:u64)->Option<WindowId>{u32::try_from(hwnd).ok().and_then(WindowId::from_raw)}
fn copy_rect(_:syscall::UserPtr<syscall::nt::NtWindowRect>,_:WindowRect)->u64{panic!("unexpected native RECT write")}
