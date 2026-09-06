use std::sync::{Arc,Mutex};
use std::cell::RefCell;
use crate::nt_window::position::Outcome;
pub mod thread_group {pub struct ThreadGroup;}
pub mod nt_callback {#[derive(Clone,Copy,Debug)]pub struct Completion{pub kind:u64,pub argument:u64}}
#[derive(Clone)]pub struct Task{pub tid:usize,pub thread_group:Arc<thread_group::ThreadGroup>}
impl Task {pub fn is_nt_personality(&self)->bool{true}}
pub mod live {pub fn current()->Option<super::Task>{super::ENV.with(|e|e.borrow().task.clone())}}
#[derive(Clone)]pub struct Callback{pub completion:nt_callback::Completion,pub message:u64,pub pointer:u64,pub bytes:Vec<u8>}
#[derive(Default)]pub struct Env {
    pub task:Option<Task>,pub callbacks:Vec<Callback>,pub fail_install:bool,pub fail_publish:bool,
    pub fail_copy:bool,pub publications:usize,pub resumes:Vec<(u64,Outcome,usize,usize)>,
    pub dimensions:Vec<(u32,i32,i32)>,
    pub preservation:Vec<(u32,ipc::win32_window::WindowRect,ipc::win32_window::WindowRect,Option<[ipc::win32_window::WindowRect;2]>)>,
}
thread_local!{pub static ENV:RefCell<Env>=RefCell::new(Env::default());}
pub static SERIAL:Mutex<()>=Mutex::new(());
pub fn publish()->Result<(),()>{ENV.with(|e|{let mut e=e.borrow_mut();e.publications+=1;if e.fail_publish{Err(())}else{Ok(())}})}
pub fn copy_from_user(bytes:&mut[u8],pointer:u64)->Result<(),()>{ENV.with(|e|{
    let e=e.borrow();if e.fail_copy{return Err(());}
    let source=&e.callbacks.iter().find(|c|c.pointer==pointer).ok_or(())?.bytes;
    bytes.copy_from_slice(source.get(..bytes.len()).ok_or(())?);Ok(())
})}
pub mod nt_rtl {
    pub fn begin_wndproc_payload_callback(_:u64,message:u64,_:u64,_:u64,bytes:&[u8],_:&[(usize,usize)],completion:super::nt_callback::Completion)->Result<u64,u64>{
        super::ENV.with(|e|{let mut e=e.borrow_mut();if e.fail_install{return Err(0);}
            let pointer=e.callbacks.len() as u64+1;e.callbacks.push(super::Callback{completion,message,pointer,bytes:bytes.to_vec()});Ok(pointer)})
    }
}
#[path="gdi.rs"]pub mod nt_gdi;
pub fn resume(token:u64,outcome:Outcome)->u64 {
    assert!(crate::nt_window::GUI.0.try_lock().is_ok(),"caller resumed under GUI lock");
    ENV.with(|e|{let mut e=e.borrow_mut();let tid=e.task.as_ref().unwrap().tid;let publications=e.publications;e.resumes.push((token,outcome,tid,publications));});token
}
