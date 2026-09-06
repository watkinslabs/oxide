use std::{cell::RefCell,sync::{Arc,Mutex}};
use syscall::nt_compositor::caret::Snapshot;
pub mod thread_group {pub struct ThreadGroup;}
#[derive(Clone)]pub struct Task{pub tid:usize,pub thread_group:Arc<thread_group::ThreadGroup>,pub nt:bool}
impl Task{pub fn is_nt_personality(&self)->bool{self.nt}}
pub mod live {pub fn current()->Option<super::Task>{super::ENV.with(|e|e.borrow().task.clone())}}
#[derive(Default)]pub struct Env{pub task:Option<Task>,pub snapshots:Vec<(u64,Snapshot)>,pub fail:bool}
thread_local!{pub static ENV:RefCell<Env>=RefCell::new(Env::default());}
pub static SERIAL:Mutex<()>=Mutex::new(());
pub(crate) fn publish_current(hwnd:u64,snapshot:&Snapshot)->bool {
    assert!(crate::nt_window::GUI.0.try_lock().is_ok(),"transport called under GUI lock");
    ENV.with(|e|{let mut e=e.borrow_mut();e.snapshots.push((hwnd,snapshot.clone()));!e.fail})
}
