// Production send boundary harness body shared by rustc and Cargo wrappers.
use std::sync::{Arc,Weak,Mutex,MutexGuard};
use std::cell::Cell;
pub mod thread_group {pub struct ThreadGroup;}
pub struct Task {pub tid:u64,pub thread_group:Arc<thread_group::ThreadGroup>}
impl Task {pub fn is_nt_personality(&self)->bool{true}}
pub mod nt_callback {#[derive(Clone,Copy)]pub struct Completion{pub kind:u64,pub argument:u64}}
thread_local!{static CURRENT:Cell<Option<&'static Task>>=const{Cell::new(None)};static CALLBACK:Cell<Option<nt_callback::Completion>>=const{Cell::new(None)};}
thread_local!{static INSTALL_FAIL:Cell<bool>=const{Cell::new(false)};static GUI_DEPTH:Cell<usize>=const{Cell::new(0)};}
thread_local!{static DEADLINE:Cell<Option<std::time::Instant>>=const{Cell::new(None)};}
pub mod live {
    use super::*;
    pub struct WaitList;
    impl WaitList {pub fn wake_all(&self){}}
    pub fn current()->Option<&'static Task>{CURRENT.with(Cell::get)}
    pub unsafe fn wait_event_uninterruptible(_: &WaitList,ready:impl Fn()->bool){
        assert!(std::time::Instant::now()<DEADLINE.with(|d|d.get().unwrap()),"hosted GUI wait made no progress");
        let end=std::time::Instant::now()+std::time::Duration::from_secs(5);
        while !ready(){assert!(std::time::Instant::now()<end,"hosted sender failed to wake");std::thread::yield_now();}
    }
}
pub mod win32_window {
    #[derive(Clone,Copy,PartialEq,Eq)]pub struct WindowId(u32);
    impl WindowId {pub fn from_raw(raw:u32)->Option<Self>{(raw!=0).then_some(Self(raw))}}
    #[derive(Clone,Copy)]pub struct Record {pub owner_tid:u64,pub wndproc:u64}
    pub struct Manager(pub Vec<(WindowId,Record)>);
    impl Manager {pub fn get(&self,id:WindowId)->Option<Record>{self.0.iter().find(|r|r.0==id).map(|r|r.1)}}
}
static CALLS:Mutex<Vec<(u64,u64,u64,u64,u64)>>=Mutex::new(Vec::new());
mod nt_rtl {
    pub fn begin_wndproc_callback_with_completion(hwnd:u64,msg:u64,wp:u64,lp:u64,_proc:u64,c:crate::nt_callback::Completion)->u64{
        if crate::INSTALL_FAIL.with(|f|f.get()){return 0xc000000d;}
        let tid=crate::live::current().unwrap().tid;
        crate::CALLS.lock().unwrap().push((tid,hwnd,msg,wp,lp));
        crate::CALLBACK.with(|saved|{assert!(saved.get().is_none());saved.set(Some(c));});0x103
    }
}
struct Lock<T>(Mutex<T>);
struct Guard<'a,T>(MutexGuard<'a,T>);
impl<T> std::ops::Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.0}}
impl<T> std::ops::DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){GUI_DEPTH.with(|d|d.set(d.get()-1));}}
impl<T> Lock<T>{fn lock(&self)->Guard<'_,T>{let guard=self.0.lock().unwrap();GUI_DEPTH.with(|d|d.set(d.get()+1));Guard(guard)}}
mod nt_window {
    use super::*;
    pub const STATUS_PENDING:u64=0x103;
    pub struct GuiEntry{pub group:Weak<thread_group::ThreadGroup>,pub state:win32_window::Manager,pub sent:send::Queue,pub wait:Arc<live::WaitList>}
    pub static GUI:Lock<Vec<GuiEntry>>=Lock(Mutex::new(Vec::new()));
    pub fn resume_position_message_current()->u64{0x777}
}
use nt_window::{GUI,STATUS_PENDING,resume_position_message_current};
#[path="../../send.rs"]mod send;
mod paint_callbacks {
    pub fn reap_retired_current(){super::GUI_DEPTH.with(|d|assert_eq!(d.get(),0));}
}
mod position {
    use std::{cell::{Cell,RefCell},sync::Arc};
    thread_local!{static READY:Cell<bool>=const{Cell::new(false)};static SAVED:RefCell<Option<Arc<crate::send::Reply>>>=const{RefCell::new(None)};}
    // Instrumented position installation boundary; production send wait supplies
    // the same owned reply retained by pending-position callbacks.
    pub fn pump_for_reply(reply:Arc<crate::send::Reply>)->Option<u64>{
        if !READY.with(|r|r.replace(false)){return None;}
        SAVED.with(|s|{assert!(s.borrow().is_none());*s.borrow_mut()=Some(reply);});Some(0x103)
    }
    pub fn has_remote_for_current()->bool{READY.with(|r|r.get())}
    pub fn ready(){READY.with(|r|r.set(true));}
    pub fn take()->Arc<crate::send::Reply>{SAVED.with(|s|s.borrow_mut().take().unwrap())}
}
static SERIAL:Mutex<()>=Mutex::new(());
fn setup()->Arc<thread_group::ThreadGroup>{
    let group=Arc::new(thread_group::ThreadGroup);
    *GUI.lock()=vec![nt_window::GuiEntry{group:Arc::downgrade(&group),sent:send::Queue::new(),wait:Arc::new(live::WaitList),
        state:win32_window::Manager(vec![(win32_window::WindowId::from_raw(7).unwrap(),win32_window::Record{owner_tid:2,wndproc:0x1234}),
            (win32_window::WindowId::from_raw(8).unwrap(),win32_window::Record{owner_tid:1,wndproc:0x1234})])}];
    CALLS.lock().unwrap().clear();group
}
fn current(group:&Arc<thread_group::ThreadGroup>,tid:u64){
    CURRENT.with(|c|c.set(Some(Box::leak(Box::new(Task{tid,thread_group:group.clone()})))));
    CALLBACK.with(|c|c.set(None));
    INSTALL_FAIL.with(|f|f.set(false));
    DEADLINE.with(|d|d.set(Some(std::time::Instant::now()+std::time::Duration::from_secs(5))));
}
fn until(ready:impl Fn()->bool){
    let end=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while !ready(){assert!(std::time::Instant::now()<end,"hosted receiver never became ready");std::thread::yield_now();}
}
#[test]
fn actual_cross_thread_execution_returns_full_result_and_resumes_retrieval(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_for_current(7,0x30,u64::MAX,0x4321)});
    until(send::has_current);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    let callback=CALLBACK.with(|c|c.take().unwrap());assert!(send::handles_callback(callback.kind));
    assert_eq!(send::complete_callback(callback,0x103),0x777);
    assert_eq!(sender.join().unwrap(),0x103);
    assert_eq!(*CALLS.lock().unwrap(),vec![(2,7,0x30,u64::MAX,0x4321)]);
}
#[test]
fn actual_same_thread_callback_returns_lresult_not_boolean(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let context=send::context_current(7).unwrap();assert_eq!((context.tid,context.wndproc),(2,0x1234));
    assert_eq!(send::send_for_current(7,0x30,0,0),0x103);
    let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,u64::MAX),u64::MAX);
}
#[test]
fn actual_revocation_wakes_sender_without_installing_callback(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_for_current(7,0x30,0,0)});
    until(send::has_current);GUI.lock()[0].state.0.clear();send::cancel_thread(&group,2);
    assert_eq!(sender.join().unwrap(),0);assert!(CALLS.lock().unwrap().is_empty());assert!(!send::has_current());
}
#[test]
fn actual_destroy_during_callback_preserves_receiver_continuation(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_for_current(7,0x30,0,0)});
    until(send::has_current);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    GUI.lock()[0].state.0.clear();send::cancel_window(&group,7);assert!(!sender.is_finished());
    let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,99),0x777);
    assert_eq!(sender.join().unwrap(),0);
}
#[test]
fn actual_send_cycle_services_incoming_callback_and_resumes_original_send(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let sender_group=group.clone();let sender=std::thread::spawn(move||{
        current(&sender_group,1);assert_eq!(send::send_for_current(7,0x30,0,0),0x103);
        let nested=CALLBACK.with(|c|c.take().unwrap());send::complete_callback(nested,55)
    });
    until(send::has_current);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    let outer=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::send_for_current(8,0x31,0,0),55);
    assert_eq!(send::complete_callback(outer,56),0x777);assert_eq!(sender.join().unwrap(),56);
    assert_eq!(*CALLS.lock().unwrap(),vec![(2,7,0x30,0,0),(1,8,0x31,0,0)]);
}
#[test]
fn shared_wait_returns_position_boolean_without_reinterpreting_it(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let reply=Arc::new(send::Reply::new());reply.complete(1);assert_eq!(send::wait_reply(reply),1);
}
#[path="resumable_hosted.rs"]mod resumable_hosted;
