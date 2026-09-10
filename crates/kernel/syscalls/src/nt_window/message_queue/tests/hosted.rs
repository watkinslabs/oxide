use std::sync::{Arc,Weak,Mutex};
use std::sync::atomic::{AtomicU64,AtomicUsize,AtomicBool,Ordering};
use ipc::win32_window::{WindowManager,queue_status::*};
#[allow(dead_code)] // Send callback fields are exercised by nt_window_send_boundary.
#[path="../../send/work.rs"]mod sent;
#[path="boundary.rs"]mod boundary;
#[path="../../../nt_wine_window/queue_raw/wait.rs"]mod wait_policy;
mod nt_wine_window {pub(crate) mod queue_raw {pub(crate) use crate::wait_policy as wait;}}
struct Group;
struct Task {tid:u64,thread_group:Arc<Group>}
impl Task {fn is_nt_personality(&self)->bool{true}}
struct GuiEntry {group:Weak<Group>,state:WindowManager,sent:sent::Queue,wait:Arc<live::WaitList>}
struct Lock<T>(Mutex<T>);
impl<T> Lock<T>{fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
static GUI:Lock<Vec<GuiEntry>>=Lock(Mutex::new(Vec::new()));
static CURRENT:Mutex<Option<Arc<Task>>>=Mutex::new(None);
static SERIAL:Mutex<()>=Mutex::new(());
static NOW:AtomicU64=AtomicU64::new(0);
static PARKS:AtomicUsize=AtomicUsize::new(0);
static INJECT:AtomicBool=AtomicBool::new(false);
static EXPECT_WAKE:AtomicBool=AtomicBool::new(false);
static OBJECT_READY:AtomicBool=AtomicBool::new(false);
static ERROR:AtomicU64=AtomicU64::new(0);
fn monotonic_ns()->u64{NOW.load(Ordering::SeqCst)}
mod live {
    use super::*;
    pub(crate) struct WaitList;
    pub(crate) fn current()->Option<Arc<Task>>{CURRENT.lock().unwrap().clone()}
    pub(crate) unsafe fn wait_event_interruptible_until(_: &WaitList,deadline:u64,_clock:fn()->u64,ready:impl Fn()->bool)->task::WaitOutcome{
        assert_eq!(PARKS.fetch_add(1,Ordering::SeqCst),0,"message wait woke repeatedly without accepted work");
        assert!(!ready(),"unexpected work before injection");
        if INJECT.swap(false,Ordering::SeqCst){enqueue(&mut GUI.lock()[0].sent,2,7);}
        let wake=ready();assert_eq!(wake,EXPECT_WAKE.load(Ordering::SeqCst),"park predicate ignored requested classes");
        if wake{task::WaitOutcome::Ready}else{assert_ne!(deadline,0);NOW.store(deadline,Ordering::SeqCst);task::WaitOutcome::TimedOut}
    }
}
mod task {#[derive(PartialEq,Eq)]pub(crate) enum WaitOutcome{Ready,TimedOut}}
mod nt_object {
    pub(crate) fn merge_wait_deadline(a:u64,b:Option<u64>)->u64{match (a,b){(0,Some(b))=>b,(a,Some(b))=>a.min(b),(a,None)=>a}}
}
mod nt_dispatch {
    pub(crate) struct Object;
    impl Object{pub(crate) fn is_signaled_at(&self,_tid:u64,_now:u64)->bool{crate::OBJECT_READY.load(crate::Ordering::SeqCst)}}
    pub(crate) fn resolve_wait_objects(_handles:u64,count:u32)->Result<Vec<Object>,()>{Ok((0..count).map(|_|Object).collect())}
}
mod nt_rtl {pub(crate) fn set_last_win32_error(error:u64){crate::ERROR.store(error,crate::Ordering::SeqCst);}}
mod owner {
    pub(crate) fn current_tid()->Option<u64>{crate::live::current().map(|task|task.tid)}
    pub(crate) fn with_entry<R>(f:impl FnOnce(&mut crate::GuiEntry)->R)->Option<R>{crate::GUI.lock().first_mut().map(f)}
}
fn enqueue(queue:&mut sent::Queue,tid:u64,hwnd:u64)->u64{
    queue.admit(1,tid,sent::Message{hwnd,message:0x400,wparam:0,lparam:0}).unwrap().0
}
fn setup(){
    let group=Arc::new(Group);*CURRENT.lock().unwrap()=Some(Arc::new(Task{tid:2,thread_group:group.clone()}));
    *GUI.lock()=vec![GuiEntry{group:Arc::downgrade(&group),state:WindowManager::new(),sent:sent::Queue::new(),wait:Arc::new(live::WaitList)}];
    NOW.store(0,Ordering::SeqCst);PARKS.store(0,Ordering::SeqCst);INJECT.store(false,Ordering::SeqCst);
    EXPECT_WAKE.store(false,Ordering::SeqCst);OBJECT_READY.store(false,Ordering::SeqCst);ERROR.store(0,Ordering::SeqCst);
}
#[test]
fn public_status_merges_posted_and_sent_and_clears_only_changed(){
    let _serial=SERIAL.lock().unwrap();setup();
    {let mut entries=GUI.lock();entries[0].state.post_quit(2,0);entries[0].state.post_to_thread(2,ipc::win32_window::WinMessage{hwnd:None,message:0x400,wparam:0,lparam:0}).unwrap();enqueue(&mut entries[0].sent,2,7);}
    let mask=QS_POSTMESSAGE|QS_SENDMESSAGE;
    assert_eq!(boundary::status::queue_status_for_current(mask),Some(0x00480048));
    assert_eq!(boundary::status::queue_status_for_current(mask),Some(0x00480000));
    enqueue(&mut GUI.lock()[0].sent,2,8);
    assert_eq!(boundary::status::queue_status_for_current(QS_SENDMESSAGE),Some(0x00400040));
}
#[test]
fn invalid_and_excluded_status_masks_do_not_consume_sent_changes(){
    let _serial=SERIAL.lock().unwrap();setup();enqueue(&mut GUI.lock()[0].sent,2,7);
    assert_eq!(boundary::status::queue_status_for_current(0x2000|QS_SENDMESSAGE),None);
    assert_eq!(boundary::status::queue_status_for_current(QS_KEY),Some(0));
    assert_eq!(boundary::status::queue_status_for_current(QS_SENDMESSAGE),Some(0x00400040));
}
#[test]
fn initially_queued_send_respects_mask_and_occupies_slot_after_objects(){
    let _serial=SERIAL.lock().unwrap();setup();enqueue(&mut GUI.lock()[0].sent,2,7);
    assert_eq!(boundary::wait_live::msg_wait(1,0,0,QS_KEY),wait_policy::WAIT_TIMEOUT);
    assert_eq!(boundary::wait_live::msg_wait(1,0,0,QS_SENDMESSAGE),1);
    assert_eq!(PARKS.load(Ordering::SeqCst),0);
    OBJECT_READY.store(true,Ordering::SeqCst);
    assert_eq!(boundary::wait_live::msg_wait(1,0,0,QS_SENDMESSAGE),0);
}
#[test]
fn send_arriving_during_park_does_not_wake_excluded_class(){
    let _serial=SERIAL.lock().unwrap();setup();INJECT.store(true,Ordering::SeqCst);
    assert_eq!(boundary::wait_live::msg_wait(0,0,1,QS_KEY),wait_policy::WAIT_TIMEOUT);
    assert_eq!(PARKS.load(Ordering::SeqCst),1);
    assert_eq!(boundary::status::queue_status_for_current(QS_SENDMESSAGE),Some(0x00400040));
}
#[test]
fn send_arriving_during_park_wakes_requested_class(){
    let _serial=SERIAL.lock().unwrap();setup();INJECT.store(true,Ordering::SeqCst);EXPECT_WAKE.store(true,Ordering::SeqCst);
    assert_eq!(boundary::wait_live::msg_wait(1,0,1,QS_SENDMESSAGE),1);
    assert_eq!(PARKS.load(Ordering::SeqCst),1);
}

#[test]
fn public_status_reports_quit_arrival_and_reposting_after_acknowledgement(){
    let _serial=SERIAL.lock().unwrap();setup();GUI.lock()[0].state.post_quit(2,1);
    assert_eq!(boundary::status::queue_status_for_current(QS_POSTED),Some(0x01080108));
    assert_eq!(boundary::status::queue_status_for_current(QS_POSTED),Some(0x01080000));
    GUI.lock()[0].state.post_quit(2,2);
    assert_eq!(boundary::status::queue_status_for_current(QS_POSTED),Some(0x01080108));
}
