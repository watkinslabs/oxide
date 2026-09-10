//! Real sent inbox and callback record; owner-thread execution and posted lifetime.
use super::*;
fn hook(owner:u64)->win32_hook::Hook{
    win32_hook::Hook{handle:51,id:win32_hook::WH_WINEVENT,process:None,thread:None,owner,
        event_min:1,event_max:0xffff,flags:win32_hook::WINEVENT_OUTOFCONTEXT,proc_address:0x3456,unicode:true,module:vec![]}
}
fn event(hwnd:u64)->HookNotification{HookNotification{event:0x800a,hwnd,object_id:-4,child_id:-1,thread:1,time:123}}
fn finish_event()->u64{let c=CALLBACK.with(|saved|saved.take().unwrap());send::complete_callback(c,u64::MAX)}
#[test]
fn event_posts_without_entering_caller_and_runs_in_owner_pump(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    assert!(send::post_event(hook(2),event(8)));assert_eq!(WAKES.load(std::sync::atomic::Ordering::SeqCst),1);assert!(EVENT_CALLS.lock().unwrap().is_empty());assert!(!send::has_current());
    current(&group,2);assert!(send::has_current());assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    assert_eq!(GUI.lock()[0].sent.received_send(2),None);
    let calls=EVENT_CALLS.lock().unwrap();assert_eq!(calls.len(),1);assert_eq!(calls[0].0,2);
    let bytes=&calls[0].1;assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()),1);
    assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()),123);
    assert_eq!(i32::from_le_bytes(bytes[16..20].try_into().unwrap()),-4);
    assert_eq!(i32::from_le_bytes(bytes[20..24].try_into().unwrap()),-1);drop(calls);
    assert_eq!(finish_event(),0x777);assert!(!send::has_current());
}
#[test]
fn event_survives_announcer_exit_and_foreign_window_destruction(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    assert!(send::post_event(hook(2),event(8)));send::cancel_thread(&group,1);send::cancel_window(&group,8);
    GUI.lock()[0].state.0.retain(|(_,record)|record.owner_tid!=1);
    current(&group,2);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));assert_eq!(finish_event(),0x777);
}
#[test]
fn owner_window_destruction_removes_its_queued_events(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    assert!(send::post_event(hook(2),event(7)));send::cancel_window(&group,7);
    current(&group,2);assert!(!send::has_current());assert_eq!(send::pump_current(),None);
}
#[test]
fn event_admission_requires_owner_queue_and_rejects_retiring_owner(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    assert!(!send::post_event(hook(9),event(7)));
    GUI.lock()[0].sent.mark_exiting(2);assert!(!send::post_event(hook(2),event(7)));
}
#[test]
fn same_thread_event_waits_for_retrieval_and_needs_no_window(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    GUI.lock()[0].state.0.clear();
    assert!(send::post_event(hook(1),event(0xdead)));assert!(EVENT_CALLS.lock().unwrap().is_empty());
    assert_eq!(send::pump_current(),Some(send::Outcome::Pending));assert_eq!(finish_event(),0x777);
}
#[test]
fn cross_process_event_uses_the_owners_queue(){
    let _serial=SERIAL.lock().unwrap();let group=setup();let other=Arc::new(thread_group::ThreadGroup);
    GUI.lock().push(nt_window::GuiEntry{group:Arc::downgrade(&other),sent:send::Queue::new(),wait:Arc::new(live::WaitList),state:win32_window::Manager(vec![],vec![3])});
    current(&group,1);assert!(send::post_event(hook(3),event(8)));assert!(!send::has_current());
    current(&other,3);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));assert_eq!(finish_event(),0x777);
    assert_eq!(EVENT_CALLS.lock().unwrap()[0].0,3);
}
#[test]
fn sent_message_and_event_preserve_owner_inbox_order(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    assert!(send::post_event(hook(2),event(8)));
    let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_for_current(7,0x30,7,8)});
    current(&group,2);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));assert_eq!(finish_event(),0x777);
    until(send::has_current);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    assert_eq!(finish_event(),0x777);assert_eq!(sender.join().unwrap(),u64::MAX);
    assert_eq!(EVENT_CALLS.lock().unwrap().len(),1);assert_eq!(CALLS.lock().unwrap().len(),1);
}
#[test]
fn queued_event_interrupts_send_wait_and_preserves_original_reply(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert!(send::post_event(hook(2),event(8)));
    let reply=Arc::new(send::Reply::new());assert_eq!(send::wait_reply(reply.clone()),STATUS_PENDING);
    reply.complete(0x1122334455667788);
    assert_eq!(finish_event(),0x1122334455667788);assert!(!send::has_current());
}
