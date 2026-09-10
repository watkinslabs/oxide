//! Sent-class status remains set until all queued work for that target drains.
use super::*;
use ipc::win32_window::queue_status::{QS_SENDMESSAGE,QS_KEY};
fn message(hwnd:u64)->Message{Message{hwnd,message:0x400,wparam:0,lparam:0}}
#[test]
fn status_is_per_target_and_queries_clear_only_requested_changes(){
    let mut queue=Queue::new();queue.admit(1,2,message(7)).unwrap();queue.admit(1,3,message(8)).unwrap();
    assert_eq!(queue.queue_status(2,QS_KEY),0);
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400000);
    assert_eq!(queue.queue_status(3,QS_SENDMESSAGE),0x00400040);
    queue.admit(1,2,message(9)).unwrap();assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);
}
#[test]
fn starting_last_work_clears_wake_and_unreported_changes_before_callback_finishes(){
    let mut queue=Queue::new();queue.admit(1,2,message(7)).unwrap();
    let active=queue.start(2,Resume::Retrieval,None).unwrap();
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
    assert!(active.reply.outcome().is_none());assert_eq!(queue.work.len(),1);
    queue.finish(2,active.token,Some(1)).unwrap();assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
}
#[test]
fn consuming_new_arrival_preserves_changed_while_older_work_remains(){
    let mut queue=Queue::new();queue.admit(1,2,message(7)).unwrap();
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);
    let (new,_)=queue.admit(1,2,message(8)).unwrap();queue.start(2,Resume::Retrieval,Some(new)).unwrap();
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);
    queue.start(2,Resume::Retrieval,None).unwrap();assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
}
#[test]
fn cancelling_partial_queue_preserves_changed_and_last_cancellation_clears_it(){
    let mut queue=Queue::new();queue.admit(1,2,message(7)).unwrap();queue.admit(3,2,message(8)).unwrap();
    queue.cancel_window(7);assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);
    queue.admit(3,2,message(9)).unwrap();queue.cancel_thread(3);assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
    queue.admit(1,2,message(7)).unwrap();queue.cancel_thread(2);assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
}
#[test]
fn rejected_send_does_not_mark_existing_queue_changed(){
    let mut queue=Queue::new();for _ in 0..LIMIT{queue.admit(1,2,message(7)).unwrap();}
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);assert!(queue.admit(1,2,message(7)).is_none());
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400000);
}

#[test]
fn status_queries_and_drain_preserve_retiring_thread_admission_guard(){
    let mut queue=Queue::new();queue.admit(1,2,message(7)).unwrap();queue.mark_exiting(2);
    assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0x00400040);assert!(queue.admit(1,2,message(8)).is_none());
    queue.start(2,Resume::Retrieval,None).unwrap();assert_eq!(queue.queue_status(2,QS_SENDMESSAGE),0);
    assert!(queue.admit(1,2,message(8)).is_none());
    queue.cancel_thread(2);assert!(queue.admit(1,2,message(8)).is_some());
}
