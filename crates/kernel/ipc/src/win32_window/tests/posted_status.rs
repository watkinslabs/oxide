//! Posted inbox mutation, before retrieval's separate changed-mask acknowledgement.
use super::*;
use crate::win32_window::MessageFilter;
const USER:u32=0x400;
fn message(hwnd:Option<WindowId>)->super::super::WinMessage{super::super::WinMessage{hwnd,message:USER,wparam:0,lparam:0}}
fn all()->MessageFilter{MessageFilter{hwnd:None,first:0,last:u32::MAX}}
fn status(queue:&MessageQueue)->u32{queue_status_result(queue.changed_bits(),queue.wake_bits(),QS_POSTED)}
#[test]
fn quit_arrival_marks_both_posted_bits_even_when_replacing_pending_quit(){
    let mut queue=MessageQueue::default();queue.post_quit(3);assert_eq!(status(&queue),0x01080108);
    queue.clear_changed(QS_POSTED);assert_eq!(status(&queue),0x01080000);
    queue.post_quit(7);assert_eq!(status(&queue),0x01080108);
    assert_eq!(queue.quit_message(all(),true,0).unwrap().wparam,7);assert_eq!(status(&queue),0);
}
#[test]
fn last_posted_removal_clears_changes_while_other_classes_remain(){
    let mut queue=MessageQueue::default();queue.post(message(None),0).unwrap();
    queue.post_with_bits(message(None),QS_KEY,0).unwrap();queue.read_entry(0,true).unwrap();
    assert_eq!(status(&queue),0);assert_eq!(queue.changed_bits(),QS_KEY);assert_eq!(queue.wake_bits(),QS_KEY);
}
#[test]
fn partial_removal_preserves_class_changes_regardless_of_arrival_order(){
    let mut queue=MessageQueue::default();queue.post(message(None),0).unwrap();queue.clear_changed(QS_POSTED);
    queue.post(message(None),0).unwrap();queue.read_entry(1,true).unwrap();
    assert_eq!(status(&queue),0x01080108);queue.read_entry(0,true).unwrap();assert_eq!(status(&queue),0);
}
#[test]
fn pending_quit_preserves_posted_class_after_last_ordinary_message_is_removed(){
    let mut queue=MessageQueue::default();queue.post(message(None),0).unwrap();queue.post_quit(1);
    queue.read_entry(0,true).unwrap();assert_eq!(status(&queue),0x01080108);
    assert_eq!(queue.take_quit_matching(|_|true,0),Some(1));assert_eq!(status(&queue),0);
}
#[test]
fn both_quit_retrieval_paths_keep_bits_for_remaining_posts_and_clear_a_drained_class(){
    for matching in [false,true]{for posted in [false,true]{
        let mut queue=MessageQueue::default();queue.post_quit(2);if posted{queue.post(message(None),0).unwrap();}
        if matching{assert_eq!(queue.take_quit_matching(|_|true,0),Some(2));}
        else{assert_eq!(queue.quit_message(all(),true,0).unwrap().wparam,2);}
        assert_eq!(status(&queue),if posted{0x01080108}else{0});
    }}
}
#[test]
fn nonremoving_or_excluded_quit_inspection_preserves_owner_status(){
    let mut queue=MessageQueue::default();queue.post_quit(2);
    assert!(queue.quit_message(all(),false,0).is_some());assert_eq!(status(&queue),0x01080108);
    assert_eq!(queue.take_quit_matching(|_|false,0),None);assert_eq!(status(&queue),0x01080108);
}
#[test]
fn window_cleanup_clears_only_a_fully_drained_posted_class(){
    let a=WindowId::from_raw(1).unwrap();let b=WindowId::from_raw(2).unwrap();
    let mut queue=MessageQueue::default();queue.post(message(Some(a)),0).unwrap();queue.post(message(Some(b)),0).unwrap();
    queue.cleanup_window(a);assert_eq!(status(&queue),0x01080108);
    queue.cleanup_window(b);assert_eq!(status(&queue),0);
    queue.post(message(Some(a)),0).unwrap();queue.post_quit(1);queue.cleanup_window(a);assert_eq!(status(&queue),0x01080108);
}
