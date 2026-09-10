//! Numeric filter normalization and selected changed-bit acknowledgement.
use super::*;
use crate::win32_window::{MessageFilter,WinMessage};
#[test]
fn default_classes_clear_arrivals_independently_of_low_peek_flags(){
    let expected=QS_POSTED|QS_HOTKEY|QS_TIMER|QS_INPUT|QS_PAINT;
    for flags in [0,1,2,3]{assert_eq!(retrieval_clear_bits(flags,0,0),expected);assert_eq!(retrieval_clear_bits(flags,0,u32::MAX),expected);}
}
#[test]
fn restricted_message_range_preserves_all_posted_changes(){
    let all=retrieval_clear_bits(0,0,0);
    for (first,last) in [(1,u32::MAX),(0,0x400),(0x400,0x400)]{assert_eq!(retrieval_clear_bits(0,first,last),all&!QS_ALLPOSTMESSAGE);}
}
#[test]
fn each_selected_class_acknowledges_its_contract_mask(){
    for (selected,expected) in [(QS_POSTMESSAGE,QS_POSTED|QS_HOTKEY|QS_TIMER),(QS_KEY,QS_INPUT),
        (QS_RAWINPUT,QS_INPUT),(QS_POINTER,QS_INPUT),(QS_PAINT,QS_PAINT),(QS_TIMER,0),(QS_HOTKEY,0),
        (QS_SENDMESSAGE,0),(QS_ALLPOSTMESSAGE,0),(QS_SMRESULT,0)]{
        assert_eq!(retrieval_clear_bits(selected<<16,0,0),expected);
    }
}
#[test]
fn owner_acknowledgement_preserves_wake_bits_other_threads_and_excluded_changes(){
    let mut state=WindowManager::new();let a=state.create(1,None,0).unwrap();let b=state.create(2,None,0).unwrap();
    for hwnd in [a,b]{state.post_to_window_with_bits(hwnd,WinMessage{hwnd:Some(hwnd),message:0x400,wparam:0,lparam:0},QS_POSTED|QS_KEY).unwrap();}
    state.acknowledge_retrieval(1,QS_POSTMESSAGE<<16,MessageFilter{hwnd:Some(a),first:0,last:0});
    assert_eq!(state.queue_status(1,QS_POSTED|QS_KEY),Some(((QS_POSTED|QS_KEY)<<16)|QS_KEY));
    assert_eq!(state.queue_status(2,QS_POSTED|QS_KEY),Some(((QS_POSTED|QS_KEY)<<16)|QS_POSTED|QS_KEY));
}

#[test]
fn class_selection_preserves_origins_and_prioritizes_paint_before_generated_timer(){
    let mut state=WindowManager::new();let hwnd=state.create(1,None,0).unwrap();let filter=MessageFilter{hwnd:None,first:0,last:0};
    let timer=WinMessage{hwnd:Some(hwnd),message:0x113,wparam:1,lparam:0};
    state.post_to_window_with_bits(hwnd,timer,QS_TIMER).unwrap();
    let posted=WinMessage{wparam:2,..timer};state.post_to_window(hwnd,posted).unwrap();
    state.set_visible(hwnd,true).unwrap();state.set_rect(hwnd,crate::win32_window::WindowRect{left:0,top:0,right:10,bottom:10}).unwrap();
    state.invalidate(hwnd,None).unwrap();
    assert_eq!(state.peek_posted_with_flags(1,filter,PM_REMOVE|(QS_POSTMESSAGE<<16)),Some(posted));
    assert_eq!(state.peek_posted_with_flags(1,filter,QS_POSTMESSAGE<<16),None);
    assert_eq!(state.peek_posted_with_flags(1,filter,0).unwrap().message,crate::win32_window::WM_PAINT);
    assert_eq!(state.peek_posted_with_flags(1,filter,QS_TIMER<<16),Some(timer));
    assert_eq!(state.peek_posted_with_flags(1,filter,QS_TIMER<<16),Some(timer));
    assert!(matches!(state.take_posted_for_thread(1,filter),crate::win32_window::QueueResult::Message(message) if message.message==crate::win32_window::WM_PAINT));
}
#[test]
fn hardware_scan_obeys_class_selection_and_posted_priority(){
    let mut state=WindowManager::new();let hwnd=state.create(1,None,0).unwrap();let filter=MessageFilter{hwnd:None,first:0,last:0};
    let input=WinMessage{hwnd:Some(hwnd),message:crate::win32_window::WM_KEYDOWN,wparam:65,lparam:0};
    state.post_input_to_window(hwnd,input).unwrap();
    let posted=WinMessage{message:0x400,..input};state.post_to_window(hwnd,posted).unwrap();
    assert_eq!(state.inspect_retrieval_with_flags(1,filter,0,0).unwrap().1,posted);
    assert_eq!(state.inspect_retrieval_with_flags(1,filter,0,QS_MOUSEMOVE<<16).unwrap().1,input);
    assert!(state.inspect_retrieval_with_flags(1,filter,0,QS_PAINT<<16).is_err());
}
