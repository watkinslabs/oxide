use super::*;
use nt_window::scroll::{control_proc,decode_scroll_info,encode_scroll_info};
use win32_window::{ScrollInfo,SIF_ALL,SIF_POS,WindowId};

fn initialized()->u64{
    let(_,hwnd)=setup();let id=WindowId::from_raw(hwnd as u32).unwrap();
    let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
    state.initialize_scroll_control(id).unwrap();
    state.set_scroll_control_info(id,ScrollInfo{cb_size:28,mask:SIF_ALL,min:-30,max:200,page:10,pos:-7,track_pos:90},false).unwrap();
    hwnd
}
fn call(hwnd:u64,message:u32,wparam:u64,lparam:u64)->u64{control_proc::for_current(hwnd,message,wparam,lparam).unwrap()}

#[test]
fn control_position_and_range_queries_read_the_canonical_control_state(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=initialized();
    assert_eq!(call(hwnd,0xe1,0,0),(-7i64)as u64);
    let(mut min,mut max)=(777i32,888i32);
    assert_eq!(call(hwnd,0xe3,&mut min as *mut i32 as u64,&mut max as *mut i32 as u64),1);
    assert_eq!((min,max),(-30,200));
    assert_eq!(call(hwnd,0xe3,0,0),1);
    assert_eq!(call(hwnd,0xe3,&mut max as *mut i32 as u64,0),1);assert_eq!(max,-30);
    assert_eq!(call(hwnd,0xe3,&mut max as *mut i32 as u64,&mut max as *mut i32 as u64),1);assert_eq!(max,200);
    assert!(RASTER.with(|r|r.borrow().is_empty()));assert!(SEND_CALLS.with(|s|s.borrow().is_empty()));
}

#[test]
fn control_scrollinfo_preserves_unrequested_fields_and_short_record_tail(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=initialized();
    let input=ScrollInfo{cb_size:24,mask:SIF_POS,min:111,max:222,page:333,pos:444,track_pos:555};
    let mut bytes=encode_scroll_info(input);
    assert_eq!(call(hwnd,0xea,0,bytes.as_mut_ptr()as u64),1);
    assert_eq!(decode_scroll_info(bytes),ScrollInfo{pos:-7,..input});
    bytes=encode_scroll_info(ScrollInfo{mask:win32_window::SIF_TRACKPOS,..input});let before=bytes;
    assert_eq!(call(hwnd,0xea,0,bytes.as_mut_ptr()as u64),1);assert_eq!(bytes,before);
    bytes=encode_scroll_info(ScrollInfo{cb_size:28,mask:SIF_ALL,..input});
    assert_eq!(call(hwnd,0xea,0,bytes.as_mut_ptr()as u64),1);
    assert_eq!(decode_scroll_info(bytes),ScrollInfo{cb_size:28,mask:SIF_ALL,min:-30,max:200,page:10,pos:-7,track_pos:-7});
}

#[test]
fn control_scrollinfo_invalid_or_empty_masks_do_not_publish_outputs(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=initialized();
    for(size,mask)in[(20,SIF_ALL),(28,0x8000_0000),(28,0),(28,win32_window::SIF_RETURNPREV)]{
        let mut bytes=encode_scroll_info(ScrollInfo{cb_size:size,mask,min:111,max:222,page:333,pos:444,track_pos:555});let before=bytes;
        assert_eq!(call(hwnd,0xea,0,bytes.as_mut_ptr()as u64),0);assert_eq!(bytes,before);
    }
    assert_eq!(call(hwnd,0xea,0,0),0);
}

#[test]
fn uninitialized_control_state_does_not_fabricate_a_range(){
    let _serial=TEST_LOCK.lock().unwrap();let(_,hwnd)=setup();let mut min=777i32;
    assert_eq!(call(hwnd,0xe1,0,0),0);
    assert_eq!(call(hwnd,0xe3,&mut min as *mut i32 as u64,0),0);assert_eq!(min,777);
}
