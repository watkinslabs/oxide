//! Actual dispatcher acknowledgement with copy and sent-callback boundaries instrumented.
use super::*;
use ipc::win32_window::{WinMessage,queue_status::*};
use std::sync::atomic::{AtomicBool,Ordering};
static COPY:Mutex<Option<WinMessage>>=Mutex::new(None);
static SENT_PENDING:AtomicBool=AtomicBool::new(false);
fn post(bits:u32)->WinMessage{
    let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;let hwnd=state.siblings_top_first(None)[0];
    let msg=WinMessage{hwnd:Some(hwnd),message:0x400,wparam:0,lparam:0};state.post_to_window_with_bits(hwnd,msg,bits).unwrap();msg
}
pub(super) fn copy(message:WinMessage)->bool{
    let Some(expected)=COPY.lock().unwrap().take() else{return false;};assert_eq!(message,expected);true
}
pub(super) fn pump()->Option<u64>{
    if !SENT_PENDING.swap(false,Ordering::SeqCst){return None;}
    assert_eq!(status(QS_POSTED),0x01080108,"sent callback must run before retrieval acknowledges arrivals");Some(0x103)
}
fn status(mask:u32)->u32{nt_window::GUI.lock()[0].state.queue_status(41,mask).unwrap()}
fn empty_scan(flags:u32)->NtCall{let mut request=call(nt::NtService::PeekMessage);request.args.a2=0x401;request.args.a3=0x401;request.args.a4=flags as u64;request}
#[test]
fn failed_filtered_scan_acknowledges_posted_changes_but_preserves_allposted(){
    let _serial=SERIAL.lock().unwrap();setup();post(QS_POSTED);
    assert_eq!(nt_window::production::dispatch(empty_scan(0)),Some(nt_window::STATUS_NO_MORE_ENTRIES));
    assert_eq!(status(QS_POSTED),0x01080100);
}
#[test]
fn full_nonremoving_peek_acknowledges_arrival_and_retains_pending_message(){
    let _serial=SERIAL.lock().unwrap();setup();let message=post(QS_POSTED);*COPY.lock().unwrap()=Some(message);
    assert_eq!(nt_window::production::dispatch(call(nt::NtService::PeekMessage)),Some(0));
    assert!(COPY.lock().unwrap().is_none());assert_eq!(status(QS_POSTED),0x01080000);
}
#[test]
fn selected_input_acknowledgement_preserves_excluded_posted_changes(){
    let _serial=SERIAL.lock().unwrap();setup();post(QS_POSTED|QS_KEY);
    assert_eq!(nt_window::production::dispatch(empty_scan(QS_KEY<<16)),Some(nt_window::STATUS_NO_MORE_ENTRIES));
    assert_eq!(status(QS_POSTED|QS_KEY),0x01090108);
}
#[test]
fn invalid_window_filter_preserves_arrivals(){
    let _serial=SERIAL.lock().unwrap();setup();post(QS_POSTED);let mut request=empty_scan(0);request.args.a1=0x12345678;
    assert_eq!(nt_window::production::dispatch(request),Some(0xc0000008));assert_eq!(status(QS_POSTED),0x01080108);
}
#[test]
fn pending_sent_callback_runs_before_acknowledgement(){
    let _serial=SERIAL.lock().unwrap();setup();post(QS_POSTED);SENT_PENDING.store(true,Ordering::SeqCst);
    assert_eq!(nt_window::production::dispatch(empty_scan(0)),Some(0x103));
}
#[test]
fn actual_peek_acknowledges_pending_paint_without_consuming_region(){
    let _serial=SERIAL.lock().unwrap();setup();
    let hwnd={let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
        let hwnd=state.siblings_top_first(None)[0];state.invalidate(hwnd,None).unwrap();hwnd};
    let message=WinMessage{hwnd:Some(hwnd),message:ipc::win32_window::WM_PAINT,wparam:0,lparam:0};
    for _ in 0..2{
        *COPY.lock().unwrap()=Some(message);
        assert_eq!(nt_window::production::dispatch(call(nt::NtService::PeekMessage)),Some(0));
        assert!(COPY.lock().unwrap().is_none());assert_eq!(status(QS_PAINT),0x00200000);
        assert!(nt_window::GUI.lock()[0].state.pending_paint_message(41).is_some());
    }
}
