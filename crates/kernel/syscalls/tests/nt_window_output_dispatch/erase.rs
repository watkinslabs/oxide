//! Unchanged erase owner joins canonical storage and actual output submission.
use super::*;
use crate::nt_gdi::GDI;
use ipc::win32_gdi::{PaintBacking,Rect};
use ipc::win32_window::{PaintRegion,WindowRect};
const STATUS_SUCCESS:u64=0;
const STATUS_INVALID_HANDLE:u64=0xc0000008;
const STATUS_INVALID_PARAMETER:u64=0xc000000d;
const REJECT_PENDING_CONTROL:bool=false;
#[path="../../src/nt_gdi/paint_frame.rs"]
mod paint_frame;
#[path="../../src/nt_gdi/erase_frame.rs"]
mod production;
mod output{
    pub(crate) use crate::output::reserve_captured;
    pub(crate) fn submit_prepared_for_current(frame:Result<crate::output::PreparedFrame,u64>)->u64{
        let status=crate::nt_gdi::output::kernel::submit_prepared_for_current(frame);
        if super::REJECT_PENDING_CONTROL&&status==0x103{super::STATUS_INVALID_PARAMETER}else{status}
    }
}
fn surface()->(u32,u32,PaintRegion,PaintBacking){
    let mut entries=GDI.lock();let state=&mut entries[0].state;
    let hwnd=state.pending_outputs().unwrap()[0].hwnd;
    let dc=state.create_dc(2,2).unwrap();state.fill_rect(dc,Rect{left:0,top:0,right:2,bottom:2},0x123456).unwrap();
    (hwnd,dc,PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap(),
        PaintBacking{width:2,height:2,client:Rect{left:0,top:0,right:2,bottom:2}})
}
fn accept(frame:&syscall::nt_compositor::Record)->u64{
    assert_eq!(&frame.payload[16..20],&0xff123456u32.to_le_bytes());STATUS_SUCCESS
}
#[test]
fn actual_erase_success_and_failed_transport_both_finish_retention_without_pending_escape(){
    let _serial=SERIAL.lock().unwrap();
    for failed in [false,true]{
        setup();let(hwnd,dc,region,layout)=surface();
        *nt_gdi::TRANSPORT.lock().unwrap()=Some(if failed{|_|STATUS_INVALID_PARAMETER}else{accept});
        assert_eq!(production::retain_erase_for_current(hwnd,dc,&region,layout),Ok(()));
        assert_eq!(nt_gdi::clean(),!failed);assert_eq!(*EVENTS.lock().unwrap(),["frame"]);
        let state=GDI.lock();assert_eq!(state[0].state.pixels(dc).unwrap(),&[0x123456;4]);drop(state);
        if failed{*nt_gdi::TRANSPORT.lock().unwrap()=Some(accept);nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());}
    }
}
#[test]
fn actual_erase_busy_owner_returns_ok_without_submission_and_remains_flushable(){
    let _serial=SERIAL.lock().unwrap();setup();let(hwnd,dc,region,layout)=surface();
    let token={let mut entries=GDI.lock();let state=&mut entries[0].state;let token=state.pending_outputs().unwrap()[0];assert!(state.reserve_output(token));token};
    assert_eq!(production::retain_erase_for_current(hwnd,dc,&region,layout),Ok(()));
    assert!(EVENTS.lock().unwrap().is_empty());assert!(!nt_gdi::clean());
    assert!(!GDI.lock()[0].state.finish_output(token,true),"older ACK cannot consume retained erase pixels");
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(accept);nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
}
#[test]
fn actual_erase_geometry_and_capture_errors_do_not_publish_or_mutate_backing(){
    let _serial=SERIAL.lock().unwrap();setup();let(hwnd,dc,region,layout)=surface();
    let before=GDI.lock()[0].state.pending_outputs().unwrap();
    let mut wrong=layout;wrong.width+=1;
    assert_eq!(production::retain_erase_for_current(hwnd,dc,&region,wrong),Err(STATUS_INVALID_HANDLE));
    assert_eq!(production::retain_erase_for_current(hwnd,u32::MAX,&region,layout),Err(STATUS_INVALID_PARAMETER));
    assert_eq!(GDI.lock()[0].state.pending_outputs().unwrap(),before);assert!(EVENTS.lock().unwrap().is_empty());
    sched::CURRENT.with(|c|*c.borrow_mut()=None);
    assert_eq!(production::retain_erase_for_current(hwnd,dc,&region,layout),Err(STATUS_INVALID_HANDLE));
}
#[test]
fn actual_erase_preserves_terminal_transport_error_if_backing_was_destroyed(){
    let _serial=SERIAL.lock().unwrap();setup();let(hwnd,dc,region,layout)=surface();
    const DISCONNECTED:u64=0xc00000b0;
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(|frame|{GDI.lock()[0].state.destroy_window_dc(frame.header.hwnd as u32).unwrap();DISCONNECTED});
    assert_eq!(production::retain_erase_for_current(hwnd,dc,&region,layout),Err(DISCONNECTED));
}
