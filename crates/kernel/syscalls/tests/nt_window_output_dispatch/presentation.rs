//! Joined production capture, reservation and completion against canonical storage.
use super::*;
use crate::output;
use ipc::win32_gdi::{PaintBacking,Rect};
use ipc::win32_window::{PaintRegion,WindowRect};
use syscall::nt_compositor::Record;
const STATUS_INVALID_HANDLE:u64=0xc0000008;
const STATUS_INVALID_PARAMETER:u64=0xc000000d;
#[path="../../src/nt_gdi/paint_frame.rs"]
mod paint_frame;
#[path="../../src/nt_gdi/presentation.rs"]
mod production;

fn pixel(frame:&Record,index:usize)->u32{u32::from_le_bytes(frame.payload[16+index*4..20+index*4].try_into().unwrap())}
fn hwnd()->u32{nt_gdi::GDI.lock()[0].state.pending_outputs().unwrap()[0].hwnd}
fn submit(frame:output::PreparedFrame)->u64{nt_gdi::output::kernel::submit_prepared_for_current(Ok(frame))}
fn accept(_: &Record)->u64{0}
pub(super) fn capture_current()->output::PreparedFrame{
    let hwnd=hwnd();let window=nt_window::window_rect_for_current(hwnd);
    let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;let dc=state.window_dc(hwnd).unwrap();
    production::capture_window(state,hwnd,dc,window).unwrap()
}

#[test]
fn actual_full_memory_capture_retains_source_and_reserves_canonical_backing(){
    let _serial=SERIAL.lock().unwrap();setup();let hwnd=hwnd();
    let window=nt_window::window_rect_for_current(hwnd);
    let prepared={let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;
        let backing=state.window_dc(hwnd).unwrap();let memory=state.create_dc(2,2).unwrap();
        state.fill_rect(memory,Rect{left:0,top:0,right:2,bottom:2},0x123456).unwrap();
        let prepared=production::capture_window(state,hwnd,memory,window).unwrap();
        assert_eq!(prepared.token.dc,backing);assert_ne!(backing,memory);
        assert_eq!(state.pixels(memory).unwrap(),&[0x123456;4]);
        assert_eq!(state.pixels(backing).unwrap(),&[0x123456;4]);
        assert_eq!(pixel(&prepared.record,3),0xff123456);
        assert!(state.reserve_output(prepared.token),"capture must not strand a reservation");
        state.finish_output(prepared.token,false);prepared};
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(accept);
    assert_eq!(submit(prepared),0);assert!(nt_gdi::clean());
}

#[test]
fn actual_region_capture_preserves_holes_and_nonclient_pixels(){
    let _serial=SERIAL.lock().unwrap();setup();let hwnd=hwnd();
    let prepared={let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;
        let backing=state.acquire_window_dc(hwnd,5,3).unwrap();
        state.fill_rect(backing,Rect{left:0,top:0,right:5,bottom:3},0x112233).unwrap();
        let paint=state.create_dc(3,1).unwrap();state.fill_rect(paint,Rect{left:0,top:0,right:3,bottom:1},0x445566).unwrap();
        let region=PaintRegion::from_rects(&[WindowRect{left:0,top:0,right:1,bottom:1},WindowRect{left:2,top:0,right:3,bottom:1}]).unwrap();
        let layout=PaintBacking{width:5,height:3,client:Rect{left:1,top:1,right:4,bottom:2}};
        let prepared=production::capture_window_region(state,hwnd,paint,0,0,3,1,Some((layout,region))).unwrap();
        assert_eq!(prepared.token.dc,backing);
        for index in 0..15{assert_eq!(pixel(&prepared.record,index),if index==6||index==8{0xff445566}else{0xff112233});}
        assert!(state.reserve_output(prepared.token));state.finish_output(prepared.token,false);prepared};
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(accept);
    assert_eq!(submit(prepared),0);assert!(nt_gdi::clean());
}

fn concurrent_write(frame:&Record)->u64{
    assert_eq!(pixel(frame,0),0xffabcdef);
    let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;
    let backing=state.window_dc(frame.header.hwnd as u32).unwrap();
    state.write_dc_pixel(backing,1,1,0x987654).unwrap();
    let current=state.pending_output(frame.header.hwnd as u32,backing).unwrap();
    assert!(!state.reserve_output(current),"new writer cannot overtake reserved submission");0
}

#[test]
fn actual_capture_ack_preserves_concurrent_dirty_then_pump_retries(){
    let _serial=SERIAL.lock().unwrap();setup();let hwnd=hwnd();let window=nt_window::window_rect_for_current(hwnd);
    let prepared={let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;let dc=state.window_dc(hwnd).unwrap();
        production::capture_window(state,hwnd,dc,window).unwrap()};
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(concurrent_write);
    assert_eq!(submit(prepared),0);assert!(!nt_gdi::clean(),"old ACK must not consume newer drawing");
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(|frame|{assert_eq!(pixel(frame,3),0xff987654);0});
    nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
    assert_eq!(*EVENTS.lock().unwrap(),["frame","idle","frame"]);
}

#[test]
fn actual_capture_failed_ack_releases_reservation_and_later_pump_publishes(){
    let _serial=SERIAL.lock().unwrap();setup();let hwnd=hwnd();let window=nt_window::window_rect_for_current(hwnd);
    let prepared={let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;let dc=state.window_dc(hwnd).unwrap();
        production::capture_window(state,hwnd,dc,window).unwrap()};
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(|_|STATUS_INVALID_PARAMETER);
    assert_eq!(submit(prepared),0x103);assert!(!nt_gdi::clean());
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(accept);
    nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
    assert_eq!(*EVENTS.lock().unwrap(),["frame","idle","frame"]);
}

#[test]
fn actual_capture_rejects_mismatched_region_before_storage_mutation(){
    let _serial=SERIAL.lock().unwrap();setup();let hwnd=hwnd();
    let mut entries=nt_gdi::GDI.lock();let state=&mut entries[0].state;let dc=state.window_dc(hwnd).unwrap();
    let before=state.pending_outputs().unwrap();let pixels=state.pixels(dc).unwrap().to_vec();
    let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:1,bottom:1}).unwrap();
    let layout=PaintBacking{width:2,height:2,client:Rect{left:0,top:0,right:2,bottom:2}};
    assert_eq!(production::capture_window_region(state,hwnd,dc,0,0,2,2,Some((layout,region))).err(),Some(STATUS_INVALID_PARAMETER));
    assert_eq!(state.pending_outputs().unwrap(),before);assert_eq!(state.pixels(dc).unwrap(),pixels);
    assert!(state.reserve_output(before[0]));state.finish_output(before[0],false);
}
