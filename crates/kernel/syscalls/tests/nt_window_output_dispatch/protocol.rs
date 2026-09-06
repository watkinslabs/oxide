//! Production frame submission and stream/queue transitions; hosted socket and wait scheduling.
use super::*;
use syscall::nt_compositor::{Record,Opcode,Header};
#[path="../../src/nt_compositor/queue.rs"]
mod queue;
#[path="../../src/nt_compositor/stream.rs"]
mod stream;
#[path="../../src/nt_gdi/output/transport.rs"]
mod transport;
#[path="../../src/nt_window/bridge.rs"]
mod bridge;
pub use queue::{Completion,TransportError};
use queue::Queue;
const STATUS_PENDING:u64=0x103;
const STATUS_FAILURE:u64=0xc000000d;
#[derive(Clone,Copy)]
enum Scenario{Presented,Failed,EarlyAckDisconnect,CompletedThenDisconnect,Disconnected,Full,Timeout,WrongAck,GuiBeforeAck,Reentrant}
thread_local!{
    static QUEUE:RefCell<Queue>=RefCell::new(Queue::new());
    static SCENARIO:RefCell<Scenario>=const{RefCell::new(Scenario::Presented)};
}
fn reset(scenario:Scenario){
    QUEUE.with(|q|*q.borrow_mut()=Queue::new());SCENARIO.with(|s|*s.borrow_mut()=scenario);
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(|frame|transport::submit_frame(Ok(frame.clone())));
}
pub(super) fn deliver_gui_event(state:&mut ipc::win32_window::WindowManager,hwnd:u32){
    let rect=syscall::nt_compositor::Rect{x:0,y:0,width:4,height:4};
    let event=Record::new(Opcode::Configure,1,hwnd as u64,rect.encode_window().unwrap().to_vec()).unwrap();
    assert!(bridge::apply_event(state,&event,|state,id,x,y,buttons,wheel|state.post_compositor_pointer(id,x,y,buttons,wheel).is_ok()));
    let filter=MessageFilter{hwnd:WindowId::from_raw(hwnd),first:ipc::win32_window::WM_SIZE,last:ipc::win32_window::WM_SIZE};
    assert!(state.peek_for_thread(41,filter,false).is_some(),"Configure must queue GUI work without dispatching application paint");
}
pub fn enqueue_current(opcode:Opcode,hwnd:u64,payload:Vec<u8>)->Result<u64,TransportError>{
    assert!(nt_gdi::GDI.unlocked());assert!(nt_window::GUI.unlocked());
    QUEUE.with(|q|{let mut q=q.borrow_mut();
        match SCENARIO.with(|s|*s.borrow()){
            Scenario::Disconnected=>q.close(),
            Scenario::Full=>for _ in 0..syscall::nt_compositor::MAX_QUEUED_RECORDS{
                q.enqueue_prepared(&mut Some(queue::Prepared::new(Opcode::Destroy,hwnd,vec![])?))?;
            },_=>{}
        }
        q.enqueue_prepared(&mut Some(queue::Prepared::new(opcode,hwnd,payload)?))
    })
}
pub fn wait_completion_current(ticket:u64,timeout:u64)->Result<Completion,TransportError>{
    assert_eq!(timeout,5_000_000_000);assert!(nt_gdi::GDI.unlocked());assert!(nt_window::GUI.unlocked());
    let bytes=QUEUE.with(|q|{let mut q=q.borrow_mut();assert_eq!(q.take_completion(ticket),Ok(Completion::Pending));q.take_send().unwrap()});
    let header=Header::decode(&bytes[..syscall::nt_compositor::HEADER_LEN]).unwrap();assert_eq!(header.sequence,ticket);
    let scenario=SCENARIO.with(|s|*s.borrow());
    if matches!(scenario,Scenario::GuiBeforeAck){
        let (send,receive)=std::sync::mpsc::channel();let hwnd=header.hwnd as u32;
        let worker=std::thread::spawn(move||{nt_window::deliver_test_event(hwnd);send.send(()).unwrap();});
        receive.recv_timeout(std::time::Duration::from_secs(1)).expect("GUI event must not require waiting app thread");
        worker.join().unwrap();EVENTS.lock().unwrap().push("gui-event");
    }
    if matches!(scenario,Scenario::Reentrant){
        let prepared=crate::presentation_fixture::capture_current();
        assert_eq!(nt_gdi::output::kernel::submit_prepared_for_current(Ok(prepared)),STATUS_PENDING);
        assert_eq!(EVENTS.lock().unwrap().iter().filter(|e|**e=="frame").count(),1,"busy submit must not recurse into transport");
    }
    let ack_status=if matches!(scenario,Scenario::Failed){3u32}else{0};
    let ack=Record::new(Opcode::Ack,ticket,header.hwnd,ack_status.to_le_bytes().to_vec()).unwrap().encode().unwrap();
    let mut offset=0;
    let ack=stream::read_record(|out|{let n=out.len().min(3).min(ack.len()-offset);out[..n].copy_from_slice(&ack[offset..offset+n]);offset+=n;Ok(n)}).unwrap();
    QUEUE.with(|q|{let mut q=q.borrow_mut();
        if matches!(scenario,Scenario::WrongAck){
            assert_eq!(q.acknowledge(ticket,header.hwnd+1,0),Err(TransportError::Unknown));q.close();return q.take_completion(ticket);
        }
        if matches!(scenario,Scenario::Timeout){
            assert!(!q.completion_ready(ticket));q.close();return Err(TransportError::Timeout);
        }
        q.acknowledge(ack.header.sequence,ack.header.hwnd,u32::from_le_bytes(ack.payload[..4].try_into().unwrap())).unwrap();
        assert_eq!(q.take_completion(ticket),Ok(Completion::Pending),"ACK alone cannot acknowledge dirty backing");
        if matches!(scenario,Scenario::EarlyAckDisconnect){
            let mut calls=0;
            assert_eq!(stream::write_record(&bytes,|_|{calls+=1;Ok(if calls==1{1}else{0})}),Err(TransportError::Disconnected));
            q.close();return q.take_completion(ticket);
        }
        let mut transmitted=Vec::new();stream::write_record(&bytes,|part|{let n=part.len().min(7);transmitted.extend_from_slice(&part[..n]);Ok(n)}).unwrap();
        assert_eq!(transmitted,bytes);q.sent().unwrap();
        if matches!(scenario,Scenario::CompletedThenDisconnect){q.close();}
        q.take_completion(ticket)
    })
}
fn submit()->u64{let prepared=crate::presentation_fixture::capture_current();nt_gdi::output::kernel::submit_prepared_for_current(Ok(prepared))}

#[test]
fn production_protocol_failures_never_ack_retained_backing_and_retry_later(){
    let _serial=SERIAL.lock().unwrap();
    for scenario in [Scenario::Failed,Scenario::EarlyAckDisconnect,Scenario::CompletedThenDisconnect,Scenario::Disconnected,Scenario::Full,Scenario::Timeout,Scenario::WrongAck]{
        setup();reset(scenario);assert_eq!(submit(),STATUS_PENDING);assert!(!nt_gdi::clean());
        assert!(!EVENTS.lock().unwrap().contains(&"ack"));
        reset(Scenario::Presented);nt_gdi::flush_pending_for_current(true);
        assert!(nt_gdi::clean());assert_eq!(EVENTS.lock().unwrap().iter().filter(|e|**e=="ack").count(),1);
    }
}
#[test]
fn production_protocol_gui_delivery_precedes_ack_without_app_message_dispatch(){
    let _serial=SERIAL.lock().unwrap();setup();reset(Scenario::GuiBeforeAck);
    assert_eq!(submit(),0);assert!(nt_gdi::clean());assert_eq!(*EVENTS.lock().unwrap(),["frame","gui-event","ack"]);
}
#[test]
fn production_protocol_reentrant_paint_is_pending_not_failed_or_recursively_submitted(){
    let _serial=SERIAL.lock().unwrap();setup();reset(Scenario::Reentrant);
    assert_eq!(submit(),0);assert!(!nt_gdi::clean(),"reentrant output demand survives old ACK");
    reset(Scenario::Presented);nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
}
#[test]
fn missing_current_and_dropped_capture_leave_no_reserved_slot(){
    let _serial=SERIAL.lock().unwrap();setup();
    let prepared=crate::presentation_fixture::capture_current();drop(prepared);
    let prepared=crate::presentation_fixture::capture_current();
    let task=sched::CURRENT.with(|c|c.borrow_mut().take());
    assert_eq!(nt_gdi::output::kernel::submit_prepared_for_current(Ok(prepared)),0xc0000008);
    sched::CURRENT.with(|c|*c.borrow_mut()=task);
    reset(Scenario::Presented);nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
}
#[test]
fn stale_capture_refreshes_pixels_before_reservation_and_upload(){
    let _serial=SERIAL.lock().unwrap();setup();let prepared=crate::presentation_fixture::capture_current();
    {let mut entries=nt_gdi::GDI.lock();entries[0].state.write_dc_pixel(prepared.token.dc,0,0,0x765432).unwrap();}
    *nt_gdi::TRANSPORT.lock().unwrap()=Some(|frame|{
        assert_eq!(&frame.payload[16..20],&0xff765432u32.to_le_bytes());0
    });
    assert_eq!(nt_gdi::output::kernel::submit_prepared_for_current(Ok(prepared)),0);assert!(nt_gdi::clean());
}
#[test]
fn production_transport_rejects_input_error_without_queue_or_ack(){
    let _serial=SERIAL.lock().unwrap();setup();reset(Scenario::Presented);
    assert_eq!(transport::submit_frame(Err(STATUS_FAILURE)),STATUS_FAILURE);assert!(EVENTS.lock().unwrap().is_empty());
}
#[test]
fn already_acknowledged_capture_is_not_retransmitted_or_reported_invalid(){
    let _serial=SERIAL.lock().unwrap();setup();reset(Scenario::Presented);
    let prepared=crate::presentation_fixture::capture_current();
    nt_gdi::flush_pending_for_current(true);assert!(nt_gdi::clean());
    let events=EVENTS.lock().unwrap().clone();
    assert_eq!(nt_gdi::output::kernel::submit_prepared_for_current(Ok(prepared)),0);
    assert_eq!(*EVENTS.lock().unwrap(),events);
}
