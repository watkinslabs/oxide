//! Send/position continuation boundary tests; scheduler and position installation are instrumented.
use super::*;
static RESUMED:Mutex<Vec<(u64,u64,Result<u64,()>)>>=Mutex::new(Vec::new());
fn resumed(token:u64,result:Result<u64,()>)->u64{
    RESUMED.lock().unwrap().push((live::current().unwrap().tid,token,result));0xabc
}
fn continuation()->send::Continuation{send::Continuation{token:42,resume:resumed}}
#[test]
fn resumable_failure_and_zero_lresult_have_distinct_channels(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    for hwnd in [0,9,u64::MAX]{assert_eq!(send::send_resumable_current(hwnd,0x30,0,0,continuation()),send::SendOutcome::Failed);}
    INSTALL_FAIL.with(|f|f.set(true));assert_eq!(send::send_resumable_current(7,0x30,0,0,continuation()),send::SendOutcome::Failed);
    assert!(RESUMED.lock().unwrap().is_empty());INSTALL_FAIL.with(|f|f.set(false));
    for value in [0,0x103,u64::MAX]{
        assert_eq!(send::send_resumable_current(7,0x30,0,0,continuation()),send::SendOutcome::Pending);
        let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,value),0xabc);
        assert_eq!(RESUMED.lock().unwrap().pop(),Some((2,42,Ok(value))));
        assert_eq!(send::complete_callback(callback,99),0);assert!(RESUMED.lock().unwrap().is_empty());
    }
}
#[test]
fn resumable_cancelled_callback_returns_failure_and_retains_only_its_continuation(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    assert_eq!(send::send_resumable_current(7,0x30,0,0,continuation()),send::SendOutcome::Pending);
    let callback=CALLBACK.with(|c|c.take().unwrap());
    GUI.lock()[0].state.0.retain(|(id,_)|*id!=win32_window::WindowId::from_raw(7).unwrap());send::cancel_window(&group,7);
    assert_eq!(send::complete_callback(callback,u64::MAX),0xabc);
    assert_eq!(RESUMED.lock().unwrap().pop(),Some((2,42,Err(()))));
}
#[test]
fn immediate_cross_thread_result_does_not_invoke_resumption_hook(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    for value in [0,0x103,u64::MAX]{
        let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_resumable_current(7,0x30,0,0,continuation())});
        until(send::has_current);assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
        let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,value),0x777);
        assert_eq!(sender.join().unwrap(),send::SendOutcome::Complete(value));assert!(RESUMED.lock().unwrap().is_empty());
    }
}
#[test]
fn position_callback_interrupts_resumable_send_and_resumes_sender_with_all_result_bits(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    for value in [0,0x103,u64::MAX]{
        let (ready_tx,ready_rx)=std::sync::mpsc::channel();
        let sender_group=group.clone();let sender=std::thread::spawn(move||{
            current(&sender_group,1);position::ready();
            assert_eq!(send::send_resumable_current(7,0x30,0,0,continuation()),send::SendOutcome::Pending);
            let saved=position::take();ready_tx.send(()).unwrap();send::wait_reply(saved)
        });
        ready_rx.recv().unwrap();assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
        let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,value),0x777);
        assert_eq!(sender.join().unwrap(),0xabc);assert_eq!(RESUMED.lock().unwrap().pop(),Some((1,42,Ok(value))));
    }
}
#[test]
fn position_callback_interrupts_send_then_destination_exit_resumes_failure(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    let (ready_tx,ready_rx)=std::sync::mpsc::channel();let sender_group=group.clone();
    let sender=std::thread::spawn(move||{
        current(&sender_group,1);position::ready();
        assert_eq!(send::send_resumable_current(7,0x30,0,0,continuation()),send::SendOutcome::Pending);
        let saved=position::take();ready_tx.send(()).unwrap();send::wait_reply(saved)
    });
    ready_rx.recv().unwrap();GUI.lock()[0].state.0.clear();send::cancel_thread(&group,2);
    assert_eq!(sender.join().unwrap(),0xabc);assert_eq!(RESUMED.lock().unwrap().pop(),Some((1,42,Err(()))));
}
#[test]
fn sent_callback_interrupts_position_wait_without_replacing_its_boolean(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let sender_group=group.clone();let sender=std::thread::spawn(move||{current(&sender_group,1);send::send_for_current(7,0x30,0,0)});
    until(send::has_current);let position_reply=Arc::new(send::Reply::new());
    assert_eq!(send::wait_reply(position_reply.clone()),0x103);
    let callback=CALLBACK.with(|c|c.take().unwrap());position_reply.complete(1);
    assert_eq!(send::complete_callback(callback,u64::MAX),1);assert_eq!(sender.join().unwrap(),u64::MAX);
}
#[test]
fn active_destroy_cannot_publish_reply_to_suspended_sender_before_receiver_returns(){
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);RESUMED.lock().unwrap().clear();
    let (ready_tx,ready_rx)=std::sync::mpsc::channel();let (continue_tx,continue_rx)=std::sync::mpsc::channel();
    let sender_group=group.clone();let sender=std::thread::spawn(move||{
        current(&sender_group,1);position::ready();
        assert_eq!(send::send_resumable_current(7,0x14,0x10040,0,continuation()),send::SendOutcome::Pending);
        let saved=position::take();ready_tx.send(saved.clone()).unwrap();continue_rx.recv().unwrap();send::wait_reply(saved)
    });
    let reply=ready_rx.recv().unwrap();assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    let callback=CALLBACK.with(|c|c.take().unwrap());GUI.lock()[0].state.0.clear();send::cancel_window(&group,7);
    assert_eq!(reply.outcome(),None,"active recipient still owns the message's HDC lease");
    assert!(RESUMED.lock().unwrap().is_empty());
    assert_eq!(send::complete_callback(callback,u64::MAX),0x777);assert_eq!(reply.outcome(),Some(Err(())));
    continue_tx.send(()).unwrap();assert_eq!(sender.join().unwrap(),0xabc);
    assert_eq!(*RESUMED.lock().unwrap(),vec![(1,42,Err(()))]);
}
