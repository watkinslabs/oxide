//! Only recipient execution is simulated; production callback queue selects messages and resumes.
use super::*;
#[path="../../src/nt_window/send/work.rs"]mod work;
pub(crate) use work::{Queue,Continuation,SendOutcome};
pub(crate) fn send_resumable_current(_:u64,message:u32,wparam:u64,_:u64,continuation:Continuation)->SendOutcome{
    assert!(GUI.0.try_lock().is_ok());assert!(GDI.try_lock().is_ok());
    ENV.with(|e|{let mut e=e.borrow_mut();assert!(e.pending.is_none());e.pending=Some((message,wparam,continuation));});
    SendOutcome::Pending
}
pub(super) fn execute_callback()->u64{
    let(message,wparam,continuation)=ENV.with(|e|e.borrow_mut().pending.take().expect("callback installed"));
    let (event,x,color)=match message{0x85=>(Event::Nc,0,0x123456),0x14=>(Event::Erase,1,0x654321),_=>panic!("unexpected callback message")};
    let dc={let entries=GUI.lock();entries[0].state.paint_session(WindowId::from_raw(1).unwrap()).unwrap().dc};
    {let mut gdi=GDI.lock().unwrap();let state=gdi.as_mut().unwrap();
        if message==0x85{assert!(wparam>1);assert!(state.region_snapshot(wparam as u32).is_ok());}else{assert_eq!(wparam,dc as u64);}
        if !OMIT_CALLBACK_PIXELS_CONTROL{state.write_dc_pixel(dc,x,0,color).unwrap();}
    }
    ENV.with(|e|{let mut e=e.borrow_mut();assert!(e.copies.is_empty());e.events.push(event);});
    (continuation.resume)(continuation.token,Ok(1))
}
