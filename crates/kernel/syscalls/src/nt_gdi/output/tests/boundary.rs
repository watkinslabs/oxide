use super::*;
use std::cell::Cell;
use std::sync::Mutex;
use ipc::win32_gdi::{GdiManager,Rect};

#[test]
fn busy_flush_observes_idle_grace_without_extending_it_or_sharing_process_state(){
    let mut first=OutputPump::default();let mut second=OutputPump::default();
    assert!(!first.allow(false,49_999_999));assert!(first.allow(false,50_000_000));
    assert!(first.allow(true,100_000_000));
    for now in [100_000_000,125_000_000,149_999_999]{assert!(!first.allow(false,now));}
    assert!(first.allow(false,150_000_000));assert!(first.allow(false,150_000_001));
    assert!(first.allow(true,160_000_000));assert!(!first.allow(false,209_999_999));
    assert!(first.allow(false,210_000_000));assert!(second.allow(false,160_000_001));
    assert!(!first.allow(false,159_000_000));
}

#[test]
fn frame_publication_owns_pixels_and_releases_capture_lock_before_transport(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,2,2).unwrap();
    g.fill_rect(dc,Rect{left:0,top:0,right:2,bottom:2},0x123456).unwrap();
    let owner=Mutex::new(g);let completed=Cell::new(false);
    let result=flush_one(||{
        let state=owner.lock().unwrap();let (w,h,pixels)=state.surface(dc).unwrap();
        Ok::<_,()>(Some((dc,crate::nt_gdi_frame::snapshot(7,1,w,h,pixels).unwrap())))
    },|frame|{
        let mut state=owner.try_lock().expect("capture must release the canonical owner before transport");
        state.fill_rect(dc,Rect{left:0,top:0,right:2,bottom:2},0xabcdef).unwrap();
        assert_eq!(&frame.payload[16..20],&0xff123456u32.to_le_bytes());true
    },|ticket,presented|{assert_eq!(ticket,dc);assert!(presented);assert!(owner.try_lock().is_ok());completed.set(true);});
    assert_eq!(result,Ok(FlushOutcome::Presented));assert!(completed.get());
}
#[test]
fn clean_and_failed_capture_never_publish_or_complete_a_nonexistent_ticket(){
    assert_eq!(flush_one::<(),()>(||Ok(None),|_|panic!("clean frame"),|_,_|panic!("clean completion")),Ok(FlushOutcome::Clean));
    assert_eq!(flush_one::<(),_>(||Err(7),|_|panic!("failed capture frame"),|_,_|panic!("failed capture completion")),Err(7));
}
#[test]
fn failed_transport_completes_failure_once_without_retrying_in_this_call(){
    let calls=Cell::new(0);let completed=Cell::new(0);
    let frame=crate::nt_gdi_frame::snapshot(7,1,1,1,&[1]).unwrap();
    assert_eq!(flush_one(||Ok::<_,()>(Some((42,frame))),|_|{calls.set(calls.get()+1);false},
        |ticket,presented|{assert_eq!(ticket,42);assert!(!presented);completed.set(completed.get()+1);}),Ok(FlushOutcome::Retry));
    assert_eq!((calls.get(),completed.get()),(1,1));
}

#[path="canonical.rs"]
mod canonical;
