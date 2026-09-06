//! Production paint reservation/native admission with canonical GUI state and faultable copy seam.
use super::*;
use crate::nt_window::GUI;
use ipc::win32_window::{WindowRect,PaintRegion,PaintSessionError};
const STATUS_SUCCESS:u64=0;
const STATUS_INVALID_HANDLE:u64=0xc0000008;
const STATUS_ACCESS_VIOLATION:u64=0xc0000005;
const COPY_DESTINATION:u64=0x4000;
const BAD_DESTINATION:u64=0x8000;
const DAMAGE:WindowRect=WindowRect{left:0,top:0,right:1,bottom:1};
const NEW_DAMAGE:WindowRect=WindowRect{left:1,top:1,right:2,bottom:2};
const ORPHAN_ROLLBACK_CONTROL:bool=false;
static COPY:Mutex<Vec<(u64,WindowRect)>>=Mutex::new(Vec::new());
thread_local!{static COPY_INVALIDATE:RefCell<bool>=const{RefCell::new(false)};}
#[path="../../src/nt_window/paint.rs"]
mod production;
fn valid_window(hwnd:u64)->Option<WindowId>{u32::try_from(hwnd).ok().and_then(WindowId::from_raw)}
fn copy_rect(destination:syscall::UserPtr<nt::NtWindowRect>,rect:WindowRect)->u64{
    assert!(GUI.unlocked(),"native paint copyout must run outside GUI ownership");
    assert!(nt_gdi::GDI.unlocked());COPY.lock().unwrap().push((destination.as_u64(),rect));
    if COPY_INVALIDATE.with(|c|*c.borrow()){
        let mut entries=GUI.lock();let id=WindowId::from_raw(1).unwrap();
        assert_eq!(entries[0].state.paint_session(id).unwrap().damage,Some(DAMAGE));
        entries[0].state.invalidate(id,Some(NEW_DAMAGE)).unwrap();
    }
    if destination.as_u64()==COPY_DESTINATION{STATUS_SUCCESS}else{
        if ORPHAN_ROLLBACK_CONTROL{sched::CURRENT.with(|c|*c.borrow_mut()=Some(Arc::new(sched::Task{
            thread_group:Arc::new(sched::thread_group::ThreadGroup),tid:41})));}
        STATUS_ACCESS_VIOLATION
    }
}
fn init(dirty:bool)->WindowId{
    setup();COPY.lock().unwrap().clear();COPY_INVALIDATE.with(|c|*c.borrow_mut()=false);
    let id=WindowId::from_raw(1).unwrap();
    if dirty{GUI.lock()[0].state.invalidate(id,Some(DAMAGE)).unwrap();}id
}
#[test]
fn actual_reserve_creates_unbound_session_without_copy_and_exposes_exact_damage(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);
    assert_eq!(production::reserve_for_current(id.raw() as u64),Ok(DAMAGE));assert!(COPY.lock().unwrap().is_empty());
    let session=GUI.lock()[0].state.paint_session(id).unwrap();assert_eq!(session.dc,0);assert_eq!(session.damage,Some(DAMAGE));
    assert_eq!(session.region,PaintRegion::from_rect(DAMAGE).unwrap());
    assert_eq!(production::current_region(id.raw() as u64),Some(session.region));
    assert_eq!(production::current_rect(id.raw() as u64),Some(DAMAGE));
    assert!(production::presentation_for_current(id.raw()).is_some());assert!(production::backing_for_current(id.raw()).is_some());
    assert_eq!(production::reserve_for_current(id.raw() as u64),Err(STATUS_INVALID_HANDLE));
    assert_eq!(GUI.lock()[0].state.paint_session(id).unwrap().dc,0);
}
#[test]
fn actual_invalid_hwnd_leaves_existing_session_and_pending_damage_unchanged(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);
    let before=GUI.lock()[0].state.erase_damage(id).unwrap();
    for hwnd in [0,2,u64::MAX,0x1_0000_0001]{
        assert_eq!(production::reserve_for_current(hwnd),Err(STATUS_INVALID_HANDLE));
        assert_eq!(production::begin(hwnd,syscall::UserPtr::new(COPY_DESTINATION).unwrap()),STATUS_INVALID_HANDLE);
    }
    assert_eq!(GUI.lock()[0].state.erase_damage(id).unwrap(),before);
    assert_eq!(GUI.lock()[0].state.paint_session(id),Err(PaintSessionError::NotActive));assert!(COPY.lock().unwrap().is_empty());
}
#[test]
fn actual_native_begin_copies_reserved_rect_once_and_keeps_session(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);
    assert_eq!(production::begin(id.raw() as u64,syscall::UserPtr::new(COPY_DESTINATION).unwrap()),STATUS_SUCCESS);
    assert_eq!(*COPY.lock().unwrap(),[(COPY_DESTINATION,DAMAGE)]);
    assert_eq!(GUI.lock()[0].state.paint_session(id).unwrap().damage,Some(DAMAGE));
}
#[test]
fn actual_native_bad_copy_ends_reservation_but_preserves_new_invalidation(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);COPY_INVALIDATE.with(|c|*c.borrow_mut()=true);
    assert_eq!(production::begin(id.raw() as u64,syscall::UserPtr::new(BAD_DESTINATION).unwrap()),STATUS_ACCESS_VIOLATION);
    assert_eq!(*COPY.lock().unwrap(),[(BAD_DESTINATION,DAMAGE)]);
    assert_eq!(GUI.lock()[0].state.paint_session(id),Err(PaintSessionError::NotActive));
    assert_eq!(production::reserve_for_current(id.raw() as u64),Ok(NEW_DAMAGE));
}
#[test]
fn actual_native_bad_copy_does_not_restore_consumed_damage_and_empty_reserve_is_valid(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);
    assert_eq!(production::begin(id.raw() as u64,syscall::UserPtr::new(BAD_DESTINATION).unwrap()),STATUS_ACCESS_VIOLATION);
    assert_eq!(GUI.lock()[0].state.paint_session(id),Err(PaintSessionError::NotActive));
    assert_eq!(production::reserve_for_current(id.raw() as u64),Ok(WindowRect{left:0,top:0,right:0,bottom:0}));
    assert!(GUI.lock()[0].state.paint_session(id).unwrap().region.is_empty());
}
#[test]
fn actual_missing_or_foreign_process_cannot_reserve_existing_hwnd(){
    let _serial=SERIAL.lock().unwrap();let id=init(true);let task=sched::live::current().unwrap();
    sched::CURRENT.with(|c|*c.borrow_mut()=None);
    assert_eq!(production::reserve_for_current(id.raw() as u64),Err(STATUS_INVALID_HANDLE));
    sched::CURRENT.with(|c|*c.borrow_mut()=Some(Arc::new(sched::Task{thread_group:Arc::new(sched::thread_group::ThreadGroup),tid:99})));
    assert_eq!(production::reserve_for_current(id.raw() as u64),Err(STATUS_INVALID_HANDLE));
    sched::CURRENT.with(|c|*c.borrow_mut()=Some(task));
    assert_eq!(production::reserve_for_current(id.raw() as u64),Ok(DAMAGE));
}
