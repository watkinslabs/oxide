//! Joined canonical paint, redraw and Send execution; only scheduler/PE installation are hosted.
#![allow(dead_code, unused_imports, unexpected_cfgs)]
extern crate alloc;
extern crate self as sched;
extern crate self as ipc;
extern crate self as uaccess;
#[path="../desktop/geometry.rs"] mod desktop_geometry;
#[path="../../../../ipc/src/win32_gdi.rs"] pub mod win32_gdi;
static GDI:std::sync::LazyLock<Mutex<win32_gdi::GdiManager>>=std::sync::LazyLock::new(||Mutex::new(win32_gdi::GdiManager::new()));
mod nt_gdi {
    use crate::{GDI,win32_window::PaintRegion,win32_gdi::{PaintBacking,Rect}};
    fn layout(hwnd:u32)->Result<PaintBacking,()> {
        let entries=crate::GUI.lock();let state=&entries[0].state;
        let id=crate::win32_window::WindowId::from_raw(hwnd).ok_or(())?;
        let b=state.rect(id).ok_or(())?;let c=state.get(id).ok_or(())?.client_rect.unwrap_or(b);
        Ok(PaintBacking{width:b.right-b.left,height:b.bottom-b.top,client:Rect{left:c.left-b.left,top:c.top-b.top,right:c.right-b.left,bottom:c.bottom-b.top}})
    }
    pub fn create_region_for_current(r:PaintRegion)->Result<u32,()>{GDI.lock().unwrap().create_region(r).map_err(|_|())}
    pub fn create_paint_dc_for_current(w:i32,h:i32)->Result<u32,()>{GDI.lock().unwrap().create_dc(w,h).map_err(|_|())}
    pub fn acquire_window_dc_for_current(hwnd:u32,w:i32,h:i32)->u64{GDI.lock().unwrap().acquire_window_dc(hwnd,w,h).map(u64::from).unwrap_or(0xc000000d)}
    pub fn release_window_dc_for_current(hwnd:u32,dc:u32)->u64{GDI.lock().unwrap().release_window_dc(hwnd,dc).map(|_|0).unwrap_or(0xc000000d)}
    pub fn seed_paint_for_current(hwnd:u32,dc:u32)->Result<(),()>{let l=layout(hwnd)?;GDI.lock().unwrap().seed_paint(hwnd,dc,l).map_err(|_|())}
    pub fn set_paint_region_for_current(dc:u64,r:PaintRegion)->Result<(),()>{GDI.lock().unwrap().set_paint_region(dc as u32,r).map_err(|_|())}
    pub fn retain_erase_for_current(hwnd:u32,dc:u32,r:&PaintRegion,l:PaintBacking)->Result<(),()>{
        if layout(hwnd)?!=l{return Err(());}GDI.lock().unwrap().retain_paint_region(hwnd,dc,r,l).map(|_|()).map_err(|_|())
    }
    pub fn delete_paint_dc_current(dc:u32)->Result<(),()>{GDI.lock().unwrap().delete_object(dc).map_err(|_|())}
    pub fn delete_region_for_current(h:u64)->Result<(),()>{GDI.lock().unwrap().delete_region(h as u32).map_err(|_|())}
    pub fn region_snapshot_for_current(handle:u64)->Result<crate::win32_window::PaintRegion,()> {
        assert!(!crate::GUI_HELD.with(|v|v.get()));
        crate::GDI.lock().unwrap().region_snapshot(u32::try_from(handle).map_err(|_|())?).map_err(|_|())
    }
}
pub fn copy_from_user(out: &mut [u8], address: u64) -> Result<(), ()> {
    if address != 0x10000 || out.len() != 16 { return Err(()); }
    for (i,value) in [7i32,7,3,3].iter().enumerate() {out[i*4..i*4+4].copy_from_slice(&value.to_le_bytes());}
    Ok(())
}
// Production send boundary harness body shared by rustc and Cargo wrappers.
use std::sync::{Arc,Weak,Mutex,MutexGuard};
use std::cell::Cell;
pub mod thread_group {pub struct ThreadGroup;}
pub struct Task {pub tid:u64,pub thread_group:Arc<thread_group::ThreadGroup>}
impl Task {pub fn is_nt_personality(&self)->bool{true}}
pub mod nt_callback {#[derive(Clone,Copy)]pub struct Completion{pub kind:u64,pub argument:u64}}
thread_local!{static CURRENT:Cell<Option<&'static Task>>=const{Cell::new(None)};static CALLBACK:Cell<Option<nt_callback::Completion>>=const{Cell::new(None)};}
thread_local!{static INSTALL_FAIL:Cell<bool>=const{Cell::new(false)};}
thread_local!{static DEADLINE:Cell<Option<std::time::Instant>>=const{Cell::new(None)};}
pub mod live {
    use super::*;
    pub struct WaitList;
    impl WaitList {pub fn wake_all(&self){}}
    pub fn current()->Option<&'static Task>{CURRENT.with(Cell::get)}
    pub unsafe fn wait_event_uninterruptible(_: &WaitList,ready:impl Fn()->bool){
        assert!(std::time::Instant::now()<DEADLINE.with(|d|d.get().unwrap()),"hosted GUI wait made no progress");
        let end=std::time::Instant::now()+std::time::Duration::from_secs(5);
        while !ready(){assert!(std::time::Instant::now()<end,"hosted sender failed to wake");std::thread::yield_now();}
    }
}
#[path="../../../../ipc/src/win32_window.rs"] pub mod win32_window;
static CALLS:Mutex<Vec<(u64,u64,u64,u64,u64)>>=Mutex::new(Vec::new());
mod nt_rtl {
    pub fn begin_wndproc_callback_with_completion(hwnd:u64,msg:u64,wp:u64,lp:u64,_proc:u64,c:crate::nt_callback::Completion)->u64{
        assert!(!crate::GUI_HELD.with(|v|v.get()), "GUI held at PE callback installation");
        if crate::INSTALL_FAIL.with(|f|f.get()){return 0xc000000d;}
        let tid=crate::live::current().unwrap().tid;
        crate::CALLS.lock().unwrap().push((tid,hwnd,msg,wp,lp));
        crate::CALLBACK.with(|saved|{assert!(saved.get().is_none());saved.set(Some(c));});0x103
    }
}
thread_local!{static GUI_HELD:Cell<bool>=const{Cell::new(false)};}
struct Lock<T>(Mutex<T>);
struct Guard<'a,T>(MutexGuard<'a,T>);
impl<T> core::ops::Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.0}}
impl<T> core::ops::DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){GUI_HELD.with(|v|v.set(false));}}
impl<T> Lock<T>{fn lock(&self)->Guard<'_,T>{
    assert!(!GUI_HELD.with(Cell::get),"recursive GUI acquisition");
    let guard=self.0.lock().unwrap();GUI_HELD.with(|v|v.set(true));Guard(guard)
}}
mod nt_window {
    use super::*;
    pub(crate) use crate::paint_callbacks;
    pub const STATUS_PENDING:u64=0x103;
    pub struct GuiEntry{pub group:Weak<thread_group::ThreadGroup>,pub state:win32_window::WindowManager,pub redraw:redraw::Queue,pub sent:send::Queue,pub wait:Arc<live::WaitList>,pub paint_callbacks:paint_callbacks::Queue}
    pub static GUI:Lock<Vec<GuiEntry>>=Lock(Mutex::new(Vec::new()));
    pub fn resume_position_message_current()->u64{0x777}
}
use nt_window::{GUI,STATUS_PENDING,resume_position_message_current};
#[path="../send.rs"]mod send;
#[path="../paint_prepare"] mod paint_prepare {
    #[path="policy.rs"] mod policy;
    pub(crate) use policy::*;
    pub(crate) fn finish_for_current(_:Prepared,_:Result<bool,()>)->u64 { unreachable!("BeginPaint preparation has a separate owner harness") }
    pub(crate) fn discard_for_current(_:Prepared) { unreachable!("BeginPaint preparation has a separate owner harness") }
}
#[path="../paint_callbacks"] mod paint_callbacks {
    use crate::paint_prepare;
    use crate::redraw;
    #[path="../paint_callbacks.rs"] mod policy;
    pub(crate) use policy::*;
    #[path="live.rs"] mod live;
    pub(crate) use live::{for_current,resume,dispose_for_current,cancel_window_current,reap_retired_current};
}
#[path="."] mod redraw {
    use ipc::win32_window::WindowId;
    #[path="../redraw.rs"] mod policy;
    pub(crate) use policy::*;
    #[path="live.rs"] mod live;
    pub(crate) use live::{for_current,resume};
    #[path="."] pub(crate) mod erase {
        pub(crate) use super::policy::erase::ErasePrepared;
        #[path="erase_live.rs"] mod live;
        pub(crate) use live::{begin_for_current,finish_for_current,discard_for_current};
    }
}
mod position {
    use std::{cell::{Cell,RefCell},sync::Arc};
    thread_local!{static READY:Cell<bool>=const{Cell::new(false)};static SAVED:RefCell<Option<Arc<crate::send::Reply>>>=const{RefCell::new(None)};}
    // Instrumented position installation boundary; production send wait supplies
    // the same owned reply retained by pending-position callbacks.
    pub fn pump_for_reply(reply:Arc<crate::send::Reply>)->Option<u64>{
        if !READY.with(|r|r.replace(false)){return None;}
        SAVED.with(|s|{assert!(s.borrow().is_none());*s.borrow_mut()=Some(reply);});Some(0x103)
    }
    pub fn has_remote_for_current()->bool{READY.with(|r|r.get())}
    pub fn ready(){READY.with(|r|r.set(true));}
    pub fn take()->Arc<crate::send::Reply>{SAVED.with(|s|s.borrow_mut().take().unwrap())}
}
static SERIAL:Mutex<()>=Mutex::new(());
fn setup()->Arc<thread_group::ThreadGroup>{
    *GDI.lock().unwrap()=win32_gdi::GdiManager::new();
    let group=Arc::new(thread_group::ThreadGroup);
    let mut state=win32_window::WindowManager::new();
    let root=state.create(2,None,0x1234).unwrap();
    let child=state.create(2,Some(root),0x2345).unwrap();
    assert_eq!((root.raw(),child.raw()),(1,2));
    for id in [root,child] {
        state.set_visible(id,true).unwrap();
        state.set_rect(id,win32_window::WindowRect{left:0,top:0,right:10,bottom:10}).unwrap();
        state.invalidate(id,None).unwrap();
    }
    *GUI.lock()=vec![nt_window::GuiEntry{group:Arc::downgrade(&group),sent:send::Queue::new(),
        wait:Arc::new(live::WaitList),redraw:redraw::Queue::new(),paint_callbacks:paint_callbacks::Queue::new(),state}];
    CALLS.lock().unwrap().clear();group
}

#[path="joined_erase_tests.rs"] mod joined_erase_tests;
fn current(group:&Arc<thread_group::ThreadGroup>,tid:u64){
    CURRENT.with(|c|c.set(Some(Box::leak(Box::new(Task{tid,thread_group:group.clone()})))));
    CALLBACK.with(|c|c.set(None));
    INSTALL_FAIL.with(|f|f.set(false));
    DEADLINE.with(|d|d.set(Some(std::time::Instant::now()+std::time::Duration::from_secs(5))));
}
fn until(ready:impl Fn()->bool){
    let end=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while !ready(){assert!(std::time::Instant::now()<end,"hosted receiver never became ready");std::thread::yield_now();}
}

fn complete_paint(hwnd:u32,value:u64)->u64 {
    let callback=CALLBACK.with(|c|c.take().unwrap());
    {
        let mut entries=GUI.lock();let state=&mut entries[0].state;
        let id=win32_window::WindowId::from_raw(hwnd).unwrap();
        state.begin_paint(id).unwrap();state.end_paint(id).unwrap();
    }
    send::complete_callback(callback,value)
}
#[test]
fn joined_same_thread_paints_children_before_returning_bool() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,0x180),STATUS_PENDING);
    assert_eq!(complete_paint(1,0),STATUS_PENDING);
    assert_eq!(complete_paint(2,u64::MAX),1);
    assert_eq!(*CALLS.lock().unwrap(),vec![(2,1,15,0,0),(2,2,15,0,0)]);
    assert_eq!(redraw::for_current(1,0,0,0x180),1);
}
#[test]
fn joined_cross_thread_executes_on_owner_and_returns_bool_to_sender() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let other=group.clone();
    let sender=std::thread::spawn(move||{current(&other,1);redraw::for_current(1,0,0,0x180)});
    for hwnd in [1,2] {
        until(send::has_current);
        assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
        assert_eq!(complete_paint(hwnd,0x103),0x777);
    }
    assert_eq!(sender.join().unwrap(),1);
    assert_eq!(*CALLS.lock().unwrap(),vec![(2,1,15,0,0),(2,2,15,0,0)]);
}
#[test]
fn joined_install_failure_and_revoked_callback_cannot_report_success() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    INSTALL_FAIL.with(|v|v.set(true));
    assert_eq!(redraw::for_current(1,0,0,0x180),0);
    INSTALL_FAIL.with(|v|v.set(false));
    assert_eq!(redraw::for_current(1,0,0,0x180),STATUS_PENDING);
    send::cancel_window(&group,1);
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,0),0);
}

#[test]
fn joined_nonclient_then_erase_completion_preserves_zero_and_cleanup_error() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let resources=paint_callbacks::Resources{hwnd:1,dc:22,nc_region:33,erase:true,delayed:false,empty_clip:false};
    let completion=paint_callbacks::Completion::Callback{token:71,finish:|token,result|{
        assert_eq!(token,71);assert!(!GUI_HELD.with(Cell::get));
        match result {Ok(needed)=>if needed{9}else{8},Err(())=>7}
    }};
    for (erase_result,expected) in [(0,9),(u64::MAX,8),(0x103,8)] {
        CALLS.lock().unwrap().clear();
        assert_eq!(paint_callbacks::for_current(resources,completion),STATUS_PENDING);
        let nc=CALLBACK.with(|c|c.take().unwrap());
        assert_eq!(send::complete_callback(nc,0),STATUS_PENDING);
        let erase=CALLBACK.with(|c|c.take().unwrap());
        assert_eq!(send::complete_callback(erase,erase_result),expected);
        assert_eq!(*CALLS.lock().unwrap(),vec![(2,1,0x85,33,0),(2,1,0x14,22,0)]);
    }
    INSTALL_FAIL.with(|v|v.set(true));
    assert_eq!(paint_callbacks::for_current(resources,completion),7);
    INSTALL_FAIL.with(|v|v.set(false));
    assert_eq!(paint_callbacks::for_current(resources,completion),STATUS_PENDING);
    send::cancel_window(&group,1);
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,1),7);
}

#[test]
fn joined_raw_redraw_mutates_exact_region_before_synchronous_send() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    // Whole-tree validation consumes pre-existing setup damage, not a posted queue copy.
    assert_eq!(redraw::for_current(1,0,0,0x488),1);
    assert_eq!(redraw::for_current(1,0,0,0x180),1);
    assert!(CALLS.lock().unwrap().is_empty());
    assert_eq!(redraw::for_current(1,0x10000,0,0x1c5),STATUS_PENDING);
    let id=win32_window::WindowId::from_raw(1).unwrap();
    {
        let mut entries=GUI.lock();let state=&mut entries[0].state;
        assert_eq!(state.begin_paint(id).unwrap(),Some(win32_window::WindowRect{left:3,top:3,right:7,bottom:7}));
        assert!(state.paint_session(id).unwrap().erase);state.end_paint(id).unwrap();
    }
    let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,0),1);
    assert_eq!(redraw::for_current(1,0xdead,0,0x81),0);
    assert_eq!(redraw::for_current(1,0,0,0x180),1);
    assert_eq!(redraw::for_current(1,0,0,0x142),STATUS_PENDING);
    assert_eq!(complete_paint(1,0),1);
    assert_eq!(redraw::for_current(1,0,0,0x180),1);
}

#[test]
fn joined_raw_hrgn_preserves_holes_and_never_reads_ignored_rect() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,0x488),1);
    let r=|l,t,r,b|win32_window::WindowRect{left:l,top:t,right:r,bottom:b};
    let region=win32_window::PaintRegion::from_rects(&[r(0,0,2,2),r(8,8,10,10)]).unwrap();
    let handle=GDI.lock().unwrap().create_region(region).unwrap();
    assert_eq!(redraw::for_current(1,u64::MAX,handle as u64,0x141),STATUS_PENDING);
    {
        let mut entries=GUI.lock();let state=&mut entries[0].state;let id=win32_window::WindowId::from_raw(1).unwrap();
        state.begin_paint(id).unwrap();let exact=state.paint_region(id).unwrap();
        assert_eq!(exact.rects().len(),2);assert_eq!(exact.bounds(),Some(r(0,0,10,10)));state.end_paint(id).unwrap();
    }
    let callback=CALLBACK.with(|c|c.take().unwrap());assert_eq!(send::complete_callback(callback,0),1);
    assert_eq!(redraw::for_current(1,0,u64::MAX,0x41),0);
    assert_eq!(redraw::for_current(1,0,0,0x180),1);
    GDI.lock().unwrap().delete_region(handle).unwrap();
}
