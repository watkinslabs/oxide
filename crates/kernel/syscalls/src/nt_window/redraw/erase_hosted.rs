//! Actual erase resource preparation/completion against canonical window and GDI owners.
#![allow(dead_code,unused_imports,unexpected_cfgs)]
extern crate alloc;
extern crate self as ipc;
extern crate self as sched;
use std::sync::{Arc,Weak,Mutex,MutexGuard,LazyLock};
#[path="../../../../ipc/src/win32_window.rs"] pub mod win32_window;
#[path="../../../../ipc/src/win32_gdi.rs"] pub mod win32_gdi;
use win32_window::{WindowManager,WindowId,WindowRect,PaintRegion,RDW_INVALIDATE,RDW_ERASE,RDW_FRAME};
use win32_gdi::{GdiManager,PaintBacking,Rect};
struct Task{tid:u64,thread_group:Arc<()>}
impl Task{fn is_nt_personality(&self)->bool{true}}
thread_local!{static TASK:Arc<Task>=Arc::new(Task{tid:7,thread_group:Arc::new(())});}
mod live{pub fn current()->Option<std::sync::Arc<super::Task>>{Some(super::TASK.with(Clone::clone))}}
struct Lock<T>(Mutex<T>);
impl<T> Lock<T>{fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
mod nt_window{
    use super::*;
    pub struct Entry{pub group:Weak<()>,pub state:WindowManager}
    pub static GUI:Lock<Vec<Entry>>=Lock(Mutex::new(Vec::new()));
    pub mod paint_callbacks{
        use super::*;
        #[derive(Clone,Copy)] pub struct Resources{pub hwnd:u64,pub dc:u64,pub nc_region:u64,pub erase:bool,pub delayed:bool,pub empty_clip:bool}
        pub enum Completion{Erase(crate::redraw::erase::ErasePrepared)}
        pub fn for_current(r:Resources,c:Completion)->u64{
            assert!(GUI.0.try_lock().is_ok());let Completion::Erase(p)=c;
            *PENDING.lock().unwrap()=Some((r,p));0x103
        }
    }
}
static SERIAL:Mutex<()>=Mutex::new(());
static GDI:LazyLock<Mutex<GdiManager>>=LazyLock::new(||Mutex::new(GdiManager::new()));
static PENDING:Mutex<Option<(nt_window::paint_callbacks::Resources,redraw::erase::ErasePrepared)>>=Mutex::new(None);
static REPLIES:Mutex<Vec<(u64,Result<u64,()>)>>=Mutex::new(Vec::new());
static FAIL_CREATE:Mutex<bool>=Mutex::new(false);
#[path="."] mod redraw{
    pub fn resume(token:u64,result:Result<u64,()>)->u64{super::REPLIES.lock().unwrap().push((token,result));u64::from(result.is_ok())}
    #[path="."] pub mod erase{
        #[path="erase.rs"] mod policy;
        pub(crate) use policy::ErasePrepared;
        #[path="erase_live.rs"] mod live;
        pub(crate) use live::{begin_for_current,finish_for_current,discard_for_current};
    }
}
fn layout()->PaintBacking{PaintBacking{width:8,height:8,client:Rect{left:2,top:2,right:6,bottom:6}}}
mod nt_gdi{
    use super::*;
    pub fn create_region_for_current(r:PaintRegion)->Result<u32,()>{GDI.lock().unwrap().create_region(r).map_err(|_|())}
    pub fn create_paint_dc_for_current(w:i32,h:i32)->Result<u32,()>{
        if *FAIL_CREATE.lock().unwrap(){return Err(());}GDI.lock().unwrap().create_dc(w,h).map_err(|_|())
    }
    pub fn acquire_window_dc_for_current(hwnd:u32,w:i32,h:i32)->u64{GDI.lock().unwrap().acquire_window_dc(hwnd,w,h).map(u64::from).unwrap_or(0xc000000d)}
    pub fn release_window_dc_for_current(hwnd:u32,dc:u32)->u64{GDI.lock().unwrap().release_window_dc(hwnd,dc).map(|_|0).unwrap_or(0xc000000d)}
    pub fn seed_paint_for_current(hwnd:u32,dc:u32)->Result<(),()>{GDI.lock().unwrap().seed_paint(hwnd,dc,layout()).map_err(|_|())}
    pub fn set_paint_region_for_current(dc:u64,r:PaintRegion)->Result<(),()>{GDI.lock().unwrap().set_paint_region(dc as u32,r).map_err(|_|())}
    pub fn region_snapshot_for_current(h:u64)->Result<PaintRegion,()>{GDI.lock().unwrap().region_snapshot(h as u32).map_err(|_|())}
    pub fn retain_erase_for_current(hwnd:u32,dc:u32,r:&PaintRegion,l:PaintBacking)->Result<(),()>{GDI.lock().unwrap().retain_paint_region(hwnd,dc,r,l).map(|_|()).map_err(|_|())}
    pub fn delete_paint_dc_current(dc:u32)->Result<(),()>{GDI.lock().unwrap().delete_object(dc).map_err(|_|())}
    pub fn delete_region_for_current(h:u64)->Result<(),()>{GDI.lock().unwrap().delete_region(h as u32).map_err(|_|())}
}
fn setup()->(u32,u32){
    *GDI.lock().unwrap()=GdiManager::new();*PENDING.lock().unwrap()=None;REPLIES.lock().unwrap().clear();*FAIL_CREATE.lock().unwrap()=false;
    let mut state=WindowManager::new();let id=state.create(7,None,1).unwrap();
    state.set_visible(id,true).unwrap();state.set_rect(id,WindowRect{left:10,top:20,right:18,bottom:28}).unwrap();
    let position=win32_window::WindowPosition{rect:WindowRect{left:10,top:20,right:18,bottom:28},client:Some(WindowRect{left:12,top:22,right:16,bottom:26}),
        window:id,order:None,visible:None,flags:0x18,notify_geometry:false};
    // The fixture installs the same canonical client geometry through position commit.
    state.apply_position(7,position).unwrap();
    let region=PaintRegion::from_rects(&[WindowRect{left:0,top:0,right:1,bottom:1},WindowRect{left:3,top:3,right:4,bottom:4}]).unwrap();
    state.redraw_damage(id,Some(&region),RDW_INVALIDATE|RDW_ERASE|RDW_FRAME,false).unwrap();
    let group=live::current().unwrap().thread_group.clone();
    *nt_window::GUI.lock()=vec![nt_window::Entry{group:Arc::downgrade(&group),state}];
    let mut g=GDI.lock().unwrap();let backing=g.acquire_window_dc(id.raw(),8,8).unwrap();g.fill_rect(backing,Rect{left:0,top:0,right:8,bottom:8},0x123456).unwrap();
    (id.raw(),backing)
}
#[test]
fn erase_live_retains_only_exact_pixels_keeps_damage_and_releases_resources(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,backing)=setup();
    assert_eq!(redraw::erase::begin_for_current(hwnd,71),0x103);
    let(r,p)=PENDING.lock().unwrap().take().unwrap();assert!(r.erase);assert!(!r.empty_clip);
    {
        let mut g=GDI.lock().unwrap();let nc=g.region_snapshot(p.nc_region).unwrap();
        assert_eq!(nc.bounds(),Some(WindowRect{left:12,top:22,right:16,bottom:26}));
        g.fill_rect(p.dc,Rect{left:0,top:0,right:4,bottom:4},0xffffff).unwrap();
    }
    assert_eq!(redraw::erase::finish_for_current(p,Ok(true)),1);
    let g=GDI.lock().unwrap();for y in 0..8{for x in 0..8{
        assert_eq!(g.pixels(backing).unwrap()[y*8+x],if(x==2&&y==2)||(x==5&&y==5){0xffffff}else{0x123456});
    }}
    for h in [p.dc,p.nc_region,p.client_region]{assert!(!g.contains_object(h));}drop(g);
    let id=WindowId::from_raw(hwnd).unwrap();let entries=nt_window::GUI.lock();
    assert!(entries[0].state.paint_session(id).is_err());assert!(entries[0].state.erase_damage(id).unwrap().delayed_erase);
    assert!(entries[0].state.pending_paint_message(7).is_some());
}
#[test]
fn erase_live_failed_preparation_preserves_flags_and_cancel_releases_owned_handles(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup();*FAIL_CREATE.lock().unwrap()=true;
    assert_eq!(redraw::erase::begin_for_current(hwnd,71),0);
    assert!(nt_window::GUI.lock()[0].state.erase_damage(WindowId::from_raw(hwnd).unwrap()).unwrap().erase);
    *FAIL_CREATE.lock().unwrap()=false;assert_eq!(redraw::erase::begin_for_current(hwnd,72),0x103);
    let(_,p)=PENDING.lock().unwrap().take().unwrap();assert_eq!(redraw::erase::finish_for_current(p,Err(())),0);
    let g=GDI.lock().unwrap();for h in [p.dc,p.nc_region,p.client_region]{assert!(!g.contains_object(h));}
}
