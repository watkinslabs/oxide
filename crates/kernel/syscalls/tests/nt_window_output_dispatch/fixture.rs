use std::sync::{Arc,Weak,Mutex,MutexGuard};
use std::cell::RefCell;
use syscall::nt::{self,NtCall,NtWindowCall,NtWindowMessage};
use ipc::win32_window::{WindowManager,WindowId,MessageFilter};
static SERIAL:Mutex<()>=Mutex::new(());
static EVENTS:Mutex<Vec<&'static str>>=Mutex::new(Vec::new());
const OMIT_FLUSH:bool=false;

struct Lock<T>(Mutex<T>);
impl<T> Lock<T>{const fn new(value:T)->Self{Self(Mutex::new(value))}
    fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}
    fn unlocked(&self)->bool{self.0.try_lock().is_ok()}}
struct Wait;
impl Wait{fn wake_all(&self){}}
mod sched{
    use super::*;
    pub mod thread_group{pub struct ThreadGroup;}
    pub struct Task{pub thread_group:Arc<thread_group::ThreadGroup>,pub tid:usize}
    impl Task{pub fn is_nt_personality(&self)->bool{true}}
    thread_local!{pub static CURRENT:RefCell<Option<Arc<Task>>>=const{RefCell::new(None)};}
    pub mod task{#[derive(Eq,PartialEq)]pub enum WaitOutcome{Ready,TimedOut,Interrupted}}
    pub mod nt_callback{pub struct Completion{pub kind:u64,pub argument:u64}}
    pub mod live{
        use super::*;
        pub fn current()->Option<Arc<Task>>{CURRENT.with(|c|c.borrow().clone())}
        pub unsafe fn wait_event_interruptible_until(_: &Arc<Wait>,_:u64,_:impl Fn()->u64,mut ready:impl FnMut()->bool)->task::WaitOutcome{
            assert!(crate::nt_window::GUI.unlocked(),"GetMessage waited with GUI locked");
            assert!(!ready());
            assert!(EVENTS.lock().unwrap().contains(&"frame"),"dirty backing must publish before wait");
            EVENTS.lock().unwrap().push("wait");task::WaitOutcome::Interrupted
        }
    }
}
mod timekeeper{pub fn monotonic_ns()->u64{1_000_000}}
mod input{
    pub fn set_native_key_hook<T>(_:Option<T>){}
    pub fn set_native_rel_hook<T>(_:Option<T>){}
    pub fn set_native_mouse_hook<T>(_:Option<T>){}
}
mod uaccess{
    pub fn copy_to_user(_:u64,_:&[u8])->Result<(),syscall::Errno>{panic!("unexpected output copy")}
    pub fn copy_from_user(_:&mut[u8],_:u64)->Result<(),syscall::Errno>{panic!("unexpected input copy")}
}
mod nt_compositor{
    pub fn monitors_current()->Option<()>{Some(())}
    pub use crate::protocol_fixture::{enqueue_current,submit_current,wait_completion_current,Completion};
}
mod nt_milestone{pub fn desktop_ack(){crate::EVENTS.lock().unwrap().push("ack");}
    pub fn paint_present(){crate::EVENTS.lock().unwrap().push("present");}}
mod nt_rtl{pub fn begin_wndproc_callback_with_completion(_:u64,_:u64,_:u64,_:u64,_:u64,_:crate::sched::nt_callback::Completion)->u64{panic!("unexpected callback")}}
mod nt_gdi{
    use super::*;
    const STATUS_SUCCESS:u64=0;const STATUS_INVALID_HANDLE:u64=0xc0000008;
    pub(super) struct Entry{pub(super) group:Weak<sched::thread_group::ThreadGroup>,pub(super) state:ipc::win32_gdi::GdiManager,output_pump:crate::output::OutputPump}
    pub(super) static GDI:Lock<Vec<Entry>>=Lock::new(Vec::new());
    pub(super) static TRANSPORT:Mutex<Option<fn(&syscall::nt_compositor::Record)->u64>>=Mutex::new(None);
    pub(super) mod output{
        pub(crate) use crate::output::{flush_one,reserve_snapshot,reserve_prepared,PrepareError,PreparedFrame,publish_prepared};
        mod transport{pub(crate) use super::super::submit_frame;}
        pub mod kernel{
            use crate::{sched,timekeeper};
            include!(concat!(env!("CARGO_MANIFEST_DIR"),"/src/nt_gdi/output/kernel.rs"));
        }
    }
    pub fn delete_paint_dc_current(_:u32)->Result<(),()>{panic!("unexpected paint cleanup")}
    pub fn destroy_window_dc_for_current(hwnd:u32){crate::teardown_fixture::destroy_dc(hwnd)}
    pub fn flush_pending_for_current(idle:bool){
        assert!(nt_window::GUI.unlocked(),"flush hook called with GUI locked");
        EVENTS.lock().unwrap().push(if idle{"idle"}else{"busy"});
        if OMIT_FLUSH{return;}
        output::kernel::flush_pending_for_current(idle);
    }
    pub(crate) fn submit_frame(frame:Result<syscall::nt_compositor::Record,u64>)->u64{
        assert!(nt_window::GUI.unlocked());assert!(GDI.unlocked());
        let frame=frame.unwrap();assert!(nt_window::window_rect_for_current(frame.header.hwnd as u32).is_some());
        EVENTS.lock().unwrap().push("frame");
        let transport=*TRANSPORT.lock().unwrap();
        if let Some(transport)=transport{return transport(&frame);}
        assert_eq!(&frame.payload[PIXELS..PIXELS+4],&0xffabcdefu32.to_le_bytes());STATUS_SUCCESS
    }
    pub fn setup(hwnd:u32){let task=sched::live::current().unwrap();let mut state=ipc::win32_gdi::GdiManager::new();
        let dc=state.acquire_window_dc(hwnd,2,2).unwrap();state.write_dc_pixel(dc,0,0,0xabcdef).unwrap();
        let mut entries=GDI.lock();entries.clear();entries.push(Entry{group:Arc::downgrade(&task.thread_group),state,output_pump:Default::default()});}
    pub fn clean()->bool{GDI.lock()[0].state.pending_outputs().unwrap().is_empty()}
    /// A window-sized paint DC and the coverage one paint of it claims.
    pub fn paint_fixture()->(u32,ipc::win32_window::PaintRegion,ipc::win32_gdi::PaintBacking){
        let mut entries=GDI.lock();let state=&mut entries[0].state;
        let token=state.pending_outputs().unwrap()[0];
        let rect=ipc::win32_gdi::Rect{left:0,top:0,right:2,bottom:2};
        (token.hwnd,ipc::win32_window::PaintRegion::from_rect(ipc::win32_window::WindowRect{left:0,top:0,right:2,bottom:2}).unwrap(),
            ipc::win32_gdi::PaintBacking{width:2,height:2,client:rect})
    }
    /// One paint: merge its coverage into the backing, then ask the pump for a
    /// rate-limited flush, exactly as the paint end does.
    pub fn merge_paint(hwnd:u32,region:&ipc::win32_window::PaintRegion,layout:ipc::win32_gdi::PaintBacking)->Result<(),u64>{
        {
            let mut entries=GDI.lock();let state=&mut entries[0].state;
            let dc=state.create_dc(2,2).unwrap();
            state.fill_rect(dc,ipc::win32_gdi::Rect{left:0,top:0,right:2,bottom:2},0xabcdef).unwrap();
            crate::erase_fixture::paint_frame::merge_region(state,hwnd,dc,region,layout).map_err(|_|1u64)?;
        }
        flush_pending_for_current(false);Ok(())
    }
    pub fn explicit_publish()->u64{
        let prepared={let mut entries=GDI.lock();let state=&mut entries[0].state;
            let token=state.pending_outputs().unwrap()[0];let(w,h,pixels)=state.surface(token.dc).unwrap();
            let record=crate::nt_gdi_frame::snapshot(token.hwnd,1,w,h,pixels,whole(w,h)).unwrap();
            crate::output::reserve_captured(state,token.hwnd,token.dc,record).unwrap()};
        output::kernel::submit_prepared_for_current(Ok(prepared))
    }
}
mod nt_window{
    use super::*;
    const STATUS_SUCCESS:u64=0;pub(super) const STATUS_INVALID_PARAMETER:u64=0xc000000d;const STATUS_INVALID_HANDLE:u64=0xc0000008;
    const STATUS_ACCESS_DENIED:u64=0xc0000022;pub const STATUS_NO_MORE_ENTRIES:u64=0x8000001a;
    const STATUS_QUOTA_EXCEEDED:u64=0xc0000044;pub const STATUS_ALERTED:u64=0x101;
    const STATUS_PENDING:u64=0x103;const STATUS_NOT_SUPPORTED:u64=0xc00000bb;const WM_DESTROY:u64=2;const CALLBACK_DESTROY:u64=1;
    struct Cleanup;
    impl Cleanup{fn cancel_window<T>(&mut self,_:T){}fn cancel_root(&mut self,_:u64){}fn holds_dc(&self,_:u32)->bool{false}fn has_for_tid(&self,_:u64)->bool{false}fn release_property_atom<T>(&mut self,_:T){}}
    struct Remote;impl Remote{fn targets(&self,_:u64)->bool{false}}
    pub(super) struct Entry{pub(super) group:Weak<sched::thread_group::ThreadGroup>,pub(super) state:WindowManager,wait:Arc<Wait>,foreground:bool,
        redraw:Cleanup,scroll_pending:Cleanup,paint_callbacks:Cleanup,remote_positions:Vec<Remote>,sent:Cleanup}
    pub(super) static GUI:Lock<Vec<Entry>>=Lock::new(Vec::new());
    static USER_ATOMS:Lock<Cleanup>=Lock::new(Cleanup);
    fn new_entry(group:&Arc<sched::thread_group::ThreadGroup>)->Entry{Entry{group:Arc::downgrade(group),state:WindowManager::new(),
        wait:Arc::new(Wait),foreground:false,redraw:Cleanup,scroll_pending:Cleanup,paint_callbacks:Cleanup,remote_positions:Vec::new(),sent:Cleanup}}
    mod owner{use super::*;
        /// The production entry lookup, which keeps the whole `GuiEntry`
        /// temporary out of the dispatcher's own frame.
        pub(super) fn entry_index(entries:&mut Vec<Entry>,group:&Arc<sched::thread_group::ThreadGroup>)->usize{
            entries.retain(|entry|entry.group.upgrade().is_some());
            if let Some(index)=entries.iter().position(|entry|entry.group.upgrade().is_some_and(|candidate|Arc::ptr_eq(&candidate,group))){return index;}
            entries.push(new_entry(group));entries.len()-1}}
    fn route_hardware_key(){}fn route_hardware_rel(){}fn route_hardware_mouse(){}
    fn callback_argument(_:u64,_:usize)->u64{0}
    fn valid_window(hwnd:u64)->Option<WindowId>{u32::try_from(hwnd).ok().and_then(WindowId::from_raw)}
    fn message_filter(state:&WindowManager,hwnd:u64,first:u32,last:u32)->Option<MessageFilter>{
        let hwnd=u32::try_from(hwnd).ok().and_then(WindowId::from_raw);state.validate_message_filter(hwnd).ok()?;Some(MessageFilter{hwnd,first,last})}
    fn copy_message(_:syscall::UserPtr<NtWindowMessage>,message:ipc::win32_window::WinMessage)->Result<(),syscall::Errno>{if crate::retrieval_status_fixture::copy(message){Ok(())}else{crate::hardware_view_fixture::copy(message)}}
    fn copy_rect(_:syscall::UserPtr<nt::NtWindowRect>,_:ipc::win32_window::WindowRect)->u64{panic!("unexpected rect")}
    fn read_rect(_:syscall::UserPtr<nt::NtWindowRect>)->Option<ipc::win32_window::WindowRect>{panic!("unexpected rect input")}
    struct CreateStructArgs;impl CreateStructArgs{fn empty(_:u64)->Self{Self}}
    enum CreateReturnConvention{NativeStatus}
    mod create{use super::*;pub(super) fn begin_create_lifecycle_for_current(_:u64,_:CreateStructArgs,_:CreateReturnConvention)->u64{panic!("unexpected create")}}
    mod control_color{pub fn for_current(_:u32,_:u64)->Option<u64>{None}}
    mod erase_background{pub mod kernel{pub fn for_current(_:u32,_:u64,_:u64)->Option<u64>{None}}}
    mod desktop{pub fn resolve_for_current()->Option<u32>{Some(crate::set_cursor_fixture::desktop())}}
    mod default_paint{pub fn for_current(_:u64)->u64{0}}
    mod retrieval{pub fn pump(_:super::NtCall,_:bool)->Option<u64>{crate::retrieval_status_fixture::pump()}}
    pub(super) mod paint{
        pub fn begin(_:u64,_:syscall::UserPtr<syscall::nt::NtWindowRect>)->u64{panic!("unexpected paint")}
        pub fn backing_for_current(hwnd:u32)->Option<ipc::win32_gdi::PaintBacking>{
            assert!(crate::nt_gdi::GDI.unlocked());
            let(bounds,_)=super::window_rect_for_current(hwnd)?;
            let(width,height)=(bounds.right-bounds.left,bounds.bottom-bounds.top);
            Some(ipc::win32_gdi::PaintBacking{width,height,client:ipc::win32_gdi::Rect{left:0,top:0,right:width,bottom:height}})
        }
    }
    mod caret{pub mod blink{pub fn expire_for_current(_:u64)->u64{0}pub fn retrieval_deadline_for_current()->Option<u64>{None}}}
    mod paint_cleanup{pub fn window_for_current(_:u64){}}
    // The pump profile reports to the console, which this fixture has none of.
    mod pump_profile{pub fn note_retrieval(){}}
    mod send{pub fn cancel_window<T>(_:&T,_:u64){} pub(super) use crate::mouse_activate_fixture::{Continuation,SendOutcome,send_resumable_current};}
    pub(crate) use crate::position_fixture as position;
    mod nonclient_frame {
        pub fn nc_paint_for_current(_:u64)->Option<u64>{panic!("nonclient paint not covered by this fixture")}
        pub fn nc_calc_size_for_current(_:u64,_:u64)->Option<u64>{panic!("nonclient layout not covered by this fixture")}
    }
    mod menu_raw{pub mod bar{
        pub fn nc_paint_for_current(_:u64)->Option<u64>{None}
        pub fn nc_calc_size_for_current(_:u64,_:u64)->Option<u64>{None}
        pub fn hit_test_for_current(_:u64,_:i64)->Option<i16>{None}
        pub fn default_proc_for_current(_:u64,_:u32,_:u64,_:i64)->Option<u64>{None}}}
    pub(super) mod hardware{
        mod delivery {
            use crate::{sched, timekeeper};
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/nt_window/hardware/delivery.rs"));
        }
        pub(crate) use delivery::{deliver_for_current, note_get};
        #[derive(Clone,Copy,Debug,Eq,PartialEq)]pub struct Selected{pub id:u64,pub message:ipc::win32_window::WinMessage}
        #[derive(Clone,Debug,Eq,PartialEq)]pub enum Stage{Ready,Drained(u64),Next(u64),Again,Pending(u64),Prepared(Box<Selected>)}
        pub fn process_for_current(_:super::NtCall,_:bool,_:syscall::nt::NtWindowCall)->Stage{crate::hardware_view_fixture::stage()}}
    mod bridge{pub fn publish_destroy_current(hwnd:u64)->Result<(),()>{crate::teardown_fixture::publish(hwnd)}pub fn publish_visibility_current(_:u64)->Result<(),()>{Ok(())}
        pub fn publish_title_current(_:u64)->Result<(),()>{Ok(())}pub fn publish_geometry_current(_:u64)->Result<(),()>{Ok(())}}
    // Visibility publication for a show goes through the show projection.
    mod show_order{pub fn publish_for_current(_:u64,_:u64,_:bool)->Result<(),()>{Ok(())}}
    pub mod production{include!(concat!(env!("CARGO_MANIFEST_DIR"),"/src/nt_window/dispatch.rs"));}
    pub(super) fn setup()->u32{let task=sched::live::current().unwrap();let mut entry=new_entry(&task.thread_group);
        let hwnd=entry.state.create(task.tid as u64,None,0).unwrap();
        entry.state.set_rect(hwnd,ipc::win32_window::WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
        entry.state.set_visible(hwnd,true).unwrap();
        let mut entries=GUI.lock();entries.clear();entries.push(entry);hwnd.raw()}
    pub fn window_rect_for_current(hwnd:u32)->Option<(ipc::win32_window::WindowRect,bool)>{
        let task=sched::live::current()?;let entries=GUI.lock();let entry=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&task.thread_group)))?;
        let hwnd=WindowId::from_raw(hwnd)?;Some((entry.state.rect(hwnd)?,entry.state.get(hwnd)?.visible))}
    pub(super) fn deliver_test_event(hwnd:u32){
        let mut entries=GUI.lock();
        crate::protocol_fixture::deliver_gui_event(&mut entries[0].state,hwnd);
    }
}
fn setup(){
    *nt_gdi::TRANSPORT.lock().unwrap()=None;
    EVENTS.lock().unwrap().clear();let group=Arc::new(sched::thread_group::ThreadGroup);
    sched::CURRENT.with(|c|*c.borrow_mut()=Some(Arc::new(sched::Task{thread_group:group,tid:41})));
    let hwnd=nt_window::setup();nt_gdi::setup(hwnd);
}
fn call(service:nt::NtService)->NtCall{NtCall{service,args:syscall::SyscallArgs{a0:0x1000,a1:0,a2:0,a3:0,a4:0,a5:0}}}
#[test]
fn actual_empty_peek_flushes_after_gui_unlock_before_return(){
    let _serial=SERIAL.lock().unwrap();setup();
    assert_eq!(nt_window::production::dispatch(call(nt::NtService::PeekMessage)),Some(nt_window::STATUS_NO_MORE_ENTRIES));
    assert_eq!(*EVENTS.lock().unwrap(),["busy","idle","frame","present"]);
    assert!(nt_gdi::clean());
}
#[test]
fn actual_empty_get_flushes_after_gui_unlock_before_wait(){
    let _serial=SERIAL.lock().unwrap();setup();
    assert_eq!(nt_window::production::dispatch(call(nt::NtService::GetMessage)),Some(nt_window::STATUS_ALERTED));
    assert_eq!(*EVENTS.lock().unwrap(),["busy","idle","frame","present","wait"]);
}
#[test]
fn actual_explicit_submit_finishes_reserved_backing_outside_gui_and_gdi_locks(){
    let _serial=SERIAL.lock().unwrap();setup();assert_eq!(nt_gdi::explicit_publish(),0);
    assert_eq!(*EVENTS.lock().unwrap(),["frame"]);assert!(nt_gdi::clean());
}

/// A burst of paints reaches the desktop as one frame. The reference lets
/// drawing accumulate a surface's damage bounds and leaves the flush to the
/// message pump, so the number of frames a burst costs is set by the pump's
/// schedule, not by how many times the application painted.
#[test]
fn actual_a_burst_of_paints_costs_one_frame_not_one_per_paint() {
    let _serial = SERIAL.lock().unwrap(); setup();
    let (hwnd, region, layout) = nt_gdi::paint_fixture();
    for _ in 0..13 { assert_eq!(nt_gdi::merge_paint(hwnd, &region, layout), Ok(())); }
    assert!(!EVENTS.lock().unwrap().iter().any(|event| *event == "frame"),
        "a paint accumulates coverage; it does not hand a frame over");
    assert!(!nt_gdi::clean(), "the burst is owed to the desktop");
    nt_gdi::flush_pending_for_current(true);
    assert_eq!(EVENTS.lock().unwrap().iter().filter(|event| **event == "frame").count(), 1,
        "thirteen paints reach the desktop as one frame");
    assert!(nt_gdi::clean());
}

/// The busy flush a paint asks for is refused inside the grace period after an
/// idle one and allowed outside it, which is what keeps an application that
/// never goes idle from paying a frame per paint while still reaching the
/// screen.
#[test]
fn actual_the_busy_flush_grace_period_bounds_a_never_idle_application() {
    let mut pump = crate::output::OutputPump::default();
    const GRACE_NS: u64 = 50_000_000;
    assert!(pump.allow(true, 1_000), "an idle point always flushes");
    assert!(!pump.allow(false, 1_000 + GRACE_NS - 1), "inside the grace period a paint does not flush");
    assert!(pump.allow(false, 1_000 + GRACE_NS), "outside it, a never-idle application still reaches the screen");
    assert!(pump.allow(false, 1_000 + GRACE_NS * 4), "and keeps reaching it");
    assert!(pump.allow(true, 1_000 + GRACE_NS * 4), "an idle point restarts the period");
    assert!(!pump.allow(false, 1_000 + GRACE_NS * 4 + 1));
}

/// Whole-surface coverage, the damage a fixture with no narrower one sends.
fn whole(width: i32, height: i32) -> syscall::nt_compositor::Damage {
    syscall::nt_compositor::Damage { left: 0, top: 0, right: width, bottom: height }
}

/// First pixel byte of a frame payload, after the extent, format and damage.
const PIXELS: usize = syscall::nt_compositor::FRAME_HEADER_BYTES;
