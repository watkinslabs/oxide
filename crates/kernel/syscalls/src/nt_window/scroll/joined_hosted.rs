//! Joined hosted scroll boundary.
//!
//! This embeds the production raw adapter, live path and concrete sink.  Only
//! the scheduler, user-copy and Curie position callback boundary are hosted.
#![allow(dead_code, unused_imports, unexpected_cfgs)]

extern crate alloc;
extern crate ipc as ipc_types;
extern crate self as ipc;
extern crate self as sched;
extern crate self as uaccess;

pub use ipc_types::win32_gdi;

use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

#[path = "../../../../ipc/src/win32_window.rs"]
pub mod win32_window;

pub mod thread_group { pub struct ThreadGroup; }

pub struct Task { pub tid: u64, pub thread_group: Arc<thread_group::ThreadGroup> }
impl Task { pub fn is_nt_personality(&self) -> bool { true } }

thread_local! {
    static CURRENT: RefCell<Option<&'static Task>> = const { RefCell::new(None) };
    static POSITION: RefCell<Option<PositionWait>> = const { RefCell::new(None) };
    static POSITION_CALLS: Cell<usize> = const { Cell::new(0) };
    static RASTER: RefCell<Vec<(u64, i32, win32_window::ScrollState)>> = const { RefCell::new(Vec::new()) };
    static RASTER_FAIL: Cell<bool> = const { Cell::new(false) };
}

// `setup` replaces the hosted GUI vector, while CURRENT is thread-local. A
// guard must span each complete scenario so parallel libtest workers cannot
// pair one scenario's current task with another scenario's GUI entry.
static TEST_LOCK: Mutex<()> = Mutex::new(());

pub mod live { pub fn current() -> Option<&'static super::Task> { super::CURRENT.with(|c| *c.borrow()) } }

pub fn copy_from_user(dst: &mut [u8], address: u64) -> Result<(), ()> {
    if address == 0 { return Err(()); }
    // Hosted fixture pointers are created by `user_info`; production usercopy
    // remains the real uaccess implementation in the kernel target.
    unsafe { core::ptr::copy_nonoverlapping(address as *const u8, dst.as_mut_ptr(), dst.len()); }
    Ok(())
}

pub fn copy_to_user(address: u64, src: &[u8]) -> Result<(), ()> {
    if address == 0 { return Err(()); }
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), address as *mut u8, src.len()); }
    Ok(())
}

pub(crate) struct Lock<T>(pub(crate) Mutex<T>);
impl<T> Lock<T> {
    pub(crate) fn lock(&self) -> MutexGuard<'_, T> { self.0.lock().unwrap() }
}

pub mod nt_window {
    use super::*;

    pub const STATUS_PENDING: u64 = 0x103;
    pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

    pub struct Wait;
    impl Wait { pub fn wake_all(&self) {} }

    pub(crate) struct GuiEntry {
        pub(crate) group: Weak<thread_group::ThreadGroup>,
        pub(crate) state: win32_window::WindowManager,
        pub(crate) scroll_pending: scroll::pending::Queue,
    }

    pub(crate) static GUI: Lock<Vec<GuiEntry>> = Lock(Mutex::new(Vec::new()));

    pub mod send {
        pub fn send_for_current(_: u64, _: u32, _: u64, _: u64) -> u64 { 0 }
    }

    pub mod position {
        use super::*;
        use ipc::win32_window::WindowRect;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Outcome { Complete(bool), Failed, Pending }
        #[derive(Clone, Copy)]
        pub struct Continuation { pub token: u64, pub resume: fn(u64, Outcome) -> u64 }
        #[derive(Clone, Copy)]
        pub struct Context { pub rect: WindowRect, pub parent: Option<u64>, pub style: u32, pub visible: bool }

        pub fn position_context_for_current(hwnd: u64) -> Option<Context> {
            let task = crate::live::current()?;
            let entries = super::GUI.lock();
            let entry = entries.iter().find(|e| e.group.upgrade().is_some_and(|g| Arc::ptr_eq(&g, &task.thread_group)))?;
            let id = win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
            let record = entry.state.get(id)?;
            Some(Context { rect: entry.state.rect(id)?, parent: record.parent.map(|p| p.raw() as u64), style: record.style, visible: record.visible })
        }

        pub fn position_apply_resumable_for_current(_: crate::nt_wine_window::position::Request, caller: Option<Continuation>) -> Outcome {
            // Curie's hosted position fixture has the real three-stage
            // changing -> NCCALCSIZE -> changed boundary; retain only the
            // caller continuation until its terminal stage.
            POSITION.with(|pending| *pending.borrow_mut() = caller.map(|continuation| PositionWait { continuation, stage: 0 }));
            Outcome::Pending
        }

        pub fn complete_position(outcome: Outcome) -> u64 {
            POSITION.with(|pending| {
                let mut pending = pending.borrow_mut();
                let Some(wait) = pending.as_mut() else { return 0; };
                wait.stage += 1;
                POSITION_CALLS.with(|calls| calls.set(calls.get() + 1));
                if wait.stage < 3 { return super::STATUS_PENDING; }
                let wait = pending.take().unwrap();
                (wait.continuation.resume)(wait.continuation.token, outcome)
            })
        }
    }

    pub(crate) mod scroll {
        #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/scroll/pending.rs"]
        pub(crate) mod pending;
        pub(crate) const SBM_SETSCROLLINFO: u32 = 0x00e9;
        pub(crate) trait ScrollActionSink {
            fn show_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
            fn hide_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
            fn enable_scroll_arrows(&mut self, hwnd: u64, bar: i32) -> bool;
            fn disable_scroll_arrows(&mut self, hwnd: u64, bar: i32) -> bool;
            fn frame_changed(&mut self, hwnd: u64, bar: i32, token: u64) -> pending::Outcome;
            fn repaint_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
            fn send_scrollbar_message(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64>;
        }
        pub(crate) fn consume_actions<S: ScrollActionSink + ?Sized>(
            sink: &mut S, hwnd: u64, bar: i32, info_ptr: u64, redraw: bool,
            outcome: ipc::win32_window::ScrollOutcome, token: Option<u64>,
        ) -> pending::Outcome {
            let action = outcome.action;
            if action.control_message && sink.send_scrollbar_message(hwnd, SBM_SETSCROLLINFO, redraw as u64, info_ptr).is_none() { return pending::Outcome::Failed; }
            if bar == ipc::win32_window::SB_CTL { return pending::Outcome::Complete(0); }
            if action.hide {
                if !sink.hide_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
                let Some(token) = token else { return pending::Outcome::Failed; };
                match sink.frame_changed(hwnd, bar, token) { pending::Outcome::Complete(_) => {}, pending::Outcome::Pending => return pending::Outcome::Pending, pending::Outcome::Failed => return pending::Outcome::Failed }
            }
            if action.show {
                if !sink.show_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
                let Some(token) = token else { return pending::Outcome::Failed; };
                match sink.frame_changed(hwnd, bar, token) { pending::Outcome::Complete(_) => {}, pending::Outcome::Pending => return pending::Outcome::Pending, pending::Outcome::Failed => return pending::Outcome::Failed }
            }
            if action.disable_arrows && !sink.disable_scroll_arrows(hwnd, bar) { return pending::Outcome::Failed; }
            if action.enable_arrows && !sink.enable_scroll_arrows(hwnd, bar) { return pending::Outcome::Failed; }
            if redraw && !action.hide && action.repaint && !sink.repaint_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
            pending::Outcome::Complete(0)
        }
        #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/scroll/raw.rs"]
        pub(crate) mod raw;
        #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/scroll/kernel.rs"]
        pub(crate) mod kernel;
        pub(crate) use kernel::dispatch;
        pub(crate) use raw::{decode_scroll_info, encode_scroll_info, SCROLLINFO_BYTES};
        #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/scroll/live.rs"]
        pub(crate) mod live;
        #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/scroll/sink.rs"]
        pub(crate) mod sink;
    }
}

struct PositionWait { continuation: nt_window::position::Continuation, stage: usize }

pub mod nt_wine_window {
    pub mod position {
        use ipc::win32_window::WindowRect;
        #[derive(Clone, Copy)] pub struct Request { pub hwnd: u64, pub rect: WindowRect, pub order: Option<()>, pub visible: Option<bool>, pub flags: u32 }
    }
}

pub mod nt_gdi {
    use super::*;
    pub fn repaint_nonclient_scroll_for_current(hwnd: u64, bar: i32, state: win32_window::ScrollState) -> bool {
        RASTER.with(|r| r.borrow_mut().push((hwnd, bar, state)));
        !RASTER_FAIL.with(|f| f.get())
    }
}

fn user_info(info: win32_window::ScrollInfo) -> u64 {
    let bytes = nt_window::scroll::encode_scroll_info(info);
    Box::into_raw(Box::new(bytes)) as u64
}

fn current(group: &Arc<thread_group::ThreadGroup>, tid: u64) {
    let task = Box::leak(Box::new(Task { tid, thread_group: Arc::clone(group) }));
    CURRENT.with(|c| *c.borrow_mut() = Some(task));
    POSITION.with(|p| *p.borrow_mut() = None);
    POSITION_CALLS.with(|c| c.set(0));
    RASTER.with(|r| r.borrow_mut().clear());
    RASTER_FAIL.with(|f| f.set(false));
}

fn setup() -> (Arc<thread_group::ThreadGroup>, u64) { setup_with_style(false) }

fn setup_with_style(vertical_style: bool) -> (Arc<thread_group::ThreadGroup>, u64) {
    let group = Arc::new(thread_group::ThreadGroup);
    let mut state = win32_window::WindowManager::new();
    let hwnd = state.create(7, None, 0).unwrap();
    if vertical_style { state.set_window_styles(hwnd, 0x0020_0000, 0).unwrap(); }
    state.set_rect(hwnd, win32_window::WindowRect { left: 0, top: 0, right: 640, bottom: 480 }).unwrap();
    *nt_window::GUI.0.lock().unwrap() = vec![nt_window::GuiEntry {
        group: Arc::downgrade(&group), state, scroll_pending: nt_window::scroll::pending::Queue::default(),
    }];
    current(&group, 7);
    (group, hwnd.raw() as u64)
}

fn set(args: [u64; 4]) -> u64 {
    let result = nt_window::scroll::dispatch(0x1581, args).unwrap();
    result
}

#[test]
fn joined_visible_scroll_runs_raw_state_three_position_callbacks_then_raster_and_saved_result() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (_group, hwnd) = setup();
    let info = user_info(win32_window::ScrollInfo { cb_size: 28, mask: win32_window::SIF_RANGE | win32_window::SIF_PAGE | win32_window::SIF_POS, min: 0, max: 100, page: 10, pos: 90, track_pos: 0 });
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, info, 1]), nt_window::STATUS_PENDING);
    assert_eq!(POSITION_CALLS.with(|c| c.get()), 0);
    assert!(RASTER.with(|r| r.borrow().is_empty()));
    // Curie's changing, NCCALCSIZE and changed callbacks all precede the
    // terminal continuation.
    POSITION.with(|p| assert!(p.borrow().is_some()));
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(POSITION_CALLS.with(|c| c.get()), 1);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(POSITION_CALLS.with(|c| c.get()), 2);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Complete(true)), 90);
    assert_eq!(POSITION_CALLS.with(|c| c.get()), 3);
    assert_eq!(RASTER.with(|r| r.borrow().len()), 1);
}

#[test]
fn joined_hidden_and_no_redraw_complete_without_raster() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (_group, hwnd) = setup_with_style(true);
    {
        let entries = nt_window::GUI.lock();
        let id = win32_window::WindowId::from_raw(hwnd as u32).unwrap();
        assert!(entries[0].state.owned_scroll_state(id, win32_window::SB_VERT).unwrap().visible);
    }
    let hidden = user_info(win32_window::ScrollInfo { cb_size: 28, mask: win32_window::SIF_RANGE | win32_window::SIF_PAGE, min: 0, max: 0, page: 1, pos: 0, track_pos: 0 });
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, hidden, 1]), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Complete(true)), 0);
    assert!(RASTER.with(|r| r.borrow().is_empty()));

    let shown_no_redraw = user_info(win32_window::ScrollInfo { cb_size: 28, mask: win32_window::SIF_RANGE | win32_window::SIF_PAGE, min: 0, max: 100, page: 10, pos: 0, track_pos: 0 });
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, shown_no_redraw, 0]), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Complete(true)), 0);
    assert!(RASTER.with(|r| r.borrow().is_empty()));
}

#[test]
fn joined_foreign_thread_is_allowed_and_deleted_root_never_resumes_saved_result() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (group, hwnd) = setup();
    current(&group, 8);
    let info = user_info(win32_window::ScrollInfo { cb_size: 28, mask: win32_window::SIF_RANGE | win32_window::SIF_PAGE, min: 0, max: 100, page: 10, pos: 0, track_pos: 0 });
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, info, 1]), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Complete(true)), 0);
    assert_eq!(POSITION_CALLS.with(|c| c.get()), 3);

    current(&group, 7);
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, info, 1]), 0);
    assert!(RASTER.with(|r| r.borrow().is_empty()));

    let (_group, hwnd) = setup();
    let info = user_info(win32_window::ScrollInfo { cb_size: 28, mask: win32_window::SIF_RANGE | win32_window::SIF_PAGE, min: 0, max: 100, page: 10, pos: 0, track_pos: 0 });
    assert_eq!(set([hwnd, win32_window::SB_VERT as u64, info, 1]), nt_window::STATUS_PENDING);
    nt_window::GUI.lock()[0].scroll_pending.cancel_root(hwnd);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Pending), nt_window::STATUS_PENDING);
    assert_eq!(nt_window::position::complete_position(nt_window::position::Outcome::Complete(true)), 0);
    assert!(RASTER.with(|r| r.borrow().is_empty()));
}
