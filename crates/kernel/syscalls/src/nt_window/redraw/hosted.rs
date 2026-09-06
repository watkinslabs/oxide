//! Hosted execution of the actual redraw continuation with canonical paint state.
#![allow(dead_code, unused_imports, unexpected_cfgs)]
extern crate alloc;
extern crate self as ipc;
extern crate self as sched;
extern crate self as uaccess;
#[path = "../../../../ipc/src/win32_gdi.rs"] pub mod win32_gdi;
pub fn copy_from_user(_: &mut [u8], _: u64) -> Result<(), ()> { Err(()) }
mod nt_gdi { pub fn region_snapshot_for_current(_: u64) -> Result<crate::win32_window::PaintRegion, ()> { Err(()) } }
#[path = "../../../../ipc/src/win32_window.rs"]
pub mod win32_window;
use std::sync::{Arc, Weak, Mutex, MutexGuard};
const STATUS_PENDING: u64 = 0x103;
pub struct Task { tid: u32, thread_group: Arc<()> }
impl Task { fn is_nt_personality(&self) -> bool { true } }
thread_local! { static TASK: Arc<Task> = Arc::new(Task { tid: 7, thread_group: Arc::new(()) }); }
pub mod live { pub fn current() -> Option<Arc<super::Task>> { Some(super::TASK.with(Clone::clone)) } use std::sync::Arc; }
struct Entry { group: Weak<()>, state: win32_window::WindowManager, redraw: redraw::Queue }
struct Gui(Mutex<Vec<Entry>>);
impl Gui { fn lock(&self) -> MutexGuard<'_, Vec<Entry>> { self.0.lock().unwrap() } }
static GUI: Gui = Gui(Mutex::new(Vec::new()));
static TEST_LOCK: Mutex<()> = Mutex::new(());
#[path = "."]
mod redraw {
    use ipc::win32_window::WindowId;
    #[path = "../redraw.rs"]
    mod policy;
    pub(crate) use policy::*;
    #[path = "live.rs"]
    mod live;
    pub(crate) use live::{for_current, resume};
    pub(crate) mod erase {
        pub(crate) fn begin_for_current(_:u32,_:u64)->u64 { unreachable!("ERASENOW executes in joined_hosted") }
    }
}

mod send {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct Continuation { pub token: u64, pub resume: fn(u64, Result<u64, ()>) -> u64 }
    pub enum SendOutcome { Pending, Complete(u64), Failed }
    thread_local! {
        pub static CALLS: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
        pub static PENDING: std::cell::RefCell<Option<(u64, Continuation)>> = const { std::cell::RefCell::new(None) };
        pub static FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub static IMMEDIATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    pub fn send_resumable_current(hwnd: u64, message: u32, wparam: u64, lparam: u64, continuation: Continuation) -> SendOutcome {
        assert_eq!((message, wparam, lparam), (15, 0, 0));
        assert!(GUI.0.try_lock().is_ok(), "GUI held across Send");
        if FAIL.with(|v| v.get()) { return SendOutcome::Failed; }
        CALLS.with(|v| v.borrow_mut().push(hwnd));
        if IMMEDIATE.with(|v| v.get()) {
            with_entry(|e| { let id = win32_window::WindowId::from_raw(hwnd as u32).unwrap(); e.state.begin_paint(id).unwrap(); e.state.end_paint(id).unwrap(); });
            return SendOutcome::Complete(0);
        }
        PENDING.with(|v| { assert!(v.borrow().is_none()); *v.borrow_mut() = Some((hwnd, continuation)); });
        SendOutcome::Pending
    }
    pub fn complete(result: Result<u64, ()>) -> u64 {
        let (hwnd, continuation) = PENDING.with(|v| v.borrow_mut().take().unwrap());
        if result.is_ok() {
            with_entry(|e| { let id = win32_window::WindowId::from_raw(hwnd as u32).unwrap(); e.state.begin_paint(id).unwrap(); e.state.end_paint(id).unwrap(); });
        }
        (continuation.resume)(continuation.token, result)
    }
}
fn with_entry<R>(f: impl FnOnce(&mut Entry) -> R) -> R {
    let task = live::current().unwrap(); let mut entries = GUI.lock();
    f(entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&task.thread_group))).unwrap())
}
fn prepare() -> (u64, u64) {
    let task = live::current().unwrap();
    let mut state = win32_window::WindowManager::new();
    let root = state.create(7, None, 0x1000).unwrap();
    let child = state.create(7, Some(root), 0x2000).unwrap();
    for window in [root, child] {
        state.set_visible(window, true).unwrap();
        state.set_rect(window, win32_window::WindowRect { left: 0, top: 0, right: 10, bottom: 10 }).unwrap();
        state.invalidate(window, None).unwrap();
    }
    GUI.lock().push(Entry { group: Arc::downgrade(&task.thread_group), state, redraw: redraw::Queue::new() });
    (root.raw() as u64, child.raw() as u64)
}

#[test]
fn redraw_live_completes_root_and_child_before_bool_success() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (root, child) = prepare();
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), STATUS_PENDING);
    assert_eq!(send::CALLS.with(|v| v.borrow().clone()), [root]);
    assert_eq!(send::complete(Ok(0)), STATUS_PENDING);
    assert_eq!(send::CALLS.with(|v| v.borrow().clone()), [root, child]);
    assert_eq!(send::complete(Ok(u64::MAX)), 1);
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), 1);
}

#[test]
fn redraw_live_send_failure_and_callback_cancellation_are_false() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (root, _) = prepare();
    send::FAIL.with(|v| v.set(true));
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), 0);
    send::FAIL.with(|v| v.set(false));
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), STATUS_PENDING);
    assert_eq!(send::complete(Err(())), 0);
    assert_eq!(redraw::for_current(root, 0, 0, 0x140), STATUS_PENDING);
    assert_eq!(send::complete(Ok(0)), 1);
}

#[test]
fn redraw_live_immediate_zero_result_is_success_not_failure() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (root, child) = prepare();
    send::IMMEDIATE.with(|v| v.set(true));
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), 1);
    assert_eq!(send::CALLS.with(|v| v.borrow().clone()), [root, child]);
}

#[test]
fn redraw_live_nested_update_retains_outer_continuation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (root, _) = prepare();
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), STATUS_PENDING);
    // The outer WndProc is executing and invokes another UpdateWindow.
    let (_, outer) = send::PENDING.with(|v| v.borrow_mut().take().unwrap());
    assert_eq!(redraw::for_current(root, 0, 0, 0x180), STATUS_PENDING);
    assert_eq!(send::complete(Ok(0)), STATUS_PENDING);
    assert_eq!(send::complete(Ok(0)), 1);
    assert_eq!((outer.resume)(outer.token, Ok(0)), 1);
    assert_eq!((outer.resume)(outer.token, Ok(0)), 0);
}
