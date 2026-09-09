use std::sync::{Arc, Weak, Mutex, MutexGuard};
use std::cell::RefCell;
use ipc::win32_window::{WindowManager, WindowId, MessageFilter, WinMessage};
use ipc::win32_window::hardware::{ClickRecord, ProcCall};
use syscall::nt::{NtCall, NtWindowCall};
static SERIAL: Mutex<()> = Mutex::new(());
static CALLS: Mutex<Vec<ProcCall>> = Mutex::new(Vec::new());
static SUSPEND: Mutex<bool> = Mutex::new(false);
static CALLBACK: Mutex<Option<(nt_window::send::Continuation, u64)>> = Mutex::new(None);
static RESUMED: Mutex<Option<nt_window::hardware::Stage>> = Mutex::new(None);
static HITS: Mutex<Vec<(u32, i32)>> = Mutex::new(Vec::new());
struct Lock<T>(Mutex<T>);
impl<T> Lock<T> {
    const fn new(value: T) -> Self { Self(Mutex::new(value)) }
    fn lock(&self) -> MutexGuard<'_, T> { self.0.lock().unwrap() }
    fn unlocked(&self) -> bool { self.0.try_lock().is_ok() }
}
struct Wait;
impl Wait { fn wake_all(&self) {} }
pub struct ThreadGroup;
pub struct Task { pub tid: usize, pub thread_group: Arc<ThreadGroup> }
impl Task { pub fn is_nt_personality(&self) -> bool { true } }
thread_local! { static CURRENT: RefCell<Option<Arc<Task>>> = const { RefCell::new(None) }; }
pub mod live {
    pub fn current() -> Option<std::sync::Arc<crate::Task>> { crate::CURRENT.with(|value| value.borrow().clone()) }
}
pub fn monotonic_ns() -> u64 { 1_000_000 }

#[path = "../../src/nt_window"]
mod nt_window {
    use super::*;
    pub const STATUS_PENDING: u64 = 0x103;
    pub struct GuiEntry {
        pub group: Weak<ThreadGroup>, pub state: WindowManager, pub wait: Arc<Wait>, pub foreground: bool,
        pub hardware: Option<hardware::PendingHardware>, pub last_click: Option<ClickRecord>, pub menu_tracking: Option<()>,
    }
    pub static GUI: Lock<Vec<GuiEntry>> = Lock::new(Vec::new());
    pub static USER_SETTINGS: Lock<ipc::win32_window::UserSettings> = Lock::new(ipc::win32_window::UserSettings::new());
    pub fn message_filter(_: &WindowManager, hwnd: u64, first: u32, last: u32) -> Option<MessageFilter> {
        assert_eq!(hwnd, 0, "HWND filter admission is outside this fixture");
        Some(MessageFilter { hwnd: None, first, last })
    }
    pub fn resume_position_message_current() -> u64 {
        retrieval::drop_saved();
        *RESUMED.lock().unwrap() = Some(peek_mouse(false));
        0x777
    }
    pub mod retrieval {
        use super::*;
        static SAVED: Mutex<bool> = Mutex::new(false);
        pub fn save(_: NtCall, _: bool) -> bool {
            let mut saved = SAVED.lock().unwrap(); assert!(!*saved); *saved = true; true
        }
        pub fn drop_saved() -> Option<()> {
            let mut saved = SAVED.lock().unwrap(); assert!(*saved); *saved = false; Some(())
        }
    }
    #[path = "send/reply.rs"]
    mod reply;
    pub mod send {
        use super::*;
        pub(crate) use super::reply::{Continuation, SendOutcome};
        pub fn send_resumable_current(hwnd: u64, message: u32, wparam: u64, lparam: u64, continuation: Continuation) -> SendOutcome {
            assert!(GUI.unlocked(), "user procedure called with GUI locked");
            CALLS.lock().unwrap().push(ProcCall { hwnd: hwnd as u32, message, wparam, lparam: lparam as i64 });
            let value = if message == ipc::win32_window::WM_NCHITTEST {
                HITS.lock().unwrap().iter().find(|(id, _)| *id == hwnd as u32).expect("missing declared hit-test reply").1 as i64 as u64
            } else { 0 };
            if *SUSPEND.lock().unwrap() {
                assert!(CALLBACK.lock().unwrap().replace((continuation, value)).is_none());
                SendOutcome::Pending
            } else { SendOutcome::Complete(value) }
        }
    }
    #[path = "hardware"]
    pub mod hardware {
        #[path = "trace_off.rs"]
        mod trace;
        #[path = "context.rs"]
        mod context;
        #[path = "live.rs"]
        mod live;
        pub(crate) use live::{process_for_current, PendingHardware, Stage};
    }
}
fn setup() {
    let task = Arc::new(Task { tid: 41, thread_group: Arc::new(ThreadGroup) });
    CURRENT.with(|current| *current.borrow_mut() = Some(task.clone()));
    let mut entries = nt_window::GUI.lock();
    entries.clear();
    entries.push(nt_window::GuiEntry { group: Arc::downgrade(&task.thread_group), state: WindowManager::new(),
        wait: Arc::new(Wait), foreground: true, hardware: None, last_click: None, menu_tracking: None });
    CALLS.lock().unwrap().clear(); HITS.lock().unwrap().clear();
    *SUSPEND.lock().unwrap() = false;
    *CALLBACK.lock().unwrap() = None;
    *RESUMED.lock().unwrap() = None;
}
fn window(parent: Option<WindowId>, rect: (i32, i32, i32, i32), hit: i32) -> WindowId {
    use ipc::win32_window::{WindowRect, styles::{WS_CHILD, WS_VISIBLE}};
    let mut entries = nt_window::GUI.lock();
    let state = &mut entries[0].state;
    let id = state.create(41, parent, 1).unwrap();
    state.set_style_bits(id, WS_VISIBLE | if parent.is_some() { WS_CHILD } else { 0 }, 0).unwrap();
    state.set_rect(id, WindowRect { left: rect.0, top: rect.1, right: rect.2, bottom: rect.3 }).unwrap();
    HITS.lock().unwrap().push((id.raw(), hit));
    id
}
fn peek_mouse(remove: bool) -> nt_window::hardware::Stage {
    peek_range(remove, ipc::win32_window::WM_LBUTTONDOWN, ipc::win32_window::WM_LBUTTONDOWN)
}
fn peek_range(remove: bool, first: u32, last: u32) -> nt_window::hardware::Stage {
    let request = NtCall { service: syscall::nt::NtService::PeekMessage,
        args: syscall::SyscallArgs { a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } };
    let operation = NtWindowCall::Peek { message: syscall::UserPtr::new(0x1000).unwrap(), hwnd: 0,
        first, last, remove: u32::from(remove) };
    nt_window::hardware::process_for_current(request, false, operation)
}
fn queued_button() -> WinMessage {
    nt_window::GUI.lock()[0].state.peek_for_thread(41,
        MessageFilter { hwnd: None, first: ipc::win32_window::WM_LBUTTONDOWN,
            last: ipc::win32_window::WM_LBUTTONDOWN }, false).unwrap()
}

fn complete_callback() -> nt_window::hardware::Stage {
    let (continuation, value) = CALLBACK.lock().unwrap().take().expect("no pending callback");
    assert_eq!((continuation.resume)(continuation.token, Ok(value)), 0x777);
    RESUMED.lock().unwrap().take().expect("callback did not resume retrieval")
}

fn raw_button(window: WindowId, x: i32, y: i32) {
    let message = WinMessage { hwnd: Some(window), message: ipc::win32_window::WM_LBUTTONDOWN,
        wparam: 1, lparam: ipc::win32_window::hardware::make_point(x, y) };
    nt_window::GUI.lock()[0].state.post_input_to_window(window, message).unwrap();
}
