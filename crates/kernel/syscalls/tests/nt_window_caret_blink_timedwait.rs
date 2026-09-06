//! Hosted execution of the production caret live/blink wrappers.
//!
//! The included production children are exercised against a real canonical
//! `ipc::WindowManager`. Only the kernel-owned current-task, GUI lock,
//! monotonic clock and compositor publication seams are hosted here.

extern crate alloc;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, Weak};

mod sched {
    use super::*;
    pub mod thread_group { pub struct ThreadGroup; }
    pub struct Task { pub thread_group: Arc<thread_group::ThreadGroup>, pub tid: usize, pub nt: bool }
    impl Task { pub fn is_nt_personality(&self) -> bool { self.nt } }
    thread_local! { static CURRENT: RefCell<Option<&'static Task>> = const { RefCell::new(None) }; }
    pub fn install(task: &'static Task) { CURRENT.with(|slot| *slot.borrow_mut() = Some(task)); }
    pub mod live { use super::*; pub fn current() -> Option<&'static Task> { CURRENT.with(|slot| *slot.borrow()) } }
}

mod timekeeper {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(1_000_000);
    pub fn set(value: u64) { NOW.store(value, Ordering::Relaxed); }
    pub fn monotonic_ns() -> u64 { NOW.load(Ordering::Relaxed) }
}

mod nt_window {
    use super::*;
    pub struct HostedLock<T>(Mutex<T>);
    impl<T> HostedLock<T> {
        pub const fn new(value: T) -> Self { Self(Mutex::new(value)) }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() }
    }
    pub struct GuiEntry { pub group: Weak<sched::thread_group::ThreadGroup>, pub state: ipc::win32_window::WindowManager }
    pub static GUI: HostedLock<Vec<GuiEntry>> = HostedLock::new(Vec::new());
    pub static USER_SETTINGS: HostedLock<ipc::win32_window::UserSettings> = HostedLock::new(ipc::win32_window::UserSettings::new());
    pub mod settings { include!("../src/nt_window/settings.rs"); use crate::sched; }

    pub mod caret {
        use super::*;
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        pub struct CaretPos { pub x: i32, pub y: i32 }
        pub const CREATE_CARET_ORDINAL: u64 = 0x1360;
        pub const DESTROY_CARET_ORDINAL: u64 = 0x137e;
        pub const HIDE_CARET_ORDINAL: u64 = 0x146c;
        pub const SET_CARET_POS_ORDINAL: u64 = 0x153c;
        pub const SHOW_CARET_ORDINAL: u64 = 0x15b7;
        pub trait CaretRenderSink {
            fn erase_caret_pixels(&mut self, owner_tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool;
            fn paint_caret_pixels(&mut self, owner_tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool;
        }
        pub fn publish_transition<S: CaretRenderSink + ?Sized>(sink: &mut S, tid: u64, transition: ipc::win32_window::CaretTransition, generation: u64) -> bool {
            let hwnd = transition.hwnd.map(|value| value.raw() as u64).unwrap_or(0);
            let old_hwnd = transition.old_hwnd.map(|value| value.raw() as u64).unwrap_or(0);
            if transition.old_visible && !sink.erase_caret_pixels(tid, old_hwnd, transition.old_rect, generation) { return false; }
            if transition.new_visible && !sink.paint_caret_pixels(tid, hwnd, transition.new_rect, generation) { return false; }
            true
        }
        pub mod publish {
            use super::*;
            pub struct Current;
            impl CaretRenderSink for Current {
                fn erase_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool { super::record(false, tid, hwnd, rect, generation); true }
                fn paint_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool { super::record(true, tid, hwnd, rect, generation); true }
            }
        }
        thread_local! { static PUBLISHED: RefCell<Vec<(bool, u64, u64, (i32, i32, i32, i32), u64)>> = const { RefCell::new(Vec::new()) }; }
        fn record(paint: bool, tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) { PUBLISHED.with(|events| events.borrow_mut().push((paint, tid, hwnd, rect, generation))); }
        pub fn published() -> Vec<(bool, u64, u64, (i32, i32, i32, i32), u64)> { PUBLISHED.with(|events| events.borrow().clone()) }
        pub fn clear_published() { PUBLISHED.with(|events| events.borrow_mut().clear()); }

        pub mod live {
            include!("../src/nt_window/caret/live.rs");
            use crate::sched;
            use crate::timekeeper;
        }
        pub mod blink_impl {
            include!("../src/nt_window/caret/blink.rs");
            use crate::sched;
        }
        pub mod paint_impl { include!("../src/nt_window/caret/paint.rs"); }
        pub mod query { include!("../src/nt_window/caret/query.rs"); use crate::sched; }
    }
}

mod raw_impl { include!("../src/nt_wine_window/caret_raw.rs"); }

use ipc::win32_window::{MessageFilter, WindowId, WindowManager, WM_TIMER};
use nt_window::caret::{blink_impl, live, paint_impl, query, CaretRenderSink};

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct Sink { events: Vec<(bool, u64, u64, (i32, i32, i32, i32), u64)> }
impl CaretRenderSink for Sink {
    fn erase_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool { self.events.push((false, tid, hwnd, rect, generation)); true }
    fn paint_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool { self.events.push((true, tid, hwnd, rect, generation)); true }
}

fn setup() -> (u64, WindowId, &'static sched::Task) {
    let group = Arc::new(sched::thread_group::ThreadGroup);
    let task = Box::leak(Box::new(sched::Task { thread_group: Arc::clone(&group), tid: 41, nt: true }));
    sched::install(task);
    let mut manager = WindowManager::new();
    let window = manager.create(task.tid as u64, None, 0).unwrap();
    let mut entries = nt_window::GUI.lock();
    entries.clear();
    entries.push(nt_window::GuiEntry { group: Arc::downgrade(&group), state: manager });
    *nt_window::USER_SETTINGS.lock() = ipc::win32_window::UserSettings::new();
    nt_window::caret::clear_published();
    (task.tid as u64, window, task)
}

#[test]
fn production_live_show_same_position_expire_publish_and_show_again() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (tid, window, _) = setup();
    timekeeper::set(1_000_000);
    let mut sink = Sink { events: Vec::new() };
    assert_eq!(live::create_caret_for_current(window.raw() as u64, 2, 16, &mut sink), 1);
    assert_eq!(live::set_caret_pos_for_current(3, 4, &mut sink), 1);
    assert_eq!(query::position_for_current(), Some(nt_window::caret::CaretPos { x: 3, y: 4 }));
    let mut copied = None;
    assert_eq!(raw_impl::get_caret_pos(0x2000, |address, bytes| { copied = Some((address, bytes)); true }), Some(1));
    assert_eq!(copied.map(|(_, bytes)| (i32::from_le_bytes(bytes[0..4].try_into().unwrap()), i32::from_le_bytes(bytes[4..8].try_into().unwrap()))), Some((3, 4)));
    assert_eq!(live::show_caret_for_current(window.raw() as u64, &mut sink), 1);
    let deadline = blink_impl::deadline_for_current().expect("show arms caret deadline");
    assert_eq!(live::show_caret_for_current(window.raw() as u64, &mut sink), 1);
    assert_eq!(blink_impl::deadline_for_current(), Some(deadline));
    assert_eq!(live::set_caret_pos_for_current(3, 4, &mut sink), 1);
    assert_eq!(blink_impl::deadline_for_current(), Some(deadline));
    {
        assert!(nt_window::settings::set_caret_blink_time(750));
    }
    assert_eq!(blink_impl::deadline_for_current(), Some(deadline));
    assert_eq!(live::hide_caret_for_current(window.raw() as u64, &mut sink), 1);
    assert_eq!(live::show_caret_for_current(window.raw() as u64, &mut sink), 1);
    assert_eq!(blink_impl::deadline_for_current(), Some(timekeeper::monotonic_ns() + 750_000_000));
    assert!(paint_impl::begin_for_current(window.raw() as u64));
    assert_eq!(blink_impl::deadline_for_current(), None);
    assert!(paint_impl::end_for_current(window.raw() as u64));
    assert!(blink_impl::deadline_for_current().is_some());
    let deadline = blink_impl::deadline_for_current().unwrap();
    assert_eq!(blink_impl::expire_for_current(deadline), 1);
    let published = nt_window::caret::published();
    assert!(published.iter().any(|event| !event.0 && event.1 == tid && event.2 == window.raw() as u64));
    timekeeper::set(deadline);
    assert_eq!(live::show_caret_for_current(window.raw() as u64, &mut sink), 1);
    assert!(blink_impl::deadline_for_current().is_some_and(|next| next >= deadline));
}

#[test]
fn raw_get_caret_pos_rejects_no_caret_invalid_copyout_and_invalid_hwnd() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (_, window, _) = setup();
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_POS_ORDINAL, [0x2000, 0, 0, 0], |_, _| panic!("copyout on missing caret")), Some(0));
    assert_eq!(live::show_caret_for_current(u64::MAX, &mut Sink { events: Vec::new() }), 0);
    let mut sink = Sink { events: Vec::new() };
    assert_eq!(live::create_caret_for_current(window.raw() as u64, 2, 16, &mut sink), 1);
    assert_eq!(live::set_caret_pos_for_current(9, 11, &mut sink), 1);
    let mut attempted = false;
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_POS_ORDINAL, [0x2000, 0, 0, 0], |_, _| { attempted = true; false }), Some(0));
    assert!(attempted);
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_POS_ORDINAL, [0, 0, 0, 0], |_, _| panic!("zero pointer copyout")), Some(0));
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_POS_ORDINAL, [u64::MAX - 3, 0, 0, 0], |_, _| panic!("overflowing copyout")), Some(0));
}

#[test]
fn production_retrieval_deadline_joins_existing_timer_and_missing_is_unbounded() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (_, window, _) = setup();
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_BLINK_TIME_ORDINAL, [0; 4], |_, _| false), Some(500));
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::SET_CARET_BLINK_TIME_ORDINAL, [750, 0, 0, 0], |_, _| false), Some(1));
    assert_eq!(raw_impl::dispatch_with_copyout(raw_impl::GET_CARET_BLINK_TIME_ORDINAL, [0; 4], |_, _| false), Some(750));
    assert_eq!(blink_impl::retrieval_deadline_for_current(), None);
    let mut sink = Sink { events: Vec::new() };
    assert_eq!(live::create_caret_for_current(window.raw() as u64, 2, 16, &mut sink), 1);
    assert_eq!(live::set_caret_pos_for_current(1, 1, &mut sink), 1);
    assert_eq!(live::show_caret_for_current(window.raw() as u64, &mut sink), 1);
    let caret_deadline = blink_impl::retrieval_deadline_for_current().unwrap();
    assert_eq!(caret_deadline, timekeeper::monotonic_ns() + 750_000_000);
    {
        let mut entries = nt_window::GUI.lock();
        let entry = entries.first_mut().unwrap();
        entry.state.set_timer(41, Some(window), 9, 5, 0, timekeeper::monotonic_ns()).unwrap();
    }
    assert_eq!(blink_impl::retrieval_deadline_for_current(), Some(caret_deadline.min(timekeeper::monotonic_ns() + 5_000_000)));
    let filter = MessageFilter { hwnd: Some(window), first: WM_TIMER, last: WM_TIMER };
    {
        let mut entries = nt_window::GUI.lock();
        let entry = entries.first_mut().unwrap();
        entry.state.expire_timers(u64::MAX);
        assert!(entry.state.peek_for_thread(41, filter, true).is_some());
    }
}
