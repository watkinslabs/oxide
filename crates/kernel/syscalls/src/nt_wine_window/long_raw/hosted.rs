//! Hosted actual owner + raw adapter; no host windowing or Wine runtime needed.
#![allow(dead_code, unused_imports, unexpected_cfgs)]
extern crate alloc;
extern crate self as ipc;
#[path = "../../../../ipc/src/win32_window.rs"]
pub mod win32_window;
#[path = "../long_raw.rs"]
mod long_raw;
extern crate self as sched;
extern crate self as uaccess;
use long_raw::*;
use std::sync::Arc;

pub struct Task { thread_group: Arc<()> }
impl Task {
    fn is_nt_personality(&self) -> bool { true }
    fn nt_teb(&self) -> u64 { 0x1000 }
}
thread_local! {
    static TASK: Arc<Task> = Arc::new(Task { thread_group: Arc::new(()) });
    static LAST_ERROR: std::cell::Cell<u32> = const { std::cell::Cell::new(77) };
}
pub mod live { pub fn current() -> Option<std::sync::Arc<super::Task>> { Some(super::TASK.with(Clone::clone)) } }
pub fn put_user_u32(address: u64, value: u32) -> Result<(), ()> {
    assert_eq!(address, 0x1068);
    LAST_ERROR.with(|slot| slot.set(value));
    Ok(())
}

mod nt_window {
    use std::sync::{Arc, Weak, Mutex, MutexGuard};
    struct Entry { group: Weak<()>, state: crate::win32_window::WindowManager }
    struct Gui(Mutex<Vec<Entry>>);
    impl Gui { fn lock(&self) -> MutexGuard<'_, Vec<Entry>> { self.0.lock().unwrap() } }
    static GUI: Gui = Gui(Mutex::new(Vec::new()));
    fn valid_window(hwnd: u64) -> Option<crate::win32_window::WindowId> {
        crate::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)
    }
    #[path = "/home/nd/oxide/kernel/crates/kernel/syscalls/src/nt_window/control.rs"]
    mod control;
    pub(crate) use control::*;
    pub fn prepare() -> u64 {
        let current = crate::live::current().unwrap();
        let mut state = crate::win32_window::WindowManager::new();
        let atom = state.register_class_with_extra(&[69, 68, 73, 84], 0x1000, 8).unwrap();
        let hwnd = state.create_class_atom(7, None, atom).unwrap();
        GUI.lock().push(Entry { group: Arc::downgrade(&current.thread_group), state });
        hwnd.raw() as u64
    }
    pub fn unicode(hwnd: u64) -> bool {
        let current = crate::live::current().unwrap();
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).unwrap();
        entry.state.get(valid_window(hwnd).unwrap()).unwrap().unicode
    }
}
#[path = "kernel.rs"]
mod live_adapter;

#[test]
fn kernel_long_adapter_actual_control_wrapper_and_teb_error_write() {
    let hwnd = nt_window::prepare();
    LAST_ERROR.with(|slot| slot.set(77));
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, 0, 0x7f65_1234_5678, 0]), Some(0));
    assert_eq!(live_adapter::get(hwnd, 0, 8), 0x7f65_1234_5678);
    assert_eq!(LAST_ERROR.with(|slot| slot.get()), 77);
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, 1, 0, 0]), Some(0));
    assert_eq!(LAST_ERROR.with(|slot| slot.get()), 1413);
    assert_eq!(live_adapter::get(hwnd, 0, 8), 0x7f65_1234_5678);
    assert_eq!(live_adapter::get(hwnd | (1 << 32), 0, 8), 0);
    assert_eq!(LAST_ERROR.with(|slot| slot.get()), 1400);
}

#[test]
fn kernel_long_adapter_unclaimed_and_style_failure_do_not_mutate() {
    let hwnd = nt_window::prepare();
    LAST_ERROR.with(|slot| slot.set(77));
    assert_eq!(live_adapter::dispatch(0, [hwnd, 0, 9, 0]), None);
    assert_eq!(LAST_ERROR.with(|slot| slot.get()), 77);
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, (-16i32) as u64, u64::MAX, 0]), Some(0));
    assert_eq!(LAST_ERROR.with(|slot| slot.get()), 120);
    assert_eq!(live_adapter::get(hwnd, -16, 8), 0);
}

#[test]
fn kernel_long_adapter_procedure_encoding_changes_atomically() {
    let hwnd = nt_window::prepare();
    assert!(nt_window::unicode(hwnd));
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, (-4i32) as u64, 0x2000, 1]), Some(0x1000));
    assert!(!nt_window::unicode(hwnd));
    assert_eq!(live_adapter::get(hwnd, -4, 8), 0x2000);
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, (-4i32) as u64, 0, 0]), Some(0x2000));
    assert!(!nt_window::unicode(hwnd));
    assert_eq!(live_adapter::dispatch(SET_PTR, [hwnd, (-4i32) as u64, 0x3000, 0]), Some(0x2000));
    assert!(nt_window::unicode(hwnd));
}
