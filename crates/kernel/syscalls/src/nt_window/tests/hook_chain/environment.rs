//! Scheduler and client execution seams; registry and callback routing are production.
use std::sync::{Mutex, MutexGuard};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
pub const STATUS_PENDING: u64 = 0x103;
pub const CALLBACK_INIT_BUILTIN_CLASSES: u64 = 0x10;
pub struct GuiLockClass;
pub struct Spinlock<T, L>(Mutex<T>, PhantomData<L>);
impl<T, L> Spinlock<T, L> {
    pub const fn new(value: T) -> Self { Self(Mutex::new(value), PhantomData) }
    pub fn lock(&self) -> MutexGuard<'_, T> { self.0.lock().unwrap_or_else(|e| e.into_inner()) }
}
static SERIAL: Mutex<()> = Mutex::new(());
pub static FAIL_CALLBACK: AtomicBool = AtomicBool::new(false);
pub static CALLS: Mutex<Vec<(Vec<u8>, ::sched::nt_callback::Completion)>> = Mutex::new(Vec::new());
pub struct Guard(MutexGuard<'static, ()>);
impl Drop for Guard { fn drop(&mut self) { for tid in 1..10 { crate::families::hook_api::hook_forget_thread(tid); } } }
pub fn reset() -> Guard {
    let guard = Guard(SERIAL.lock().unwrap_or_else(|e| e.into_inner()));
    for tid in 1..10 { crate::families::hook_api::hook_forget_thread(tid); }
    FAIL_CALLBACK.store(false, Ordering::Relaxed);
    CALLS.lock().unwrap().clear(); guard
}
pub struct Task { pub tid: u32, pub thread_group: Group }
pub struct Group;
pub struct Pid { pub tid: u32 }
impl Group { pub fn leader_pid(&self) -> Pid { Pid { tid: 1 } } }
impl Task { pub fn is_nt_personality(&self) -> bool { true } }
static TASK: Task = Task { tid: 1, thread_group: Group };
pub mod sched {
    pub use ::sched::nt_callback;
    pub mod live { pub fn current() -> Option<&'static super::super::Task> { Some(&super::super::TASK) } }
    pub mod registry { pub fn lookup(_: u32) -> Option<&'static super::super::Task> { Some(&super::super::TASK) } }
}
pub mod timekeeper { pub fn monotonic_ns() -> u64 { 123_000_000 } }
pub fn begin_user_callback(index: u32, input: crate::nt_user_callback::Input<'_>, completion: sched::nt_callback::Completion) -> u64 {
    assert_eq!(index, 3);
    let crate::nt_user_callback::Input::Record(bytes) = input;
    CALLS.lock().unwrap().push((bytes.to_vec(), completion));
    if FAIL_CALLBACK.load(Ordering::Relaxed) { 0xc000000d } else { STATUS_PENDING }
}
pub mod send {
    #[derive(Clone, Copy)]
    pub struct Continuation { pub token: u64, pub resume: fn(u64, Result<u64, ()>) -> u64 }
    pub fn handles_callback(_: u64) -> bool { false }
    pub fn complete_callback(_: super::sched::nt_callback::Completion, _: u64) -> u64 { panic!("unexpected Send completion") }
}
pub mod position {
    pub fn handles_callback(_: u64) -> bool { false }
    pub fn complete_position_callback(_: super::sched::nt_callback::Completion, _: u64) -> u64 { panic!("unexpected position completion") }
}
pub mod create { pub fn complete_callback(_: super::sched::nt_callback::Completion, _: u64) -> u64 { panic!("unexpected create completion") } }
pub mod scroll {
    pub mod proc_abi { pub const PAINT_COMPLETION: u64 = 0x80; pub const REFRESH_COMPLETION: u64 = 0x81; }
    pub mod control_paint { pub fn complete_callback(_: super::super::sched::nt_callback::Completion, _: u64) -> u64 { panic!("unexpected paint completion") } }
    pub mod control_refresh { pub fn complete_callback(_: super::super::sched::nt_callback::Completion, _: u64) -> u64 { panic!("unexpected refresh completion") } }
}
