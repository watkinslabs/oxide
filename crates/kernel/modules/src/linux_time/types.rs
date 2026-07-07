use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize};

pub const KPI_HZ: u64 = 100;
pub const NSEC_PER_USEC: u64 = 1_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const MSEC_PER_SEC: u64 = 1_000;
pub const DEFAULT_KTHREAD_NAME: &str = "kthread";

#[repr(C)]
pub struct LinuxHListNode {
    pub next: *mut u8,
    pub pprev: *mut *mut u8,
}

#[repr(C)]
pub struct LinuxListHead {
    pub next: *mut u8,
    pub prev: *mut u8,
}

#[repr(C)]
pub struct LinuxRbNode {
    pub parent_color: usize,
    pub right: *mut u8,
    pub left: *mut u8,
}

#[repr(C)]
pub struct LinuxTimerqueueNode {
    pub node: LinuxRbNode,
    pub expires: i64,
}

#[repr(C)]
pub struct LinuxTimerList {
    pub entry: LinuxHListNode,
    pub expires: u64,
    pub function: Option<extern "C" fn(*mut LinuxTimerList)>,
    pub flags: u32,
}

#[repr(C)]
pub struct LinuxHrtimer {
    pub node: LinuxTimerqueueNode,
    pub softexpires: i64,
    pub function: Option<extern "C" fn(*mut LinuxHrtimer) -> i32>,
    pub base: *mut u8,
    pub state: u8,
    pub is_rel: u8,
    pub is_soft: u8,
    pub is_hard: u8,
}

#[repr(C)]
pub struct LinuxWorkStruct {
    pub data: AtomicUsize,
    pub entry: LinuxListHead,
    pub func: Option<extern "C" fn(*mut LinuxWorkStruct)>,
}

#[repr(C)]
pub struct LinuxWorkqueueStruct {
    pub flags: u32,
    pub max_active: i32,
    pub destroyed: AtomicBool,
    pub name: [u8; 32],
}

#[repr(C)]
pub struct LinuxDelayedWork {
    pub work: LinuxWorkStruct,
    pub timer: LinuxTimerList,
    pub wq: *mut LinuxWorkqueueStruct,
    pub cpu: i32,
}

#[repr(C)]
pub struct LinuxTaskStruct {
    pub pid: i32,
    pub should_stop: AtomicI32,
    pub result: AtomicI32,
    pub done: AtomicBool,
    pub started: AtomicBool,
    pub start: *mut KthreadStart,
}

#[repr(C)]
pub struct LinuxTaskletStruct {
    pub next: *mut LinuxTaskletStruct,
    pub state: u64,
    pub count: AtomicUsize,
    pub func: Option<extern "C" fn(usize)>,
    pub data: usize,
}

pub type KthreadFn = extern "C" fn(*mut u8) -> i32;

pub struct KthreadStart {
    pub task: *mut LinuxTaskStruct,
    pub func: KthreadFn,
    pub data: *mut u8,
    pub name: &'static str,
}

#[repr(C)]
pub struct LinuxTimespec64 {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
