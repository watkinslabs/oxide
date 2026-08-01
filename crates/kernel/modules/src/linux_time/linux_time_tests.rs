use super::{clock::*, kthread::*, tasklet::*, types::*, work::*};
use crate::symtab;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

static WORK_COUNT: AtomicUsize = AtomicUsize::new(0);
static TASKLET_DATA: AtomicUsize = AtomicUsize::new(0);

extern "C" fn work_cb(_w: *mut LinuxWorkStruct) { WORK_COUNT.fetch_add(1, Ordering::AcqRel); }
extern "C" fn tasklet_cb(data: usize) { TASKLET_DATA.store(data, Ordering::Release); }
extern "C" fn thread_cb(data: *mut u8) -> i32 { data as usize as i32 }

#[test]
fn time_conversions_and_sleep_advance_host_clock() {
    let _modules = crate::test_serial::claim();
    FALLBACK_NS.store(0, Ordering::Release);
    jiffies.store(0, Ordering::Release);
    assert_eq!(msecs_to_jiffies(10), 1);
    assert_eq!(jiffies_to_msecs(1), 10);
    msleep(20);
    assert_eq!(ktime_get_ns(), 20_000_000);
    assert_eq!(jiffies.load(Ordering::Acquire), 2);
}

#[test]
fn work_delayed_work_tasklet_and_kthread_paths() {
    let _modules = crate::test_serial::claim();
    WORK_COUNT.store(0, Ordering::Release);
    TASKLET_DATA.store(0, Ordering::Release);
    let mut w = LinuxWorkStruct {
        data: AtomicUsize::new(0),
        entry: LinuxListHead { next: null_mut(), prev: null_mut() },
        func: None,
    };
    init_work(&mut w, Some(work_cb));
    assert_eq!(schedule_work(&mut w), 1);
    let mut dw = LinuxDelayedWork {
        work: LinuxWorkStruct {
            data: AtomicUsize::new(0),
            entry: LinuxListHead { next: null_mut(), prev: null_mut() },
            func: None,
        },
        timer: LinuxTimerList {
            entry: LinuxHListNode { next: null_mut(), pprev: null_mut() },
            expires: 0,
            function: None,
            flags: 0,
        },
        wq: null_mut(),
        cpu: -1,
    };
    init_delayed_work(&mut dw, Some(work_cb));
    assert_eq!(schedule_delayed_work(&mut dw, 0), 1);
    ::timer::run_due(now_ns());
    assert_eq!(WORK_COUNT.load(Ordering::Acquire), 2);
    let mut t = LinuxTaskletStruct { next: null_mut(), state: 0, count: AtomicUsize::new(0), func: None, data: 0 };
    tasklet_init(&mut t, Some(tasklet_cb), 42);
    tasklet_schedule(&mut t);
    ::timer::run_due(now_ns());
    assert_eq!(TASKLET_DATA.load(Ordering::Acquire), 42);
    let task = kthread_create(Some(thread_cb), 7usize as *mut u8, b"kt\0".as_ptr());
    assert!(!task.is_null());
    assert_eq!(wake_up_process(task), 1);
    assert_eq!(kthread_stop(task), 7);
}

#[test]
fn export_symbols_registers_time_surface() {
    let _modules = crate::test_serial::claim();
    super::export_symbols();
    for name in ["jiffies", "jiffies_64", "msecs_to_jiffies", "ktime_get_ns",
        "msleep", "init_timer", "hrtimer_start", "schedule_work",
        "schedule_delayed_work", "kthread_create", "tasklet_schedule"] {
        assert!(symtab::resolve(name, true).is_ok(), "{name}");
    }
}
