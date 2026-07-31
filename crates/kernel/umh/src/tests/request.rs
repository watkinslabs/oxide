// Request construction and the init/cleanup callback contract.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::backend::{self, HelperRun};
use crate::env;
use crate::exec::{call_usermodehelper_exec, call_usermodehelper_setup};
use crate::gate;
use crate::info::{HelperCtx, SubprocessInfo};
use crate::uapi::UMH_WAIT_EXEC;

use super::serialize;

/// What the `init` callback returns.
static INIT_RC: AtomicI32 = AtomicI32::new(0);
/// Times `init` ran.
static INITS: AtomicU32 = AtomicU32::new(0);
/// `data` the callbacks observed.
static SEEN_DATA: AtomicUsize = AtomicUsize::new(0);
/// Descriptor the callback installed, as counted from the helper's table.
static SEEN_FDS: AtomicUsize = AtomicUsize::new(0);
/// The program the backend was asked to load, and its argv/envp, flattened.
static SEEN_PATH: AtomicUsize = AtomicUsize::new(0);

fn helper_ctx() -> HelperCtx {
    HelperCtx {
        task: Arc::new(sched::Task::new(0x2000, "umh-test",
                                        sched::SchedClass::Normal { weight: 1024 })),
        fdt: Arc::new(vfs::FdTable::new()),
    }
}

/// Backend that reproduces the real one's order: run `init`, and only load the
/// image if it succeeded.
fn init_running_backend(mut info: Box<SubprocessInfo>) -> HelperRun {
    let ctx = helper_ctx();
    let rc = info.run_init(&ctx);
    SEEN_FDS.store(ctx.fdt.count(), Ordering::Release);
    SEEN_PATH.store(info.path_bytes().len(), Ordering::Release);
    info.retval = if rc != 0 { rc } else { 0 };
    HelperRun::Done(info)
}

fn record_init(info: &mut SubprocessInfo, _ctx: &HelperCtx) -> i32 {
    INITS.fetch_add(1, Ordering::AcqRel);
    SEEN_DATA.store(info.data, Ordering::Release);
    INIT_RC.load(Ordering::Acquire)
}

fn arm() {
    gate::reset_for_test();
    gate::usermodehelper_enable();
    backend::install(init_running_backend);
    INITS.store(0, Ordering::Release);
    INIT_RC.store(0, Ordering::Release);
    SEEN_DATA.store(0, Ordering::Release);
    SEEN_FDS.store(usize::MAX, Ordering::Release);
    SEEN_PATH.store(0, Ordering::Release);
}

#[test]
fn setup_preserves_the_program_argv_and_environment_verbatim() {
    let info = call_usermodehelper_setup(
        b"/sbin/request-key",
        &[b"/sbin/request-key" as &[u8], b"create", b"12345", b"0", b"0"],
        &env::UPCALL_ENV,
        None, None, 0);
    assert_eq!(info.path_bytes(), b"/sbin/request-key");
    assert_eq!(info.argv.len(), 5);
    assert_eq!(info.argv[1].as_slice(), b"create");
    assert_eq!(info.argv[4].as_slice(), b"0");
    assert_eq!(info.envp.len(), 2);
    assert_eq!(info.envp[0].as_slice(), b"HOME=/");
    assert_eq!(info.envp[1].as_slice(), b"PATH=/sbin:/bin:/usr/sbin:/usr/bin");
    assert!(!info.path_is_null());
    assert!(!info.path_is_empty());
    assert!(!info.has_init());
}

#[test]
fn a_helper_may_be_given_no_environment_at_all() {
    let info = call_usermodehelper_setup(b"/usr/lib/systemd/systemd-coredump",
                                         &[b"/usr/lib/systemd/systemd-coredump" as &[u8]],
                                         &[], None, None, 0);
    assert!(info.envp.is_empty());
}

#[test]
fn the_module_loader_environment_carries_a_terminal_type() {
    // Three variables, and the module directories come first on the path.
    assert_eq!(env::MODPROBE_ENV.len(), 3);
    assert_eq!(env::MODPROBE_ENV[1], b"TERM=linux");
    assert_eq!(env::MODPROBE_ENV[2], b"PATH=/sbin:/usr/sbin:/bin:/usr/bin");
}

#[test]
fn init_runs_against_the_helper_and_sees_the_callers_context() {
    let _g = serialize();
    arm();
    let info = call_usermodehelper_setup(b"/sbin/request-key", &[], &[],
                                         Some(record_init), None, 0xBEEF);
    assert!(info.has_init());
    assert_eq!(call_usermodehelper_exec(info, UMH_WAIT_EXEC), 0);
    assert_eq!(INITS.load(Ordering::Acquire), 1);
    assert_eq!(SEEN_DATA.load(Ordering::Acquire), 0xBEEF);
}

#[test]
fn a_failing_init_aborts_the_helper_with_its_own_errno() {
    let _g = serialize();
    arm();
    INIT_RC.store(-9, Ordering::Release); // EBADF from a descriptor install
    let info = call_usermodehelper_setup(b"/usr/lib/systemd/systemd-coredump", &[], &[],
                                         Some(record_init), None, 0);
    // The caller must see the setup failure, not a zero implying the dump was
    // handed to a program that never ran.
    assert_eq!(call_usermodehelper_exec(info, UMH_WAIT_EXEC), -9);
    assert_eq!(INITS.load(Ordering::Acquire), 1);
}

#[test]
fn the_helper_starts_from_an_empty_descriptor_table() {
    let _g = serialize();
    arm();
    let info = call_usermodehelper_setup(b"/sbin/request-key", &[], &[],
                                         Some(record_init), None, 0);
    let _ = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
    // The coredump pipe relies on this: descriptor 0 is free because the helper
    // is a child of a kernel worker, not of the crashing process.
    assert_eq!(SEEN_FDS.load(Ordering::Acquire), 0);
}

#[test]
fn a_request_with_no_init_still_reaches_the_image_load() {
    let _g = serialize();
    arm();
    let info = call_usermodehelper_setup(b"/sbin/request-key", &[], &[], None, None, 0);
    assert_eq!(call_usermodehelper_exec(info, UMH_WAIT_EXEC), 0);
    assert_eq!(INITS.load(Ordering::Acquire), 0);
    assert_eq!(SEEN_PATH.load(Ordering::Acquire), b"/sbin/request-key".len());
}

#[test]
fn cleanup_observes_the_data_it_owns() {
    let _g = serialize();
    arm();
    static FREED: AtomicUsize = AtomicUsize::new(0);
    fn free_data(info: &mut SubprocessInfo) { FREED.store(info.data, Ordering::Release); }
    FREED.store(0, Ordering::Release);
    let owned: Box<Vec<u8>> = Box::new(alloc::vec![1u8, 2, 3]);
    let raw = Box::into_raw(owned) as usize;
    let info = call_usermodehelper_setup(b"/sbin/request-key", &[], &[], None,
                                         Some(free_data), raw);
    let _ = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
    assert_eq!(FREED.load(Ordering::Acquire), raw);
    // SAFETY: `raw` came from Box::into_raw on a Box<Vec<u8>> a few lines above and has not been reclaimed since; this is its single matching from_raw.
    drop(unsafe { Box::from_raw(raw as *mut Vec<u8>) });
}
