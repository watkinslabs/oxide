// Linux io_uring command KPI dispatch.  The command state itself belongs to
// the io_uring core; this module owns only the loadable-module ABI exports.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use pmm::native_bvec::NativeIovIter;

const LINUX_EOPNOTSUPP: i32 = 95;

#[repr(C)]
pub struct LinuxIoUringCmd {
    pub file: *mut c_void,
    pub sqe: *const u8,
    pub cmd_op: u32,
    pub flags: u32,
    pub pdu: [u8; 32],
    pub unused: [u8; 8],
}

#[repr(C)]
pub struct LinuxUserIovec { pub base: *mut c_void, pub len: usize }

pub type DoInTask = unsafe extern "C" fn(*mut LinuxIoUringCmd, usize, u32);
pub type Done = unsafe extern "C" fn(*mut LinuxIoUringCmd, i32, u64, u32, bool);
pub type ImportFixed = unsafe extern "C" fn(u64, usize, i32, *mut NativeIovIter, *mut LinuxIoUringCmd, u32) -> i32;
pub type ImportFixedVec = unsafe extern "C" fn(*mut LinuxIoUringCmd, *const LinuxUserIovec, usize, i32, *mut NativeIovIter, u32) -> i32;

static DO_IN_TASK: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static IMPORT_FIXED: AtomicUsize = AtomicUsize::new(0);
static IMPORT_FIXED_VEC: AtomicUsize = AtomicUsize::new(0);

/// Install the canonical io_uring-core callbacks before modules become loadable.
/// # C: O(1)
pub fn install_cmd_hooks(do_in_task: DoInTask, done: Done, import_fixed: ImportFixed, import_fixed_vec: ImportFixedVec) {
    DO_IN_TASK.store(do_in_task as usize, Ordering::Release);
    DONE.store(done as usize, Ordering::Release);
    IMPORT_FIXED.store(import_fixed as usize, Ordering::Release);
    IMPORT_FIXED_VEC.store(import_fixed_vec as usize, Ordering::Release);
}

/// Register io_uring command exports for loadable drivers.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__io_uring_cmd_do_in_task", __io_uring_cmd_do_in_task as *const () as usize),
        ("__io_uring_cmd_done", __io_uring_cmd_done as *const () as usize),
        ("io_uring_cmd_import_fixed", io_uring_cmd_import_fixed as *const () as usize),
        ("io_uring_cmd_import_fixed_vec", io_uring_cmd_import_fixed_vec as *const () as usize),
    ] { export(name, addr, true); }
}

unsafe extern "C" fn __io_uring_cmd_do_in_task(cmd: *mut LinuxIoUringCmd, callback: usize, flags: u32) {
    let hook = DO_IN_TASK.load(Ordering::Acquire);
    if hook == 0 { return; }
    // SAFETY: install_cmd_hooks accepts only the canonical io_uring core callback ABI.
    unsafe { core::mem::transmute::<usize, DoInTask>(hook)(cmd, callback, flags); }
}

unsafe extern "C" fn __io_uring_cmd_done(cmd: *mut LinuxIoUringCmd, ret: i32, res2: u64, flags: u32, cqe32: bool) {
    let hook = DONE.load(Ordering::Acquire);
    if hook == 0 { return; }
    // SAFETY: install_cmd_hooks accepts only the canonical io_uring core callback ABI.
    unsafe { core::mem::transmute::<usize, Done>(hook)(cmd, ret, res2, flags, cqe32); }
}

unsafe extern "C" fn io_uring_cmd_import_fixed(buf: u64, len: usize, rw: i32, iter: *mut NativeIovIter, cmd: *mut LinuxIoUringCmd, flags: u32) -> i32 {
    let hook = IMPORT_FIXED.load(Ordering::Acquire);
    if hook == 0 { return -LINUX_EOPNOTSUPP; }
    // SAFETY: install_cmd_hooks accepts only the canonical io_uring core callback ABI.
    unsafe { core::mem::transmute::<usize, ImportFixed>(hook)(buf, len, rw, iter, cmd, flags) }
}

unsafe extern "C" fn io_uring_cmd_import_fixed_vec(cmd: *mut LinuxIoUringCmd, vec: *const LinuxUserIovec, nr: usize, dir: i32, iter: *mut NativeIovIter, flags: u32) -> i32 {
    let hook = IMPORT_FIXED_VEC.load(Ordering::Acquire);
    if hook == 0 { return -LINUX_EOPNOTSUPP; }
    // SAFETY: install_cmd_hooks accepts only the canonical io_uring core callback ABI.
    unsafe { core::mem::transmute::<usize, ImportFixedVec>(hook)(cmd, vec, nr, dir, iter, flags) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn task(_cmd: *mut LinuxIoUringCmd, cb: usize, flags: u32) { CALLS.store(cb ^ flags as usize, Ordering::SeqCst); }
    unsafe extern "C" fn done(_cmd: *mut LinuxIoUringCmd, ret: i32, _res2: u64, _flags: u32, _wide: bool) { CALLS.store(ret as usize, Ordering::SeqCst); }
    unsafe extern "C" fn fixed(_buf: u64, _len: usize, _rw: i32, _iter: *mut NativeIovIter, _cmd: *mut LinuxIoUringCmd, _flags: u32) -> i32 { 17 }
    unsafe extern "C" fn fixed_vec(_cmd: *mut LinuxIoUringCmd, _vec: *const LinuxUserIovec, _nr: usize, _dir: i32, _iter: *mut NativeIovIter, _flags: u32) -> i32 { 19 }
    #[test] fn target_layouts_are_pinned() { assert_eq!(core::mem::size_of::<LinuxIoUringCmd>(), 64); assert_eq!(core::mem::offset_of!(LinuxIoUringCmd, pdu), 24); assert_eq!(core::mem::size_of::<NativeIovIter>(), 40); assert_eq!(core::mem::size_of::<LinuxUserIovec>(), 16); }
    #[test] fn installed_core_hooks_receive_every_exported_operation() { let _modules = crate::test_serial::claim(); install_cmd_hooks(task, done, fixed, fixed_vec); let mut cmd = LinuxIoUringCmd { file: core::ptr::null_mut(), sqe: core::ptr::null(), cmd_op: 0, flags: 0, pdu: [0; 32], unused: [0; 8] }; unsafe { __io_uring_cmd_do_in_task(&mut cmd, 0x55, 0x11); } assert_eq!(CALLS.load(Ordering::SeqCst), 0x44); unsafe { __io_uring_cmd_done(&mut cmd, 7, 0, 0, false); } assert_eq!(CALLS.load(Ordering::SeqCst), 7); assert_eq!(unsafe { io_uring_cmd_import_fixed(0, 0, 0, core::ptr::null_mut(), &mut cmd, 0) }, 17); assert_eq!(unsafe { io_uring_cmd_import_fixed_vec(&mut cmd, core::ptr::null(), 0, 0, core::ptr::null_mut(), 0) }, 19); }
}
