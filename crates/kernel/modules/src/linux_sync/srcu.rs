use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use alloc::boxed::Box;

const LINUX_EINVAL: i32 = 22;

#[repr(C)]
pub(super) struct LinuxSrcuCtr { locks: isize, unlocks: isize }

#[repr(C)]
pub(super) struct LinuxSrcuStruct {
    ctrp: *mut LinuxSrcuCtr,
    sda: *mut c_void,
    flavor: u8,
    pad: [u8; 7],
    sup: *mut SrcuState,
}

struct SrcuState {
    readers: [AtomicUsize; 2],
    epoch: AtomicUsize,
    writer: AtomicBool,
    counters: [LinuxSrcuCtr; 2],
}

impl LinuxSrcuStruct {
    pub(super) const fn new() -> Self {
        Self { ctrp: core::ptr::null_mut(), sda: core::ptr::null_mut(), flavor: 0, pad: [0; 7], sup: core::ptr::null_mut() }
    }
}

impl SrcuState {
    fn new() -> Self {
        Self {
            readers: [AtomicUsize::new(0), AtomicUsize::new(0)], epoch: AtomicUsize::new(0), writer: AtomicBool::new(false),
            counters: [LinuxSrcuCtr { locks: 0, unlocks: 0 }, LinuxSrcuCtr { locks: 0, unlocks: 0 }],
        }
    }
}

/// Register the external-module Tree SRCU surface.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("init_srcu_struct", init_srcu_struct as *const () as usize),
        ("cleanup_srcu_struct", cleanup_srcu_struct as *const () as usize),
        ("__srcu_read_lock", __srcu_read_lock as *const () as usize),
        ("__srcu_read_unlock", __srcu_read_unlock as *const () as usize),
        ("synchronize_srcu", synchronize_srcu as *const () as usize),
        ("synchronize_srcu_expedited", synchronize_srcu_expedited as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn init_srcu_struct(ssp: *mut LinuxSrcuStruct) -> i32 {
    if ssp.is_null() { return -LINUX_EINVAL; }
    ensure_state(ssp).map_or(-LINUX_EINVAL, |_| 0)
}

extern "C" fn cleanup_srcu_struct(ssp: *mut LinuxSrcuStruct) {
    if ssp.is_null() { return; }
    synchronize_srcu(ssp);
    // SAFETY: cleanup follows reader/writer teardown and synchronize_srcu drained the old epoch before this final state release.
    unsafe {
        let state = (*ssp).sup;
        if state.is_null() { return; }
        (*ssp).sup = core::ptr::null_mut();
        (*ssp).ctrp = core::ptr::null_mut();
        (*ssp).sda = core::ptr::null_mut();
        drop(Box::from_raw(state));
    }
}

extern "C" fn __srcu_read_lock(ssp: *mut LinuxSrcuStruct) -> i32 {
    let Some(state) = ensure_state(ssp) else { return -LINUX_EINVAL; };
    loop {
        let idx = state.epoch.load(Ordering::Acquire) & 1;
        state.readers[idx].fetch_add(1, Ordering::SeqCst);
        if state.epoch.load(Ordering::Acquire) & 1 == idx { return idx as i32; }
        state.readers[idx].fetch_sub(1, Ordering::SeqCst);
    }
}

extern "C" fn __srcu_read_unlock(ssp: *mut LinuxSrcuStruct, idx: i32) {
    if !(0..=1).contains(&idx) { return; }
    let Some(state) = ensure_state(ssp) else { return; };
    state.readers[idx as usize].fetch_sub(1, Ordering::SeqCst);
}

extern "C" fn synchronize_srcu(ssp: *mut LinuxSrcuStruct) {
    let Some(state) = ensure_state(ssp) else { return; };
    writer_lock(state);
    let old = state.epoch.fetch_xor(1, Ordering::SeqCst) & 1;
    while state.readers[old].load(Ordering::SeqCst) != 0 { sync::relax(); }
    writer_unlock(state);
}

extern "C" fn synchronize_srcu_expedited(ssp: *mut LinuxSrcuStruct) { synchronize_srcu(ssp); }

fn ensure_state(ssp: *mut LinuxSrcuStruct) -> Option<&'static SrcuState> {
    if ssp.is_null() { return None; }
    // SAFETY: srcu_struct is pointer-aligned C storage; the atomic owner pointer is the single initialization publication point.
    unsafe {
        let slot = core::sync::atomic::AtomicPtr::from_ptr(core::ptr::addr_of_mut!((*ssp).sup));
        let present = slot.load(Ordering::Acquire);
        if !present.is_null() { return present.as_ref(); }
        let fresh = Box::into_raw(Box::new(SrcuState::new()));
        match slot.compare_exchange(core::ptr::null_mut(), fresh, Ordering::Release, Ordering::Acquire) {
            Ok(_) => {
                (*ssp).ctrp = (*fresh).counters.as_mut_ptr();
                (*ssp).sda = fresh.cast();
                fresh.as_ref()
            }
            Err(winner) => {
                drop(Box::from_raw(fresh));
                winner.as_ref()
            }
        }
    }
}

fn writer_lock(state: &SrcuState) {
    while state.writer.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { sync::relax(); }
}

fn writer_unlock(state: &SrcuState) { state.writer.store(false, Ordering::Release); }

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};
    use std::sync::{Arc, Barrier};

    #[test]
    fn reader_epoch_blocks_the_grace_period_that_follows_it() {
        let _serial = crate::test_serial::claim();
        let mut srcu = LinuxSrcuStruct::new();
        assert_eq!(init_srcu_struct(&mut srcu), 0);
        let ready = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let ptr = &mut srcu as *mut LinuxSrcuStruct as usize;
        let r_ready = ready.clone();
        let r_release = release.clone();
        let reader = std::thread::spawn(move || {
            let srcu = ptr as *mut LinuxSrcuStruct;
            let idx = __srcu_read_lock(srcu);
            r_ready.wait();
            r_release.wait();
            __srcu_read_unlock(srcu, idx);
        });
        ready.wait();
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let ptr = &mut srcu as *mut LinuxSrcuStruct as usize;
        let writer = std::thread::spawn(move || { synchronize_srcu(ptr as *mut LinuxSrcuStruct); d.store(true, Ordering::Release); });
        std::thread::yield_now();
        assert!(!done.load(Ordering::Acquire));
        release.wait();
        reader.join().unwrap(); writer.join().unwrap();
        assert!(done.load(Ordering::Acquire));
        cleanup_srcu_struct(&mut srcu);
    }

    #[test]
    fn tree_srcu_abi_is_pointer_owned() {
        assert_eq!((size_of::<LinuxSrcuStruct>(), align_of::<LinuxSrcuStruct>()), (32, 8));
        let mut srcu = LinuxSrcuStruct::new();
        assert_eq!(init_srcu_struct(&mut srcu), 0);
        assert!(!srcu.sup.is_null()); assert!(!srcu.ctrp.is_null());
        cleanup_srcu_struct(&mut srcu);
    }

    #[test]
    fn zero_initialized_static_domain_is_published_once() {
        let _serial = crate::test_serial::claim();
        let mut srcu = LinuxSrcuStruct::new();
        assert_eq!(__srcu_read_lock(&mut srcu), 0);
        __srcu_read_unlock(&mut srcu, 0);
        assert!(!srcu.sup.is_null());
        cleanup_srcu_struct(&mut srcu);
    }
}
