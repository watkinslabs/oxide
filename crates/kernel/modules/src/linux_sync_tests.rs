use super::*;
use crate::symtab;
use core::sync::atomic::{AtomicU32, Ordering};

#[test]
fn spin_mutex_and_rw_paths_round_trip() {
    let _modules = crate::test_serial::claim();
    let mut s = LinuxSpinlock { state: 7 };
    spin_lock_init(&mut s);
    assert_eq!(spin_trylock(&mut s), 1);
    assert_eq!(spin_is_locked(&mut s), 1);
    spin_unlock(&mut s);
    let mut m = LinuxMutex { state: 0 };
    mutex_lock(&mut m);
    assert_eq!(mutex_trylock(&mut m), 0);
    mutex_unlock(&mut m);
    let mut rw = LinuxRwLock { state: 0 };
    read_lock(&mut rw); read_unlock(&mut rw);
    write_lock(&mut rw); write_unlock(&mut rw);
    let mut sem = LinuxRwSem { state: 0 };
    assert_eq!(down_read_trylock(&mut sem), 1);
    up_read(&mut sem);
    assert_eq!(down_write_trylock(&mut sem), 1);
    up_write(&mut sem);
    let mut s = LinuxSemaphore { lock: LinuxSpinlock { state: 0 }, count: 0, wait_seq: 0 };
    sema_init(&mut s, 1);
    assert_eq!(down_trylock(&mut s), 0);
    assert_eq!(down_trylock(&mut s), 1);
    up(&mut s);
    assert_eq!(down_interruptible(&mut s), 0);
}

#[test]
fn completion_refcount_kref_and_seq_work() {
    let _modules = crate::test_serial::claim();
    let mut c = LinuxCompletion { done: 0 };
    init_completion(&mut c);
    assert_eq!(try_wait_for_completion(&mut c), 0);
    complete(&mut c);
    assert_eq!(try_wait_for_completion(&mut c), 1);
    let mut seq = LinuxSeqLock { seq: 0, lock: 0 };
    seqlock_init(&mut seq);
    let start = read_seqbegin(&mut seq);
    write_seqlock(&mut seq);
    write_sequnlock(&mut seq);
    assert_eq!(read_seqretry(&mut seq, start), 1);
    let mut r = LinuxRefcount { refs: 0 };
    refcount_set(&mut r, 1);
    assert_eq!(refcount_dec_and_test(&mut r), 1);
    static RELEASED: AtomicU32 = AtomicU32::new(0);
    extern "C" fn release(_k: *mut LinuxKref) { RELEASED.fetch_add(1, Ordering::AcqRel); }
    let mut k = LinuxKref { refs: LinuxRefcount { refs: 0 } };
    kref_init(&mut k);
    assert_eq!(kref_put(&mut k, Some(release)), 1);
    assert_eq!(RELEASED.load(Ordering::Acquire), 1);
}

#[test]
fn export_symbols_registers_sync_surface() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in ["spin_lock", "raw_spin_lock", "mutex_lock", "read_lock",
        "down_read", "seqlock_init", "complete", "wake_up", "atomic_inc",
        "refcount_inc", "kref_put", "lockdep_set_class", "down_interruptible"] {
        assert!(symtab::resolve(name, true).is_ok(), "{name}");
    }
}

#[test]
fn waitqueue_prepare_tracks_active_until_finish() {
    let _modules = crate::test_serial::claim();
    wait::reset_wait_cells();
    let mut wq = LinuxWaitQueueHead { seq: 0 };
    let mut ent = LinuxWaitQueueEntry {
        flags: 0,
        private: core::ptr::null_mut(),
        func: core::ptr::null_mut(),
        seq: 0,
    };
    init_waitqueue_head(&mut wq);
    assert_eq!(waitqueue_active(&mut wq), 0);
    assert_eq!(prepare_to_wait_event(&mut wq, &mut ent, 1), 0);
    assert_eq!(waitqueue_active(&mut wq), 1);
    wake_up(&mut wq);
    finish_wait(&mut wq, &mut ent);
    assert_eq!(waitqueue_active(&mut wq), 0);
}
