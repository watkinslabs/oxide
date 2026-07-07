// Linux synchronization KPI exports for loadable drivers.

use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const WRITER: i32 = -1;
const COMPLETE_ALL: u32 = u32::MAX;
const TASK_WAKE: u32 = 1;

#[repr(C)]
pub struct LinuxSpinlock { state: u32 }
#[repr(C)]
pub struct LinuxMutex { state: u32 }
#[repr(C)]
pub struct LinuxRwLock { state: i32 }
#[repr(C)]
pub struct LinuxRwSem { state: i32 }
#[repr(C)]
pub struct LinuxSeqLock { seq: u32, lock: u32 }
#[repr(C)]
pub struct LinuxCompletion { done: u32 }
#[repr(C)]
pub struct LinuxWaitQueueHead { seq: u32 }
#[repr(C)]
pub struct LinuxWaitQueueEntry { flags: u32, private: *mut c_void, func: *mut c_void, seq: u32 }
#[repr(C)]
pub struct LinuxSwaitQueueHead { seq: u32 }
#[repr(C)]
pub struct LinuxSemaphore { lock: LinuxSpinlock, count: u32, wait_seq: u32 }
#[repr(C)]
pub struct LinuxAtomic { counter: i32 }
#[repr(C)]
pub struct LinuxAtomic64 { counter: i64 }
#[repr(C)]
pub struct LinuxRefcount { refs: u32 }
#[repr(C)]
pub struct LinuxKref { refs: LinuxRefcount }

type KrefRelease = extern "C" fn(*mut LinuxKref);

/// Register Linux synchronization KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("spin_lock_init", spin_lock_init as *const () as usize),
        ("spin_lock", spin_lock as *const () as usize),
        ("spin_trylock", spin_trylock as *const () as usize),
        ("spin_unlock", spin_unlock as *const () as usize),
        ("spin_is_locked", spin_is_locked as *const () as usize),
        ("raw_spin_lock_init", raw_spin_lock_init as *const () as usize),
        ("raw_spin_lock", raw_spin_lock as *const () as usize),
        ("raw_spin_trylock", raw_spin_trylock as *const () as usize),
        ("raw_spin_unlock", raw_spin_unlock as *const () as usize),
        ("_raw_spin_lock", raw_spin_lock as *const () as usize),
        ("_raw_spin_unlock", raw_spin_unlock as *const () as usize),
        ("_raw_spin_lock_bh", raw_spin_lock_bh as *const () as usize),
        ("_raw_spin_lock_irq", raw_spin_lock_irq as *const () as usize),
        ("_raw_spin_lock_irqsave", raw_spin_lock_irqsave as *const () as usize),
        ("_raw_spin_unlock_bh", raw_spin_unlock_bh as *const () as usize),
        ("_raw_spin_unlock_irq", raw_spin_unlock_irq as *const () as usize),
        ("_raw_spin_unlock_irqrestore", raw_spin_unlock_irqrestore as *const () as usize),
        ("mutex_init", mutex_init as *const () as usize),
        ("__mutex_init", __mutex_init as *const () as usize),
        ("mutex_lock", mutex_lock as *const () as usize),
        ("mutex_lock_interruptible", mutex_lock_interruptible as *const () as usize),
        ("mutex_trylock", mutex_trylock as *const () as usize),
        ("mutex_unlock", mutex_unlock as *const () as usize),
        ("mutex_is_locked", mutex_is_locked as *const () as usize),
        ("rwlock_init", rwlock_init as *const () as usize),
        ("read_lock", read_lock as *const () as usize),
        ("read_trylock", read_trylock as *const () as usize),
        ("read_unlock", read_unlock as *const () as usize),
        ("write_lock", write_lock as *const () as usize),
        ("write_trylock", write_trylock as *const () as usize),
        ("write_unlock", write_unlock as *const () as usize),
        ("init_rwsem", init_rwsem as *const () as usize),
        ("down_read", down_read as *const () as usize),
        ("down_read_trylock", down_read_trylock as *const () as usize),
        ("up_read", up_read as *const () as usize),
        ("down_write", down_write as *const () as usize),
        ("down_write_trylock", down_write_trylock as *const () as usize),
        ("up_write", up_write as *const () as usize),
        ("sema_init", sema_init as *const () as usize),
        ("down", down as *const () as usize),
        ("down_interruptible", down_interruptible as *const () as usize),
        ("down_trylock", down_trylock as *const () as usize),
        ("up", up as *const () as usize),
        ("seqlock_init", seqlock_init as *const () as usize),
        ("write_seqlock", write_seqlock as *const () as usize),
        ("write_sequnlock", write_sequnlock as *const () as usize),
        ("read_seqbegin", read_seqbegin as *const () as usize),
        ("read_seqretry", read_seqretry as *const () as usize),
        ("init_completion", init_completion as *const () as usize),
        ("reinit_completion", reinit_completion as *const () as usize),
        ("complete", complete as *const () as usize),
        ("complete_all", complete_all as *const () as usize),
        ("wait_for_completion", wait_for_completion as *const () as usize),
        ("wait_for_completion_interruptible", wait_for_completion_interruptible as *const () as usize),
        ("wait_for_completion_timeout", wait_for_completion_timeout as *const () as usize),
        ("try_wait_for_completion", try_wait_for_completion as *const () as usize),
        ("completion_done", completion_done as *const () as usize),
        ("init_waitqueue_head", init_waitqueue_head as *const () as usize),
        ("__init_waitqueue_head", __init_waitqueue_head as *const () as usize),
        ("__init_swait_queue_head", __init_swait_queue_head as *const () as usize),
        ("wake_up", wake_up as *const () as usize),
        ("__wake_up", __wake_up as *const () as usize),
        ("wake_up_all", wake_up_all as *const () as usize),
        ("waitqueue_active", waitqueue_active as *const () as usize),
        ("init_wait_entry", init_wait_entry as *const () as usize),
        ("prepare_to_wait_event", prepare_to_wait_event as *const () as usize),
        ("finish_wait", finish_wait as *const () as usize),
        ("__rcu_read_lock", __rcu_read_lock as *const () as usize),
        ("__rcu_read_unlock", __rcu_read_unlock as *const () as usize),
        ("synchronize_rcu", synchronize_rcu as *const () as usize),
        ("rcu_barrier", rcu_barrier as *const () as usize),
        ("atomic_read", atomic_read as *const () as usize),
        ("atomic_set", atomic_set as *const () as usize),
        ("atomic_inc", atomic_inc as *const () as usize),
        ("atomic_dec", atomic_dec as *const () as usize),
        ("atomic_add", atomic_add as *const () as usize),
        ("atomic_sub", atomic_sub as *const () as usize),
        ("atomic_dec_and_test", atomic_dec_and_test as *const () as usize),
        ("atomic_inc_return", atomic_inc_return as *const () as usize),
        ("refcount_set", refcount_set as *const () as usize),
        ("refcount_read", refcount_read as *const () as usize),
        ("refcount_inc", refcount_inc as *const () as usize),
        ("refcount_dec_and_test", refcount_dec_and_test as *const () as usize),
        ("refcount_warn_saturate", refcount_warn_saturate as *const () as usize),
        ("kref_init", kref_init as *const () as usize),
        ("kref_get", kref_get as *const () as usize),
        ("kref_put", kref_put as *const () as usize),
        ("lockdep_set_class", lockdep_set_class as *const () as usize),
        ("lockdep_set_class_and_name", lockdep_set_class_and_name as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn spin_lock_init(l: *mut LinuxSpinlock) {
    if l.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned spinlock storage.
    unsafe { (*l).state = 0; }
}
extern "C" fn spin_lock(l: *mut LinuxSpinlock) { lock_u32(field_u32(l)); }
extern "C" fn spin_trylock(l: *mut LinuxSpinlock) -> i32 { try_lock_u32(field_u32(l)) as i32 }
extern "C" fn spin_unlock(l: *mut LinuxSpinlock) { unlock_u32(field_u32(l)); }
extern "C" fn spin_is_locked(l: *mut LinuxSpinlock) -> i32 { load_u32(field_u32(l)) as i32 }
extern "C" fn raw_spin_lock_init(l: *mut LinuxSpinlock) { spin_lock_init(l); }
extern "C" fn raw_spin_lock(l: *mut LinuxSpinlock) { spin_lock(l); }
extern "C" fn raw_spin_trylock(l: *mut LinuxSpinlock) -> i32 { spin_trylock(l) }
extern "C" fn raw_spin_unlock(l: *mut LinuxSpinlock) { spin_unlock(l); }
extern "C" fn raw_spin_lock_bh(l: *mut LinuxSpinlock) { raw_spin_lock(l); }
extern "C" fn raw_spin_lock_irq(l: *mut LinuxSpinlock) { raw_spin_lock(l); }
extern "C" fn raw_spin_lock_irqsave(l: *mut LinuxSpinlock) -> usize { raw_spin_lock(l); 0 }
extern "C" fn raw_spin_unlock_bh(l: *mut LinuxSpinlock) { raw_spin_unlock(l); }
extern "C" fn raw_spin_unlock_irq(l: *mut LinuxSpinlock) { raw_spin_unlock(l); }
extern "C" fn raw_spin_unlock_irqrestore(l: *mut LinuxSpinlock, _flags: usize) { raw_spin_unlock(l); }

extern "C" fn mutex_init(m: *mut LinuxMutex) {
    if m.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned mutex storage.
    unsafe { (*m).state = 0; }
}
extern "C" fn __mutex_init(m: *mut LinuxMutex, _name: *const u8, _key: *mut c_void) { mutex_init(m); }
extern "C" fn mutex_lock(m: *mut LinuxMutex) { lock_u32(mutex_u32(m)); }
extern "C" fn mutex_lock_interruptible(m: *mut LinuxMutex) -> i32 { mutex_lock(m); 0 }
extern "C" fn mutex_trylock(m: *mut LinuxMutex) -> i32 { try_lock_u32(mutex_u32(m)) as i32 }
extern "C" fn mutex_unlock(m: *mut LinuxMutex) { unlock_u32(mutex_u32(m)); }
extern "C" fn mutex_is_locked(m: *mut LinuxMutex) -> i32 { load_u32(mutex_u32(m)) as i32 }

extern "C" fn rwlock_init(l: *mut LinuxRwLock) {
    if l.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned rwlock storage.
    unsafe { (*l).state = 0; }
}
extern "C" fn read_lock(l: *mut LinuxRwLock) { read_take(rwlock_i32(l)); }
extern "C" fn read_trylock(l: *mut LinuxRwLock) -> i32 { read_try(rwlock_i32(l)) as i32 }
extern "C" fn read_unlock(l: *mut LinuxRwLock) { read_drop(rwlock_i32(l)); }
extern "C" fn write_lock(l: *mut LinuxRwLock) { write_take(rwlock_i32(l)); }
extern "C" fn write_trylock(l: *mut LinuxRwLock) -> i32 { write_try(rwlock_i32(l)) as i32 }
extern "C" fn write_unlock(l: *mut LinuxRwLock) { write_drop(rwlock_i32(l)); }

extern "C" fn init_rwsem(s: *mut LinuxRwSem) {
    if s.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned rwsem storage.
    unsafe { (*s).state = 0; }
}
extern "C" fn down_read(s: *mut LinuxRwSem) { read_take(rwsem_i32(s)); }
extern "C" fn down_read_trylock(s: *mut LinuxRwSem) -> i32 { read_try(rwsem_i32(s)) as i32 }
extern "C" fn up_read(s: *mut LinuxRwSem) { read_drop(rwsem_i32(s)); }
extern "C" fn down_write(s: *mut LinuxRwSem) { write_take(rwsem_i32(s)); }
extern "C" fn down_write_trylock(s: *mut LinuxRwSem) -> i32 { write_try(rwsem_i32(s)) as i32 }
extern "C" fn up_write(s: *mut LinuxRwSem) { write_drop(rwsem_i32(s)); }

extern "C" fn sema_init(s: *mut LinuxSemaphore, val: i32) {
    if s.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned semaphore storage.
    unsafe { (*s).lock.state = 0; (*s).count = val.max(0) as u32; (*s).wait_seq = 0; }
}
extern "C" fn down(s: *mut LinuxSemaphore) { while down_trylock(s) != 0 { core::hint::spin_loop(); } }
extern "C" fn down_interruptible(s: *mut LinuxSemaphore) -> i32 { down(s); 0 }
extern "C" fn down_trylock(s: *mut LinuxSemaphore) -> i32 {
    if s.is_null() { return 1; }
    let c = sem_count_u32(s);
    loop {
        let v = c.load(Ordering::Acquire);
        if v == 0 { return 1; }
        if c.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() { return 0; }
    }
}
extern "C" fn up(s: *mut LinuxSemaphore) {
    if s.is_null() { return; }
    sem_count_u32(s).fetch_add(1, Ordering::AcqRel);
    sem_wait_u32(s).fetch_add(1, Ordering::Release);
}

extern "C" fn seqlock_init(s: *mut LinuxSeqLock) {
    if s.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned seqlock storage.
    unsafe { (*s).seq = 0; (*s).lock = 0; }
}
extern "C" fn write_seqlock(s: *mut LinuxSeqLock) {
    if s.is_null() { return; }
    lock_u32(seq_lock_u32(s));
    seq_u32(s).fetch_add(1, Ordering::Release);
}
extern "C" fn write_sequnlock(s: *mut LinuxSeqLock) {
    if s.is_null() { return; }
    seq_u32(s).fetch_add(1, Ordering::Release);
    unlock_u32(seq_lock_u32(s));
}
extern "C" fn read_seqbegin(s: *mut LinuxSeqLock) -> u32 {
    if s.is_null() { return 0; }
    loop {
        let v = seq_u32(s).load(Ordering::Acquire);
        if v & 1 == 0 { return v; }
        core::hint::spin_loop();
    }
}
extern "C" fn read_seqretry(s: *mut LinuxSeqLock, start: u32) -> i32 {
    if s.is_null() { return 0; }
    (seq_u32(s).load(Ordering::Acquire) != start) as i32
}

extern "C" fn init_completion(c: *mut LinuxCompletion) {
    if c.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned completion storage.
    unsafe { (*c).done = 0; }
}
extern "C" fn reinit_completion(c: *mut LinuxCompletion) { init_completion(c); }
extern "C" fn complete(c: *mut LinuxCompletion) { if !c.is_null() { done_u32(c).fetch_add(1, Ordering::Release); } }
extern "C" fn complete_all(c: *mut LinuxCompletion) { if !c.is_null() { done_u32(c).store(COMPLETE_ALL, Ordering::Release); } }
extern "C" fn wait_for_completion(c: *mut LinuxCompletion) { while try_wait_for_completion(c) == 0 { core::hint::spin_loop(); } }
extern "C" fn wait_for_completion_interruptible(c: *mut LinuxCompletion) -> i32 { wait_for_completion(c); 0 }
extern "C" fn wait_for_completion_timeout(c: *mut LinuxCompletion, timeout: usize) -> usize {
    if try_wait_for_completion(c) != 0 { timeout.max(1) } else { 0 }
}
extern "C" fn try_wait_for_completion(c: *mut LinuxCompletion) -> i32 {
    if c.is_null() { return 0; }
    let d = done_u32(c);
    loop {
        let v = d.load(Ordering::Acquire);
        if v == 0 { return 0; }
        if v == COMPLETE_ALL { return 1; }
        if d.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() { return 1; }
    }
}
extern "C" fn completion_done(c: *mut LinuxCompletion) -> i32 {
    if c.is_null() { 0 } else { (done_u32(c).load(Ordering::Acquire) != 0) as i32 }
}

extern "C" fn init_waitqueue_head(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait-queue storage.
    unsafe { (*w).seq = 0; }
}
extern "C" fn __init_waitqueue_head(w: *mut LinuxWaitQueueHead, _name: *const u8, _key: *mut c_void) {
    init_waitqueue_head(w);
}
extern "C" fn __init_swait_queue_head(w: *mut LinuxSwaitQueueHead, _name: *const u8, _key: *mut c_void) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned simple wait-queue storage.
    unsafe { (*w).seq = 0; }
}
extern "C" fn wake_up(w: *mut LinuxWaitQueueHead) { wake_up_all(w); }
extern "C" fn __wake_up(w: *mut LinuxWaitQueueHead, _mode: u32, _nr: i32, _key: *mut c_void) -> i32 {
    wake_up_all(w);
    1
}
extern "C" fn wake_up_all(w: *mut LinuxWaitQueueHead) { if !w.is_null() { waitq_u32(w).fetch_add(1, Ordering::Release); } }
extern "C" fn waitqueue_active(w: *mut LinuxWaitQueueHead) -> i32 {
    if w.is_null() { 0 } else { (waitq_u32(w).load(Ordering::Acquire) != 0) as i32 }
}
extern "C" fn init_wait_entry(e: *mut LinuxWaitQueueEntry, flags: i32) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags = flags as u32; (*e).private = core::ptr::null_mut(); (*e).func = core::ptr::null_mut(); (*e).seq = 0; }
}
extern "C" fn prepare_to_wait_event(w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry, state: i32) -> isize {
    if e.is_null() { return 0; }
    let seq = if w.is_null() { 0 } else { waitq_u32(w).load(Ordering::Acquire) };
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).seq = seq; (*e).flags |= TASK_WAKE | state as u32; }
    0
}
extern "C" fn finish_wait(_w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags &= !TASK_WAKE; }
}
extern "C" fn __rcu_read_lock() { sched::rcu_read_lock(); }
extern "C" fn __rcu_read_unlock() {
    // SAFETY: module caller pairs this with a preceding __rcu_read_lock.
    unsafe { sched::rcu_read_unlock(); }
}
extern "C" fn synchronize_rcu() { sync::synchronize_rcu(); }
extern "C" fn rcu_barrier() { sync::rcu_barrier(); }

extern "C" fn atomic_read(v: *mut LinuxAtomic) -> i32 { if v.is_null() { 0 } else { atomic_i32(v).load(Ordering::Acquire) } }
extern "C" fn atomic_set(v: *mut LinuxAtomic, n: i32) { if !v.is_null() { atomic_i32(v).store(n, Ordering::Release); } }
extern "C" fn atomic_inc(v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_add(1, Ordering::AcqRel); } }
extern "C" fn atomic_dec(v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_sub(1, Ordering::AcqRel); } }
extern "C" fn atomic_add(n: i32, v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_add(n, Ordering::AcqRel); } }
extern "C" fn atomic_sub(n: i32, v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_sub(n, Ordering::AcqRel); } }
extern "C" fn atomic_dec_and_test(v: *mut LinuxAtomic) -> i32 {
    if v.is_null() { 0 } else { (atomic_i32(v).fetch_sub(1, Ordering::AcqRel) == 1) as i32 }
}
extern "C" fn atomic_inc_return(v: *mut LinuxAtomic) -> i32 {
    if v.is_null() { 0 } else { atomic_i32(v).fetch_add(1, Ordering::AcqRel) + 1 }
}

extern "C" fn refcount_set(r: *mut LinuxRefcount, n: u32) { if !r.is_null() { ref_u32(r).store(n, Ordering::Release); } }
extern "C" fn refcount_read(r: *mut LinuxRefcount) -> u32 { if r.is_null() { 0 } else { ref_u32(r).load(Ordering::Acquire) } }
extern "C" fn refcount_inc(r: *mut LinuxRefcount) { if !r.is_null() { ref_u32(r).fetch_add(1, Ordering::AcqRel); } }
extern "C" fn refcount_dec_and_test(r: *mut LinuxRefcount) -> i32 {
    if r.is_null() { 0 } else { (ref_u32(r).fetch_sub(1, Ordering::AcqRel) == 1) as i32 }
}
extern "C" fn refcount_warn_saturate(r: *mut LinuxRefcount, _t: i32) { if !r.is_null() { ref_u32(r).store(u32::MAX, Ordering::Release); } }
extern "C" fn kref_init(k: *mut LinuxKref) {
    if k.is_null() { return; }
    refcount_set(kref_refs(k), 1);
}
extern "C" fn kref_get(k: *mut LinuxKref) {
    if k.is_null() { return; }
    refcount_inc(kref_refs(k));
}
extern "C" fn kref_put(k: *mut LinuxKref, release: Option<KrefRelease>) -> i32 {
    if k.is_null() { return 0; }
    let zero = refcount_dec_and_test(kref_refs(k));
    if zero != 0 {
        if let Some(f) = release { f(k); }
    }
    zero
}

extern "C" fn lockdep_set_class(_lock: *mut u8, _key: *mut u8) {}
extern "C" fn lockdep_set_class_and_name(_lock: *mut u8, _key: *mut u8, _name: *const u8) {}

fn lock_u32(a: &AtomicU32) {
    while a.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}
fn try_lock_u32(a: &AtomicU32) -> bool {
    a.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}
fn unlock_u32(a: &AtomicU32) { a.store(0, Ordering::Release); }
fn load_u32(a: &AtomicU32) -> u32 { a.load(Ordering::Acquire) }

fn read_take(a: &AtomicI32) { while !read_try(a) { core::hint::spin_loop(); } }
fn read_try(a: &AtomicI32) -> bool {
    loop {
        let v = a.load(Ordering::Acquire);
        if v < 0 { return false; }
        if a.compare_exchange_weak(v, v + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { return true; }
    }
}
fn read_drop(a: &AtomicI32) { a.fetch_sub(1, Ordering::Release); }
fn write_take(a: &AtomicI32) { while !write_try(a) { core::hint::spin_loop(); } }
fn write_try(a: &AtomicI32) -> bool {
    a.compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok()
}
fn write_drop(a: &AtomicI32) { a.store(0, Ordering::Release); }

fn field_u32(p: *mut LinuxSpinlock) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
fn mutex_u32(p: *mut LinuxMutex) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
fn seq_u32(p: *mut LinuxSeqLock) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid seqlock pointer; seq is first u32 field.
    let q = unsafe { &mut (*p).seq as *mut u32 };
    atomic_u32(q)
}
fn seq_lock_u32(p: *mut LinuxSeqLock) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid seqlock pointer; lock is atomic word storage.
    let q = unsafe { &mut (*p).lock as *mut u32 };
    atomic_u32(q)
}
fn done_u32(p: *mut LinuxCompletion) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
fn waitq_u32(p: *mut LinuxWaitQueueHead) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
fn rwlock_i32(p: *mut LinuxRwLock) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
fn rwsem_i32(p: *mut LinuxRwSem) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
fn sem_count_u32(p: *mut LinuxSemaphore) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid semaphore pointer; count is atomic word storage.
    let q = unsafe { &mut (*p).count as *mut u32 };
    atomic_u32(q)
}
fn sem_wait_u32(p: *mut LinuxSemaphore) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid semaphore pointer; wait_seq is atomic word storage.
    let q = unsafe { &mut (*p).wait_seq as *mut u32 };
    atomic_u32(q)
}
fn atomic_i32(p: *mut LinuxAtomic) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
fn ref_u32(p: *mut LinuxRefcount) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
fn kref_refs(k: *mut LinuxKref) -> *mut LinuxRefcount {
    // SAFETY: non-null kref points at C storage whose first field is refs.
    unsafe { &mut (*k).refs }
}
fn unsafe_field_u32(p: *mut u32) -> *mut u32 { p }
fn unsafe_field_i32(p: *mut i32) -> *mut i32 { p }
fn atomic_u32(p: *mut u32) -> &'static AtomicU32 {
    // SAFETY: Linux C structs store these fields as naturally aligned u32 words.
    unsafe { &*(p as *const AtomicU32) }
}
fn atomic_i32_word(p: *mut i32) -> &'static AtomicI32 {
    // SAFETY: Linux C structs store these fields as naturally aligned i32 words.
    unsafe { &*(p as *const AtomicI32) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symtab;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn spin_mutex_and_rw_paths_round_trip() {
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
        symtab::_reset();
        export_symbols();
        for name in ["spin_lock", "raw_spin_lock", "mutex_lock", "read_lock",
            "down_read", "seqlock_init", "complete", "wake_up", "atomic_inc",
            "refcount_inc", "kref_put", "lockdep_set_class", "down_interruptible"] {
            assert!(symtab::resolve(name, true).is_ok(), "{name}");
        }
    }
}
