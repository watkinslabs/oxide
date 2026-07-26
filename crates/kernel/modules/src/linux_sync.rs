// Linux synchronization KPI exports for loadable drivers.
use core::ffi::c_void;
use sync::IrqGate;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
#[path = "linux_sync_wait.rs"]
mod wait;
use wait::{wait_cell, WAIT_COMPLETION, WAIT_MUTEX, WAIT_QUEUE, WAIT_SEM};

/// Arch IRQ gate backing the module ABI's `_irq` / `_irqsave` lock variants.
#[cfg(target_arch = "x86_64")]
type ModIrq = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
type ModIrq = hal_aarch64::ArmIrqGate;

const WRITER: i32 = -1;
const COMPLETE_ALL: u32 = u32::MAX;
const TASK_WAKE: u32 = 1;
const LINUX_EINTR: i32 = 4;
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
// The `_bh` / `_irq` / `_irqsave` variants each promised to exclude a context
// and delivered a bare `raw_spin_lock`. A module doing
// `spin_lock_bh(&lock)` got NO bottom-half exclusion, so its softirq could
// re-enter the section it believed it owned; `spin_lock_irqsave` returned a
// fabricated flags value of 0 and left interrupts enabled, so a handler could
// spin on a lock its own CPU held. Silent data corruption and a hard CPU wedge
// respectively — the ABI advertised the guarantee and provided none
// (`skizm.md` §2 item A, Step 9).
//
// Each now does what its name says, using the same primitives core uses:
// `sched::bh::{local_bh_disable, local_bh_enable}` and the arch `IrqGate`.
// Ordering matches Linux and `Spinlock::lock_bh`: the lock is released BEFORE
// bottom halves or interrupts are re-enabled, because the drain that
// `local_bh_enable` may run is entitled to take that same lock.

extern "C" fn raw_spin_lock_bh(l: *mut LinuxSpinlock) {
    sched::bh::local_bh_disable();
    raw_spin_lock(l);
}
extern "C" fn raw_spin_unlock_bh(l: *mut LinuxSpinlock) {
    raw_spin_unlock(l);
    // SAFETY: pairs the local_bh_disable in raw_spin_lock_bh; the lock is already released, so an inline softirq drain here cannot deadlock against it.
    unsafe { sched::bh::local_bh_enable(); }
}

extern "C" fn raw_spin_lock_irq(l: *mut LinuxSpinlock) {
    // SAFETY: paired with the enable in raw_spin_unlock_irq, per the caller's Linux contract that the two bracket one critical section.
    unsafe { <ModIrq as IrqGate>::save_disable(); }
    raw_spin_lock(l);
}
extern "C" fn raw_spin_unlock_irq(l: *mut LinuxSpinlock) {
    raw_spin_unlock(l);
    // Linux `spin_unlock_irq` is `local_irq_enable()`, NOT a restore: it
    // unconditionally enables and the caller asserts it was not already in an
    // IRQ-disabled section. `save_enable` is that enable; its returned prior
    // state is deliberately discarded.
    //
    // A synthetic flags word must never be handed to `restore` instead — on
    // x86 `restore` is `popfq`, which writes the WHOLE of RFLAGS, so a
    // fabricated "IF set" token would clobber the arithmetic flags, DF and
    // IOPL along with it.
    // SAFETY: enables IRQs after the lock is released, per the caller's spin_unlock_irq contract.
    unsafe { let _ = <ModIrq as IrqGate>::save_enable(); }
}

extern "C" fn raw_spin_lock_irqsave(l: *mut LinuxSpinlock) -> usize {
    // SAFETY: the returned token is handed back to raw_spin_unlock_irqrestore, which restores exactly this state — the Linux irqsave contract.
    let flags = unsafe { <ModIrq as IrqGate>::save_disable() };
    raw_spin_lock(l);
    flags as usize
}
extern "C" fn raw_spin_unlock_irqrestore(l: *mut LinuxSpinlock, flags: usize) {
    raw_spin_unlock(l);
    // SAFETY: `flags` is the token returned by the matching raw_spin_lock_irqsave; restoring it re-establishes the caller's prior IRQ state.
    unsafe { <ModIrq as IrqGate>::restore(flags as u64); }
}

extern "C" fn mutex_init(m: *mut LinuxMutex) {
    if m.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned mutex storage.
    unsafe { (*m).state = 0; }
}
extern "C" fn __mutex_init(m: *mut LinuxMutex, _name: *const u8, _key: *mut c_void) { mutex_init(m); }
extern "C" fn mutex_lock(m: *mut LinuxMutex) { let _ = mutex_lock_common(m, false); }
extern "C" fn mutex_lock_interruptible(m: *mut LinuxMutex) -> i32 { mutex_lock_common(m, true) }
extern "C" fn mutex_trylock(m: *mut LinuxMutex) -> i32 { try_lock_u32(mutex_u32(m)) as i32 }
extern "C" fn mutex_unlock(m: *mut LinuxMutex) {
    if m.is_null() { return; }
    let cell = wait_cell(m as usize, WAIT_MUTEX);
    let gate = cell.gate.lock();
    unlock_u32(mutex_u32(m));
    drop(gate);
    cell.wake_one();
}
extern "C" fn mutex_is_locked(m: *mut LinuxMutex) -> i32 { load_u32(mutex_u32(m)) as i32 }
fn mutex_lock_common(m: *mut LinuxMutex, interruptible: bool) -> i32 {
    if m.is_null() { return 0; }
    let cell = wait_cell(m as usize, WAIT_MUTEX);
    loop {
        let gate = cell.gate.lock();
        if try_lock_u32(mutex_u32(m)) { drop(gate); return 0; }
        if interruptible && signal_pending() { drop(gate); return -LINUX_EINTR; }
        cell.park_locked();
        drop(gate);
        cell.yield_parked();
    }
}

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
extern "C" fn down(s: *mut LinuxSemaphore) { let _ = down_common(s, false); }
extern "C" fn down_interruptible(s: *mut LinuxSemaphore) -> i32 { down_common(s, true) }
extern "C" fn down_trylock(s: *mut LinuxSemaphore) -> i32 { (!sem_take(s)) as i32 }
fn sem_take(s: *mut LinuxSemaphore) -> bool {
    if s.is_null() { return false; }
    let c = sem_count_u32(s);
    loop { let v = c.load(Ordering::Acquire); if v == 0 { return false; } if c.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() { return true; } }
}
extern "C" fn up(s: *mut LinuxSemaphore) {
    if s.is_null() { return; }
    let cell = wait_cell(s as usize, WAIT_SEM);
    let gate = cell.gate.lock();
    sem_count_u32(s).fetch_add(1, Ordering::AcqRel);
    sem_wait_u32(s).fetch_add(1, Ordering::Release);
    drop(gate);
    cell.wake_one();
}
fn down_common(s: *mut LinuxSemaphore, interruptible: bool) -> i32 {
    if s.is_null() { return 0; }
    let cell = wait_cell(s as usize, WAIT_SEM);
    loop {
        let gate = cell.gate.lock();
        if sem_take(s) { drop(gate); return 0; }
        if interruptible && signal_pending() { drop(gate); return -LINUX_EINTR; }
        cell.park_locked();
        drop(gate);
        cell.yield_parked();
    }
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
extern "C" fn complete(c: *mut LinuxCompletion) {
    if c.is_null() { return; }
    let cell = wait_cell(c as usize, WAIT_COMPLETION);
    let gate = cell.gate.lock();
    done_u32(c).fetch_add(1, Ordering::Release);
    drop(gate);
    cell.wake_one();
}
extern "C" fn complete_all(c: *mut LinuxCompletion) {
    if c.is_null() { return; }
    let cell = wait_cell(c as usize, WAIT_COMPLETION);
    let gate = cell.gate.lock();
    done_u32(c).store(COMPLETE_ALL, Ordering::Release);
    drop(gate);
    cell.wake_all();
}
extern "C" fn wait_for_completion(c: *mut LinuxCompletion) { let _ = completion_wait_common(c, false); }
extern "C" fn wait_for_completion_interruptible(c: *mut LinuxCompletion) -> i32 { completion_wait_common(c, true) }
extern "C" fn wait_for_completion_timeout(c: *mut LinuxCompletion, timeout: usize) -> usize {
    if timeout == 0 { return try_wait_for_completion(c) as usize; }
    if try_wait_for_completion(c) != 0 { timeout.max(1) } else { 0 }
}
extern "C" fn try_wait_for_completion(c: *mut LinuxCompletion) -> i32 { completion_take(c) as i32 }
fn completion_take(c: *mut LinuxCompletion) -> bool {
    if c.is_null() { return false; }
    let d = done_u32(c);
    loop {
        let v = d.load(Ordering::Acquire);
        if v == 0 { return false; }
        if v == COMPLETE_ALL { return true; }
        if d.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() { return true; }
    }
}
extern "C" fn completion_done(c: *mut LinuxCompletion) -> i32 {
    if c.is_null() { 0 } else { (done_u32(c).load(Ordering::Acquire) != 0) as i32 }
}
fn completion_wait_common(c: *mut LinuxCompletion, interruptible: bool) -> i32 {
    if c.is_null() { return 0; }
    let cell = wait_cell(c as usize, WAIT_COMPLETION);
    loop {
        let gate = cell.gate.lock();
        if completion_take(c) { drop(gate); return 0; }
        if interruptible && signal_pending() { drop(gate); return -LINUX_EINTR; }
        cell.park_locked();
        drop(gate);
        cell.yield_parked();
    }
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
    if _nr == 1 { wake_up_one(w); } else { wake_up_all(w); }
    1
}
fn wake_up_one(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    waitq_u32(w).fetch_add(1, Ordering::Release);
    wait_cell(w as usize, WAIT_QUEUE).wake_one();
}
extern "C" fn wake_up_all(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    waitq_u32(w).fetch_add(1, Ordering::Release);
    wait_cell(w as usize, WAIT_QUEUE).wake_all();
}
extern "C" fn waitqueue_active(w: *mut LinuxWaitQueueHead) -> i32 {
    if w.is_null() { 0 } else { wait_cell(w as usize, WAIT_QUEUE).active() as i32 }
}
extern "C" fn init_wait_entry(e: *mut LinuxWaitQueueEntry, flags: i32) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags = flags as u32; (*e).private = core::ptr::null_mut(); (*e).func = core::ptr::null_mut(); (*e).seq = 0; }
}
extern "C" fn prepare_to_wait_event(w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry, state: i32) -> isize {
    if e.is_null() { return 0; }
    let cell = if w.is_null() { None } else { Some(wait_cell(w as usize, WAIT_QUEUE)) };
    let gate = cell.map(|c| c.gate.lock());
    let seq = if w.is_null() { 0 } else { waitq_u32(w).load(Ordering::Acquire) };
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).seq = seq; (*e).flags |= TASK_WAKE | state as u32; }
    if let Some(c) = cell { c.park_locked(); }
    drop(gate);
    0
}
extern "C" fn finish_wait(w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags &= !TASK_WAKE; }
    if !w.is_null() { wait_cell(w as usize, WAIT_QUEUE).finish_waiter(); }
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() { t.set_state(sched::TaskState::Runnable); }
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
    while a.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
}
fn try_lock_u32(a: &AtomicU32) -> bool { a.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() }
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
fn write_try(a: &AtomicI32) -> bool { a.compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() }
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
    let q = unsafe { &mut (*p).count as *mut u32 }; atomic_u32(q)
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
#[cfg(target_os = "oxide-kernel")]
fn signal_pending() -> bool { sched::live::deliverable_signals_self() != 0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn signal_pending() -> bool { false }
#[cfg(test)]
#[path = "linux_sync_tests.rs"]
mod tests;
