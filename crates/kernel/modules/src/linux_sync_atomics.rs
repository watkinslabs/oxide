use super::*;

pub(super) extern "C" fn atomic_read(v: *mut LinuxAtomic) -> i32 { if v.is_null() { 0 } else { atomic_i32(v).load(Ordering::Acquire) } }
pub(super) extern "C" fn atomic_set(v: *mut LinuxAtomic, n: i32) { if !v.is_null() { atomic_i32(v).store(n, Ordering::Release); } }
pub(super) extern "C" fn atomic_inc(v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_add(1, Ordering::AcqRel); } }
pub(super) extern "C" fn atomic_dec(v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_sub(1, Ordering::AcqRel); } }
pub(super) extern "C" fn atomic_add(n: i32, v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_add(n, Ordering::AcqRel); } }
pub(super) extern "C" fn atomic_sub(n: i32, v: *mut LinuxAtomic) { if !v.is_null() { atomic_i32(v).fetch_sub(n, Ordering::AcqRel); } }
pub(super) extern "C" fn atomic_dec_and_test(v: *mut LinuxAtomic) -> i32 {
    if v.is_null() { 0 } else { (atomic_i32(v).fetch_sub(1, Ordering::AcqRel) == 1) as i32 }
}
pub(super) extern "C" fn atomic_inc_return(v: *mut LinuxAtomic) -> i32 {
    if v.is_null() { 0 } else { atomic_i32(v).fetch_add(1, Ordering::AcqRel) + 1 }
}

pub(super) extern "C" fn refcount_set(r: *mut LinuxRefcount, n: u32) { if !r.is_null() { ref_u32(r).store(n, Ordering::Release); } }
pub(super) extern "C" fn refcount_read(r: *mut LinuxRefcount) -> u32 { if r.is_null() { 0 } else { ref_u32(r).load(Ordering::Acquire) } }
pub(super) extern "C" fn refcount_inc(r: *mut LinuxRefcount) { if !r.is_null() { ref_u32(r).fetch_add(1, Ordering::AcqRel); } }
pub(super) extern "C" fn refcount_dec_and_test(r: *mut LinuxRefcount) -> i32 {
    if r.is_null() { 0 } else { (ref_u32(r).fetch_sub(1, Ordering::AcqRel) == 1) as i32 }
}
pub(super) extern "C" fn refcount_warn_saturate(r: *mut LinuxRefcount, _t: i32) { if !r.is_null() { ref_u32(r).store(u32::MAX, Ordering::Release); } }
pub(crate) extern "C" fn kref_init(k: *mut LinuxKref) {
    if k.is_null() { return; }
    refcount_set(kref_refs(k), 1);
}
pub(crate) extern "C" fn kref_get(k: *mut LinuxKref) {
    if k.is_null() { return; }
    refcount_inc(kref_refs(k));
}
pub(crate) extern "C" fn kref_put(k: *mut LinuxKref, release: Option<KrefRelease>) -> i32 {
    if k.is_null() { return 0; }
    let zero = refcount_dec_and_test(kref_refs(k));
    if zero != 0 {
        if let Some(f) = release { f(k); }
    }
    zero
}

pub(super) extern "C" fn lockdep_set_class(_lock: *mut u8, _key: *mut u8) {}
pub(super) extern "C" fn lockdep_set_class_and_name(_lock: *mut u8, _key: *mut u8, _name: *const u8) {}

pub(super) fn lock_u32(a: &AtomicU32) {
    while a.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() { sync::spin_relax::relax(); }
}
pub(super) fn try_lock_u32(a: &AtomicU32) -> bool { a.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() }
pub(super) fn unlock_u32(a: &AtomicU32) { a.store(0, Ordering::Release); }
pub(super) fn load_u32(a: &AtomicU32) -> u32 { a.load(Ordering::Acquire) }
pub(super) fn read_take(a: &AtomicI32) { while !read_try(a) { sync::spin_relax::relax(); } }
pub(super) fn read_try(a: &AtomicI32) -> bool {
    loop {
        let v = a.load(Ordering::Acquire);
        if v < 0 { return false; }
        if a.compare_exchange_weak(v, v + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { return true; }
    }
}
pub(super) fn read_drop(a: &AtomicI32) { a.fetch_sub(1, Ordering::Release); }
pub(super) fn write_take(a: &AtomicI32) { while !write_try(a) { sync::spin_relax::relax(); } }
pub(super) fn write_try(a: &AtomicI32) -> bool { a.compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() }
pub(super) fn write_drop(a: &AtomicI32) { a.store(0, Ordering::Release); }
pub(super) fn field_u32(p: *mut LinuxSpinlock) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
pub(super) fn mutex_u32(p: *mut LinuxMutex) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
pub(super) fn seq_u32(p: *mut LinuxSeqLock) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid seqlock pointer; seq is first u32 field.
    let q = unsafe { &mut (*p).seq as *mut u32 };
    atomic_u32(q)
}
pub(super) fn seq_lock_u32(p: *mut LinuxSeqLock) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid seqlock pointer; lock is atomic word storage.
    let q = unsafe { &mut (*p).lock as *mut u32 };
    atomic_u32(q)
}
pub(super) fn done_u32(p: *mut LinuxCompletion) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
pub(super) fn waitq_u32(p: *mut LinuxWaitQueueHead) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
pub(super) fn rwlock_i32(p: *mut LinuxRwLock) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
pub(super) fn rwsem_i32(p: *mut LinuxRwSem) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
pub(super) fn sem_count_u32(p: *mut LinuxSemaphore) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid semaphore pointer; count is atomic word storage.
    let q = unsafe { &mut (*p).count as *mut u32 }; atomic_u32(q)
}
pub(super) fn sem_wait_u32(p: *mut LinuxSemaphore) -> &'static AtomicU32 {
    // SAFETY: caller supplies a valid semaphore pointer; wait_seq is atomic word storage.
    let q = unsafe { &mut (*p).wait_seq as *mut u32 };
    atomic_u32(q)
}
pub(super) fn atomic_i32(p: *mut LinuxAtomic) -> &'static AtomicI32 { atomic_i32_word(unsafe_field_i32(p.cast())) }
pub(super) fn ref_u32(p: *mut LinuxRefcount) -> &'static AtomicU32 { atomic_u32(unsafe_field_u32(p.cast())) }
pub(super) fn kref_refs(k: *mut LinuxKref) -> *mut LinuxRefcount {
    // SAFETY: non-null kref points at C storage whose first field is refs.
    unsafe { &mut (*k).refs }
}
pub(super) fn unsafe_field_u32(p: *mut u32) -> *mut u32 { p }
pub(super) fn unsafe_field_i32(p: *mut i32) -> *mut i32 { p }
pub(super) fn atomic_u32(p: *mut u32) -> &'static AtomicU32 {
    // SAFETY: Linux C structs store these fields as naturally aligned u32 words.
    unsafe { &*(p as *const AtomicU32) }
}
pub(super) fn atomic_i32_word(p: *mut i32) -> &'static AtomicI32 {
    // SAFETY: Linux C structs store these fields as naturally aligned i32 words.
    unsafe { &*(p as *const AtomicI32) }
}

