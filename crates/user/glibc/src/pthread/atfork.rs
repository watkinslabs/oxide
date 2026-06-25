// pthread_atfork (docs/59§6 G11/§9.1). Register prepare/parent/child handlers
// run around fork(2): prepare in LIFO before the fork, parent/child in FIFO
// after. Fixed registry (covers real usage); spinlock-guarded registration.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, Ordering};

type Handler = Option<extern "C" fn()>;
const MAX: usize = 64;

struct Reg { prepare: [Handler; MAX], parent: [Handler; MAX], child: [Handler; MAX], n: usize }
struct Cell(UnsafeCell<Reg>);
// SAFETY: the registry is a process-global; all access is serialized by LOCK
// (a test-and-set spinlock) and fork handlers run single-threaded around fork.
unsafe impl Sync for Cell {}
static REG: Cell = Cell(UnsafeCell::new(Reg { prepare: [None; MAX], parent: [None; MAX], child: [None; MAX], n: 0 }));
static LOCK: AtomicI32 = AtomicI32::new(0);

fn lock() { while LOCK.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); } }
fn unlock() { LOCK.store(0, Ordering::Release); }

// # C: int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
#[no_mangle]
pub extern "C" fn pthread_atfork(prepare: Handler, parent: Handler, child: Handler) -> i32 {
    lock();
    // SAFETY: LOCK is held, so this is the sole writer of the registry slot.
    let r = unsafe { &mut *REG.0.get() };
    if r.n >= MAX { unlock(); return 12; } // ENOMEM
    r.prepare[r.n] = prepare; r.parent[r.n] = parent; r.child[r.n] = child; r.n += 1;
    unlock();
    0
}

// # C: int __register_atfork(..., void *dso_handle) — DSO handle ignored here.
#[no_mangle]
pub extern "C" fn __register_atfork(
    prepare: Handler,
    parent: Handler,
    child: Handler,
    dso_handle: *mut core::ffi::c_void,
) -> i32 {
    let _ = dso_handle;
    pthread_atfork(prepare, parent, child)
}

/// # C: internal — run pthread_atfork prepare handlers (LIFO) before fork(2).
/// The lock is held across the fork (released by run_parent/run_child, or
/// abort_unlock on fork failure) so the registry stays stable for both procs.
pub(crate) fn run_prepare() {
    lock();
    // SAFETY: LOCK held; snapshot count and call each prepare handler newest-first.
    let r = unsafe { &*REG.0.get() };
    let n = r.n;
    for i in (0..n).rev() { if let Some(f) = r.prepare[i] { f(); } }
}
/// # C: internal — release the held atfork lock when fork(2) fails.
pub(crate) fn abort_unlock() { unlock(); }
/// # C: internal — run atfork parent handlers (FIFO) post-fork, then unlock.
pub(crate) fn run_parent() {
    // SAFETY: post-fork parent; registry is stable (fork is serialized via run_prepare's lock).
    let r = unsafe { &*REG.0.get() };
    for i in 0..r.n { if let Some(f) = r.parent[i] { f(); } }
    unlock();
}
/// # C: internal — run atfork child handlers (FIFO) post-fork, then unlock.
pub(crate) fn run_child() {
    // SAFETY: post-fork child owns the address space copy; run child handlers FIFO.
    let r = unsafe { &*REG.0.get() };
    for i in 0..r.n { if let Some(f) = r.child[i] { f(); } }
    unlock();
}
