// exit family + atexit handlers (docs/59§6 G2/G7d). exit() runs registered
// handlers LIFO then exit_group. Fixed 64-slot registry (atexit returns
// nonzero when full — valid C; unlimited malloc spill is a follow-up).
// abort() exit_group(134); real SIGABRT raise lands at G9.
use core::ffi::c_void;

pub(crate) type AtexitFn = extern "C" fn();
pub(crate) type CxaFn = extern "C" fn(*mut c_void);
// on_exit handler: void (*)(int status, void *arg).
pub(crate) type OnExitFn = extern "C" fn(i32, *mut c_void);

#[derive(Clone, Copy)]
pub(crate) enum Slot { Plain(AtexitFn), Cxa(CxaFn, *mut c_void), OnExit(OnExitFn, *mut c_void) }

const SLOTS: usize = 64;

pub(crate) struct Registry { slots: [Option<Slot>; SLOTS], n: usize }
impl Registry {
    /// # C: empty handler registry
    pub(crate) const fn new() -> Self { Registry { slots: [None; SLOTS], n: 0 } }
    /// # C: register a handler; false if the table is full
    pub(crate) fn push(&mut self, s: Slot) -> bool {
        if self.n < SLOTS { self.slots[self.n] = Some(s); self.n += 1; true } else { false }
    }
    /// # C: invoke all registered handlers in LIFO order, once each (`code` is
    /// the process exit status, passed to on_exit handlers)
    pub(crate) unsafe fn run(&mut self, code: i32) {
        // Each slot holds a handler the caller registered; call each once,
        // newest first. (Calling the fn pointers is type-safe; the unsafe
        // contract is that the registered pointers are still valid.)
        while self.n > 0 {
            self.n -= 1;
            if let Some(s) = self.slots[self.n].take() {
                match s {
                    Slot::Plain(f) => f(),
                    Slot::Cxa(f, a) => f(a),
                    Slot::OnExit(f, a) => f(code, a),
                }
            }
        }
    }
}

// Raw process termination. Always built (used by __libc_start_main and
// __stack_chk_fail); not a C export by itself.
/// # C: exit_group(code) — terminate the whole thread group
#[inline]
pub(crate) fn exit_group(code: i32) -> ! {
    // SAFETY: exit_group(2) terminates every thread in the group with
    // `code` and never returns; no memory is referenced.
    unsafe { crate::arch::syscall::sys1(crate::internal::nr::EXIT_GROUP, code as usize) };
    // SAFETY: exit_group never returns; the kernel has torn down the
    // process, so control provably cannot reach this point.
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(feature = "freestanding")]
pub(crate) use imp::exit;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    struct G { lock: AtomicBool, at: UnsafeCell<Registry>, quick: UnsafeCell<Registry> }
    // SAFETY: both registries are mutated only under `lock`; the raw cells
    // are never aliased across threads.
    unsafe impl Sync for G {}
    static G: G = G { lock: AtomicBool::new(false), at: UnsafeCell::new(Registry::new()), quick: UnsafeCell::new(Registry::new()) };

    fn reg(s: Slot, quick: bool) -> i32 {
        while G.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
        // SAFETY: lock held — exclusive access to the chosen registry.
        let ok = unsafe { (*(if quick { G.quick.get() } else { G.at.get() })).push(s) };
        G.lock.store(false, Ordering::Release);
        if ok { 0 } else { -1 }
    }

    // run the atexit registry (called by exit()), passing the exit status to
    // any on_exit handlers.
    pub(crate) unsafe fn run_atexit(code: i32) {
        // SAFETY: drains the atexit registry once under the lock; handlers
        // were registered by the program and are called newest-first.
        unsafe {
            while G.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
            (*G.at.get()).run(code);
            G.lock.store(false, Ordering::Release);
        }
    }
    unsafe fn run_quick(code: i32) {
        // SAFETY: drains the at_quick_exit registry once under the lock.
        unsafe {
            while G.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
            (*G.quick.get()).run(code);
            G.lock.store(false, Ordering::Release);
        }
    }

    // # C: int atexit(void (*fn)(void))
    #[no_mangle]
    pub extern "C" fn atexit(f: AtexitFn) -> i32 { reg(Slot::Plain(f), false) }
    // # C: int __cxa_atexit(void (*fn)(void*), void *arg, void *dso)
    #[no_mangle]
    pub extern "C" fn __cxa_atexit(f: CxaFn, arg: *mut c_void, _dso: *mut c_void) -> i32 { reg(Slot::Cxa(f, arg), false) }
    // # C: int at_quick_exit(void (*fn)(void))
    #[no_mangle]
    pub extern "C" fn at_quick_exit(f: AtexitFn) -> i32 { reg(Slot::Plain(f), true) }
    // # C: int on_exit(void (*fn)(int, void*), void *arg)
    #[no_mangle]
    pub extern "C" fn on_exit(f: OnExitFn, arg: *mut c_void) -> i32 { reg(Slot::OnExit(f, arg), false) }

    // # C: _Noreturn void exit(int) — run atexit handlers (LIFO) then exit.
    #[no_mangle]
    pub extern "C" fn exit(code: i32) -> ! {
        // SAFETY: run_atexit drains the registry; no stdio buffering yet to
        // flush (G6 follow-up).
        unsafe { run_atexit(code); }
        exit_group(code)
    }
    // # C: _Noreturn void quick_exit(int)
    #[no_mangle]
    pub extern "C" fn quick_exit(code: i32) -> ! {
        // SAFETY: runs the at_quick_exit list then terminates.
        unsafe { run_quick(code); }
        exit_group(code)
    }
    // # C: _Noreturn void _exit(int) — no atexit, no flush.
    #[no_mangle]
    pub extern "C" fn _exit(code: i32) -> ! { exit_group(code) }
    // # C: _Noreturn void _Exit(int) — C99 alias of _exit.
    #[no_mangle]
    pub extern "C" fn _Exit(code: i32) -> ! { exit_group(code) }
    // # C: _Noreturn void abort(void)
    #[no_mangle]
    pub extern "C" fn abort() -> ! {
        // SAFETY: raise SIGABRT (default action terminates with core); if a
        // handler returns or it's blocked/ignored, fall back to exit_group.
        unsafe { crate::signal::sig::raise(6); }
        exit_group(134) // 128 + SIGABRT
    }

    // # C: void __cxa_finalize(void *dso)
    // Runs DSO destructors at dlclose/exit. We register all __cxa_atexit
    // handlers in one global list run at exit(); a per-DSO finalize is a no-op
    // (handlers still run at process exit) — the symbol just needs to exist so
    // DSO _fini stubs link.
    #[no_mangle]
    pub extern "C" fn __cxa_finalize(_dso: *mut c_void) {}

    // # C: _Noreturn void __assert_fail(const char *assertion, const char *file,
    //                                   unsigned int line, const char *function)
    #[no_mangle]
    pub extern "C" fn __assert_fail(assertion: *const u8, file: *const u8, line: u32, function: *const u8) -> ! {
        // SAFETY: the four args are NUL-terminated C strings (or null); we write
        // a diagnostic to fd 2 via the raw write(2) slot, then abort().
        unsafe {
            let w = |s: *const u8| { if !s.is_null() { let mut n = 0usize; while *s.add(n) != 0 { n += 1; } let _ = crate::arch::syscall::sys3(crate::internal::nr::WRITE, 2, s as usize, n); } };
            let lit = |s: &[u8]| { let _ = crate::arch::syscall::sys3(crate::internal::nr::WRITE, 2, s.as_ptr() as usize, s.len()); };
            w(file); lit(b":"); // file:
            // line number (decimal) — small stack buffer
            let mut buf = [0u8; 12]; let mut i = buf.len(); let mut v = line;
            loop { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; if v == 0 { break; } }
            lit(&buf[i..]); lit(b": ");
            w(function); lit(b": Assertion `"); w(assertion); lit(b"' failed.\n");
        }
        abort()
    }

    // # C: _Noreturn void __fortify_fail(const char *msg)
    #[no_mangle]
    pub extern "C" fn __fortify_fail(_msg: *const u8) -> ! {
        abort()
    }

    // # C: _Noreturn void __chk_fail(void)
    #[no_mangle]
    pub extern "C" fn __chk_fail() -> ! {
        abort()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static ORDER: [AtomicUsize; 4] = [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];
    static POS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn h0() { ORDER[POS.fetch_add(1, Ordering::Relaxed)].store(10, Ordering::Relaxed); }
    extern "C" fn h1() { ORDER[POS.fetch_add(1, Ordering::Relaxed)].store(11, Ordering::Relaxed); }
    extern "C" fn h2() { ORDER[POS.fetch_add(1, Ordering::Relaxed)].store(12, Ordering::Relaxed); }

    #[test]
    fn handlers_run_lifo() {
        let mut r = Registry::new();
        assert!(r.push(Slot::Plain(h0)));
        assert!(r.push(Slot::Plain(h1)));
        assert!(r.push(Slot::Plain(h2)));
        // SAFETY: the three handlers are valid; run drains LIFO.
        unsafe { r.run(0); }
        assert_eq!(ORDER[0].load(Ordering::Relaxed), 12);
        assert_eq!(ORDER[1].load(Ordering::Relaxed), 11);
        assert_eq!(ORDER[2].load(Ordering::Relaxed), 10);
        assert_eq!(POS.load(Ordering::Relaxed), 3);
    }
    #[test]
    fn registry_full_returns_false() {
        let mut r = Registry::new();
        for _ in 0..SLOTS { assert!(r.push(Slot::Plain(h0))); }
        assert!(!r.push(Slot::Plain(h0)));
    }
}
