use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
use syscall::nt_native_thread::{self as abi, FactoryRequest, Prepared};

pub(super) trait Ops: Send + Sync + 'static {
    fn prepare(&self, request: FactoryRequest) -> Result<Prepared, u64>;
    fn attach(&self, prepared: Prepared) -> Result<(), u64>;
    fn ready(&self) -> Result<(), u64>;
    fn publish(&self) -> Result<(), u64>;
    fn enter(&self) -> u64;
    fn release(&self);
}

struct Gate { prepared: AtomicU32, go: AtomicU32 }
const WAITING: u32 = 0;
const READY: u32 = 1;
const START: u32 = 1;
const ABORT: u32 = 2;

fn signal(word: &AtomicU32, value: u32) {
    word.store(value, Ordering::Release);
    // SAFETY: the live Arc owns the aligned futex word throughout wake.
    unsafe { libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, i32::MAX); }
}

fn wait(word: &AtomicU32) -> u32 {
    loop {
        let value = word.load(Ordering::Acquire);
        if value != WAITING { return value; }
        // SAFETY: aligned atomic lives in a shared Arc; no libc lock is held
        // while its canonical native thread sleeps at this publication gate.
        unsafe { libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            WAITING, std::ptr::null::<libc::timespec>()); }
    }
}

pub(super) fn create<O: Ops>(ops: Arc<O>, request: FactoryRequest) -> u64 {
    let gate = Arc::new(Gate { prepared: AtomicU32::new(WAITING), go: AtomicU32::new(WAITING) });
    let child_gate = gate.clone();
    let child_ops = ops.clone();
    let child = match std::thread::Builder::new().name("nt-native".into()).spawn(move || {
        let prepared = match child_ops.prepare(request) {
            Ok(prepared) => prepared,
            Err(status) => { signal(&child_gate.prepared, status as u32); return; }
        };
        if let Err(status) = child_ops.attach(prepared).and_then(|()| child_ops.ready()) {
            child_ops.release(); signal(&child_gate.prepared, status as u32); return;
        }
        signal(&child_gate.prepared, READY);
        if wait(&child_gate.go) == START { let _ = child_ops.enter(); }
        child_ops.release();
        // Returning through std's pthread entry releases native TLS/stack and
        // robust-list/clear-TID state on the very thread that acquired them.
    }) {
        Ok(child) => child,
        Err(_) => return abi::NO_MEMORY,
    };
    let ready = wait(&gate.prepared);
    if ready != READY {
        let _ = child.join();
        return ready as u64;
    }
    if let Err(status) = ops.publish() {
        signal(&gate.go, ABORT);
        let _ = child.join();
        return status;
    }
    signal(&gate.go, START);
    // Dropping a valid JoinHandle delegates normal detached pthread cleanup
    // to libc. Failure paths above join before returning the failed create.
    drop(child);
    abi::SUCCESS
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
