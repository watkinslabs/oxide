use super::*;
use std::{cell::Cell, sync::{Mutex, mpsc}, time::Duration};

thread_local! { static NATIVE_TLS: Cell<u64> = const { Cell::new(0) }; }

struct Probe {
    creator_tid: i64, fail_attach: bool, fail_publish: bool,
    trace: Mutex<Vec<(&'static str, i64)>>, finished: Mutex<Option<mpsc::Sender<()>>>,
}

fn tid() -> i64 {
    // SAFETY: gettid has no pointer arguments or caller-owned state.
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

impl Probe {
    fn note(&self, event: &'static str) { self.trace.lock().unwrap().push((event, tid())); }
}

impl Ops for Probe {
    fn prepare(&self, _: FactoryRequest) -> Result<Prepared, u64> {
        assert_ne!(tid(), self.creator_tid);
        // Real Rust TLS on the pthread created by the production factory.
        NATIVE_TLS.with(|slot| { assert_eq!(slot.get(), 0); slot.set(tid() as u64); });
        // SAFETY: pthread_self is valid after libc's pthread entry initialization.
        assert_ne!(unsafe { libc::pthread_self() } as usize, 0);
        self.note("prepare");
        Ok(Prepared { teb: 0x1000, peb: 0x2000 })
    }
    fn attach(&self, _: Prepared) -> Result<(), u64> {
        NATIVE_TLS.with(|slot| assert_eq!(slot.get(), tid() as u64));
        self.note("attach");
        if self.fail_attach { Err(abi::NOT_READY) } else { Ok(()) }
    }
    fn ready(&self) -> Result<(), u64> { self.note("ready"); Ok(()) }
    fn publish(&self) -> Result<(), u64> {
        assert_eq!(tid(), self.creator_tid);
        assert_eq!(self.trace.lock().unwrap().last().unwrap().0, "ready");
        self.note("publish");
        if self.fail_publish { Err(abi::INVALID) } else { Ok(()) }
    }
    fn enter(&self) -> u64 {
        NATIVE_TLS.with(|slot| assert_eq!(slot.get(), tid() as u64));
        assert_eq!(self.trace.lock().unwrap().last().unwrap().0, "publish");
        self.note("enter"); 0
    }
    fn release(&self) {
        self.note("release");
        if let Some(done) = self.finished.lock().unwrap().take() { done.send(()).unwrap(); }
    }
}

fn run(fail_attach: bool, fail_publish: bool) -> (u64, Vec<(&'static str, i64)>) {
    let (tx, rx) = mpsc::channel();
    let probe = Arc::new(Probe { creator_tid: tid(), fail_attach, fail_publish,
        trace: Mutex::new(Vec::new()), finished: Mutex::new(Some(tx)) });
    let result = create(probe.clone(), FactoryRequest { creator: tid() as u64, generation: 1 });
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let trace = probe.trace.lock().unwrap().clone();
    (result, trace)
}

#[test]
fn real_libc_child_has_tls_before_attach_and_keeps_its_tid_through_entry() {
    let (result, trace) = run(false, false);
    assert_eq!(result, abi::SUCCESS);
    assert_eq!(trace.iter().map(|x| x.0).collect::<Vec<_>>(), ["prepare", "attach", "ready", "publish", "enter", "release"]);
    let child_tid = trace[0].1;
    assert!(trace.iter().filter(|x| x.0 != "publish").all(|x| x.1 == child_tid));
}

#[test]
fn attachment_failure_joins_child_without_publication_or_pe_entry() {
    let (result, trace) = run(true, false);
    assert_eq!(result, abi::NOT_READY);
    assert_eq!(trace.iter().map(|x| x.0).collect::<Vec<_>>(), ["prepare", "attach", "release"]);
}

#[test]
fn handle_publication_failure_releases_native_child_without_pe_entry() {
    let (result, trace) = run(false, true);
    assert_eq!(result, abi::INVALID);
    assert_eq!(trace.iter().map(|x| x.0).collect::<Vec<_>>(), ["prepare", "attach", "ready", "publish", "release"]);
}

#[test]
#[ignore = "requires OXIDE_TEST_NTDLL pointing to the source-built native ntdll.so"]
fn source_built_ntdll_attaches_a_real_pthread_without_replacing_native_tls() {
    use std::ffi::CString;
    let path = CString::new(std::env::var("OXIDE_TEST_NTDLL").expect("source-built ntdll path required")).unwrap();
    // SAFETY: the explicit test fixture path is NUL-terminated and the handle
    // remains loaded until process exit, beyond every borrowed TEB lifetime.
    let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!library.is_null());
    // SAFETY: these two symbols are exported by the source-owned native adapter.
    let attach = unsafe { libc::dlsym(library, c"wine_oxide_attach_thread".as_ptr()) } as usize;
    let current = unsafe { libc::dlsym(library, c"NtCurrentTeb".as_ptr()) } as usize;
    assert_ne!(attach, 0); assert_ne!(current, 0);
    let peb = vec![0u64; 1024].into_boxed_slice();
    let peb_address = peb.as_ptr() as u64;
    let child = std::thread::spawn(move || {
        let mut teb = vec![0u64; 8192].into_boxed_slice();
        let address = teb.as_mut_ptr() as u64;
        teb[0x30 / 8] = address;
        teb[0x40 / 8] = std::process::id() as u64;
        teb[0x48 / 8] = tid() as u64;
        teb[0x60 / 8] = peb_address;
        NATIVE_TLS.with(|slot| slot.set(0xabcddcba));
        // SAFETY: the adapter and accessor use the source-owned native ABI;
        // the aligned TEB/PEB fixture buffers remain alive through pthread join.
        let attach: unsafe extern "C" fn(u64, u64) -> i32 = unsafe { std::mem::transmute(attach) };
        let current: unsafe extern "C" fn() -> u64 = unsafe { std::mem::transmute(current) };
        let before = tid();
        assert_eq!(unsafe { current() }, 0);
        assert_eq!(unsafe { attach(address, peb_address) }, 0);
        assert_eq!(unsafe { current() }, address);
        assert_eq!(tid(), before);
        NATIVE_TLS.with(|slot| assert_eq!(slot.get(), 0xabcddcba));
        assert_eq!(teb[0x48 / 8], before as u64);
        teb
    });
    let teb = child.join().unwrap();
    assert_eq!(teb[0x60 / 8], peb_address);
    drop(teb); drop(peb);
}
