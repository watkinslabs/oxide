//! End-to-end AF_UNIX stream-listener accept-readiness delivery through the
//! REAL `net::UnixListener` + `net::UnixRegistry` + `fs::epoll` objects, not
//! hand-rolled `PollSubscribers` test doubles standing in for the listener.
//!
//! This is the exact wiring `scratch/poll.md` flagged as unresolved:
//! `UnixListener.subs` is a cached `Weak<PollSubscribers>` set once by
//! `register_subs`, rather than a per-`poll()`-call waitqueue registration.
//! The concern was that this side pointer could diverge from whatever
//! `PollSubscribers` `epoll_ctl(ADD)` actually subscribes into
//! (`file.poll_subscribers()`), silently dropping the accept-readiness wake.
//!
//! Note on scope: the real `listen(2)`/`accept(2)` syscall handlers
//! (`net::sock::ops`, `net::sock::io`) are `#[cfg(target_os =
//! "oxide-kernel")]`-only with no hosted/test fallback — unlike
//! `net::unix_sock` (`UnixListener`/`UnixRegistry`), which is unconditionally
//! compiled. `InetFileOps::poll` (the socket inode's `FileOps::poll`) is
//! ALSO kernel-only gated, so a hosted `make_inet_socket_inode` build falls
//! back to the trait's unconditional-ready default (`POLL_IN | POLL_OUT`),
//! which cannot distinguish "before connect" from "after connect" — that
//! path is not meaningfully hosted-testable at all today (see the
//! conformance report for this branch). This test instead wraps the real
//! `Arc<UnixListener>` directly with a thin `FileOps::poll` that calls its
//! real `poll_mask()` (real `accept_q`-driven readiness, not a stub), and
//! shares its `poll_subs` with `register_subs` exactly like the real
//! `ops::listen` does — proving the notify/subscribe wiring itself, while
//! documenting the coverage gap in the InetSocket poll path honestly rather
//! than papering over it with a fake-readiness assertion.
//!
//! It registers the listener fd with `EPOLLET`, which makes
//! `EpollData::rescan_levels()` (the generic per-`epoll_wait` level poll)
//! blind to it — the ONLY way the epitem can land on the ready list is a
//! genuine notify callback fired by `UnixListener::connect_pair`'s
//! `notify_subs()`. If the listener's cached `Weak` ever pointed at a
//! different (or already-dropped) `PollSubscribers` than the one
//! `epoll_ctl(ADD)` subscribed into, this test would see `epoll_wait`
//! report 0 events after a successful connect.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use net::{UnixAddr, UnixListener, UnixRegistry};
use sched::{SchedClass, Task};
use syscall::SyscallArgs;
use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, OpenFlags,
          PollSubscribers, default_inode_ops, mk_mode};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x9300);

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x1;
const EPOLLET: u32 = 1 << 31;

/// Thin `FileOps` reporting the REAL `UnixListener`'s real accept-queue
/// readiness — not a stub, not a manually-toggled atomic.
struct ListenerPollOps(Arc<UnixListener>);
impl FileOps for ListenerPollOps {
    fn poll(&self, _inode: &Inode) -> u32 { self.0.poll_mask() }
}

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: test stores a leaked Task pointer and clears the hook before returning.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn install_current_with_fdt(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x9200, "epoll-listener-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn args(a0: u64, a1: u64, a2: u64, a3: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2, a3, a4: 0, a5: 0 }
}

fn epoll_event(events: u32, data: u64) -> [u8; 12] {
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&events.to_ne_bytes());
    ev[4..12].copy_from_slice(&data.to_ne_bytes());
    ev
}

fn read_epoll_event(ev: &[u8; 12]) -> (u32, u64) {
    let mut e = [0u8; 4];
    let mut d = [0u8; 8];
    e.copy_from_slice(&ev[..4]);
    d.copy_from_slice(&ev[4..12]);
    (u32::from_ne_bytes(e), u64::from_ne_bytes(d))
}

/// Publish a listener fd exactly the way `net::sock::ops::listen`'s AF_UNIX
/// branch wires readiness: `listener.register_subs(&subs)`, and the SAME
/// `subs` shared with the inode epoll actually subscribes into.
fn listener_file(listener: &Arc<UnixListener>) -> Arc<File> {
    let subs = Arc::new(PollSubscribers::new());
    listener.register_subs(&subs);
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Socket, 0o600),
        default_inode_ops(), Arc::new(ListenerPollOps(Arc::clone(listener))))
        .poll_subs_arc(subs)
        .build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[test]
fn unix_listener_connect_wakes_epollet_epitem_through_real_listener_wiring() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Arc::clone(&fdt));

    let registry = UnixRegistry::new();
    let addr = UnixAddr::from_abstract_or_test_path("epoll-listener-wake-test".to_string());
    let listener = registry.bind_addr(addr.clone()).expect("bind AF_UNIX listener");
    listener.listen(16, net::sysctl::DEFAULT_SOMAXCONN);
    let listener_fd = fdt.alloc(listener_file(&listener)).unwrap();

    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    // EPOLLET: EpollData::rescan_levels() explicitly skips ET entries on
    // every epoll_wait, so the only path that can queue this epitem is the
    // listener's own connect() -> notify_subs() -> the subscribed callback.
    let mut add = epoll_event(EPOLLIN | EPOLLET, 0x9200_0001);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, listener_fd as u64,
        add.as_mut_ptr() as u64)), 0);

    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0,
        "no pending connection yet: real accept_q-driven poll_mask() is 0");

    registry.connect_addr(&addr).expect("connect to listener");

    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1,
        "listener connect() must notify the SAME PollSubscribers epoll_ctl(ADD) subscribed to");
    assert_eq!(read_epoll_event(&out), (EPOLLIN, 0x9200_0001));

    // Draining the queued connection clears real listener readiness too —
    // confirms `ListenerPollOps` is reporting genuine accept_q state, not a
    // one-way stub.
    let (_pair, pin) = listener.accept().expect("accept queued connection");
    drop(pin);
    assert_eq!(listener.poll_mask(), 0, "accept_q drained: real listener readiness clears");
    reset();
}
