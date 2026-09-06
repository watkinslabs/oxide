use alloc::{sync::Arc, vec::Vec};
use sched::thread_group::ThreadGroup;
use sync::{Spinlock, TaskList};
use syscall::nt_compositor::{Monitor, Opcode, Record};
use super::{Completion, Queue, TransportError};

const HANDSHAKE_NS: u64 = 5_000_000_000;
const MAX_BINDINGS: usize = 128;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xc000_009a;
const STATUS_IO_TIMEOUT: u64 = 0xc000_00b5;
const STATUS_PIPE_DISCONNECTED: u64 = 0xc000_00b0;

/// Called without transport/socket/GUI locks. Canonical GUI owner validates HWND and delivers the event.
pub type EventHandler = fn(&Arc<ThreadGroup>, &Record) -> bool;
static HANDLER: Spinlock<Option<EventHandler>, TaskList> = Spinlock::new(None);
static BINDINGS: Spinlock<Vec<Arc<Binding>>, TaskList> = Spinlock::new(Vec::new());

pub(super) struct State { pub queue: Queue, pub monitors: Vec<Monitor>, pub incoming: u64 }
pub(super) struct Binding {
    pub capability: super::capability::Capability,
    pub state: Spinlock<State, TaskList>,
    pub wait: sched::live::WaitList,
}
impl core::ops::Deref for Binding {
    type Target = super::capability::Capability;
    fn deref(&self) -> &Self::Target { &self.capability }
}

impl Binding {
    pub(super) fn live(&self) -> bool {
        self.owner_live() && !self.state.lock().queue.is_dead()
    }
    pub(super) fn cancel(&self) {
        let old = {
            let mut state = self.state.lock();
            let old = core::mem::replace(&mut state.queue, Queue::new());
            state.queue.close(); state.monitors.clear(); old
        };
        drop(old);
        // Owned capability teardown must wake both workers even if the task's
        // credentials changed since binding. Protocol shutdown has no new admission.
        self.capability.shutdown();
        self.wait.wake_all();
    }
}

fn lookup(group: &Arc<ThreadGroup>) -> Result<Arc<Binding>, TransportError> {
    BINDINGS.lock().iter().find(|b| b.belongs_to(group)).cloned().ok_or(TransportError::Disconnected)
}

/// Install the canonical GUI event consumer before binding launchers. # C: O(1)
pub fn set_event_handler(handler: EventHandler) { *HANDLER.lock() = Some(handler); }

pub(super) fn deliver(group: &Arc<ThreadGroup>, record: &Record) -> bool {
    let handler = *HANDLER.lock(); handler.is_some_and(|f| f(group, record))
}

/// Teardown hook for canonical process final exit. # C: O(bindings + queued bytes)
pub fn disconnect(group: &Arc<ThreadGroup>) {
    let binding = {
        let mut bindings = BINDINGS.lock();
        bindings.iter().position(|b| b.belongs_to(group)).map(|i| bindings.swap_remove(i))
    };
    if let Some(binding) = binding { binding.cancel(); }
}

pub(super) fn retire(binding: &Arc<Binding>) {
    binding.cancel();
    BINDINGS.lock().retain(|b| !Arc::ptr_eq(b, binding));
}

/// Pre-PE binding pins the open file description; CLOEXEC cannot remove the pin.
/// Does not close the numeric fd (a concurrent reuse must never close another file).
/// # C: O(bindings) + bounded handshake wait
/// # Ctx: current process, no GUI/GDI lock; # Sleeps: yes
fn bind_current(fd: u64) -> Result<(), TransportError> {
    if fd > i32::MAX as u64 { return Err(TransportError::Invalid); }
    let cur = sched::live::current().ok_or(TransportError::Invalid)?;
    let file = crate::net_common::fd_file(fd).ok_or(TransportError::Unknown)?;
    let capability = super::capability::Capability::pin(&cur.thread_group, file)?;
    let binding = Arc::new(Binding { capability, state: Spinlock::new(State { queue: Queue::try_new()?, monitors: Vec::new(), incoming: 0 }),
        wait: sched::live::WaitList::new() });
    {
        let mut bindings = BINDINGS.lock();
        if bindings.iter().any(|b| b.group.ptr_eq(&binding.group)) { return Err(TransportError::Busy); }
        if bindings.len() >= MAX_BINDINGS { return Err(TransportError::Full); }
        bindings.try_reserve(1).map_err(|_| TransportError::NoMemory)?;
        bindings.push(binding.clone());
    }
    if let Err(error) = super::worker::spawn(&binding) { retire(&binding); return Err(error); }
    let deadline = net::sock_clock::monotonic_ns_safe().saturating_add(HANDSHAKE_NS);
    // SAFETY: bind_current runs in process context with no locks held; wait
    // publishes and rechecks against the reader's monitor/death notification.
    unsafe { sched::live::wait_event_uninterruptible_until(&binding.wait, deadline,
        net::sock_clock::monotonic_ns_safe, || {
            let s = binding.state.lock(); !s.monitors.is_empty() || s.queue.is_dead()
        }); }
    let result = { let state = binding.state.lock();
        if state.queue.is_dead() { Err(TransportError::Disconnected) }
        else if state.monitors.is_empty() { Err(TransportError::Timeout) } else { Ok(()) }
    };
    if result.is_err() { retire(&binding); } result
}

/// Selector 552, a0 is a Linux fd; callable before NT personality activation. # C: O(bind)
pub fn bind_service(fd: u64) -> u64 {
    match bind_current(fd) { Ok(()) => STATUS_SUCCESS,
        Err(TransportError::Unknown) => STATUS_INVALID_HANDLE,
        Err(TransportError::NoMemory | TransportError::Full) => STATUS_INSUFFICIENT_RESOURCES,
        Err(TransportError::Timeout) => STATUS_IO_TIMEOUT,
        Err(TransportError::Disconnected) => STATUS_PIPE_DISCONNECTED,
        Err(_) => STATUS_INVALID_PARAMETER }
}

/// Only canonical window owners may supply HWND mutations. No window state is retained here.
/// # C: O(payload + bindings); # Sleeps: no socket I/O
pub fn enqueue(group: &Arc<ThreadGroup>, opcode: Opcode, hwnd: u64, payload: Vec<u8>) -> Result<u64, TransportError> {
    let binding = lookup(group)?;
    let mut prepared = Some(super::queue::Prepared::new(opcode, hwnd, payload)?);
    let result = binding.state.lock().queue.enqueue_prepared(&mut prepared);
    if result.is_ok() { binding.wait.wake_all(); } result
}
/// # C: O(payload + bindings)
pub fn enqueue_current(opcode: Opcode, hwnd: u64, payload: Vec<u8>) -> Result<u64, TransportError> {
    let cur = sched::live::current().ok_or(TransportError::Disconnected)?;
    enqueue(&cur.thread_group, opcode, hwnd, payload)
}
/// Wait outside GUI/GDI locks. Terminal completion is consumed for controls and frames alike.
/// Timeout invalidates the connection: an abandoned transaction cannot later claim success.
/// # C: O(bindings + records) + bounded wait; # Sleeps: yes
pub fn wait_completion_current(ticket: u64, timeout_ns: u64) -> Result<Completion, TransportError> {
    let cur = sched::live::current().ok_or(TransportError::Disconnected)?;
    let binding = lookup(&cur.thread_group)?;
    let deadline = net::sock_clock::monotonic_ns_safe().saturating_add(timeout_ns.min(HANDSHAKE_NS));
    // SAFETY: caller has released GUI/GDI locks; the reader publishes ACK or
    // disconnect before waking this wait list, and the condition is rechecked.
    unsafe { sched::live::wait_event_uninterruptible_until(&binding.wait, deadline,
        net::sock_clock::monotonic_ns_safe, || binding.state.lock().queue.completion_ready(ticket)); }
    let result = binding.state.lock().queue.take_completion(ticket);
    if result == Ok(Completion::Pending) { retire(&binding); Err(TransportError::Timeout) } else { result }
}
/// Empty/missing/disconnected desktop data is unavailable. # C: O(bindings + monitors)
pub fn monitors(group: &Arc<ThreadGroup>) -> Option<Vec<Monitor>> {
    let binding = lookup(group).ok()?; let state = binding.state.lock();
    if state.queue.is_dead() || state.monitors.is_empty() { None } else { Some(state.monitors.clone()) }
}
/// # C: O(bindings + monitors)
pub fn monitors_current() -> Option<Vec<Monitor>> { monitors(&sched::live::current()?.thread_group) }
