use alloc::sync::Arc;
use syscall::nt_compositor::{self as wire, Opcode};
use super::{binding::{self, Binding}, stream, TransportError};

const LIFETIME_CHECK_NS: u64 = 100_000_000;
const TRANSFER_TIMEOUT_NS: u64 = 5_000_000_000;

pub(super) fn spawn(binding: &Arc<Binding>) -> Result<(), TransportError> {
    for (name, entry) in [("nt-cmp-rx", reader as extern "C" fn(usize) -> !), ("nt-cmp-tx", writer as extern "C" fn(usize) -> !)] {
        let raw = Arc::into_raw(binding.clone());
        // SAFETY: each new worker receives one unique Arc reference; its entry
        // reclaims that reference once and exits via canonical kthread_exit.
        let result = unsafe { sched::live::spawn_kernel_thread(sched::live::next_tid(), name, entry, raw as usize) };
        if result.is_err() {
            // SAFETY: spawn failed before publication, so no worker owns raw.
            unsafe { drop(Arc::from_raw(raw)); }
            binding.cancel(); return Err(TransportError::NoMemory);
        }
    } Ok(())
}

/// Name why a transport worker gave up. Every exit below tears the bridge down
/// and the peer only observes a closed socket, so a connection that dies for
/// one of these reasons is otherwise indistinguishable from any other.
fn teardown(reason: &'static [u8], sequence: u64, hwnd: u64) {
    klog::write_raw(b"[WINDOWS-BRIDGE-DOWN] reason=");
    klog::write_raw(reason);
    klog::write_raw(b" seq=");
    klog::write_hex_u64(sequence);
    klog::write_raw(b" hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b"\n");
}

extern "C" fn reader(arg: usize) -> ! {
    // SAFETY: spawn passed exactly one Arc strong reference to this worker.
    let binding = unsafe { Arc::from_raw(arg as *const Binding) };
    while binding.live() {
        let record = match stream::read_record(|buf| {
            if !binding.live() { return Err(TransportError::Disconnected); }
            // An interrupted partial record cannot be exposed or restarted
            // from its header; terminate the connection on receive errors.
            binding.socket.read_kernel(buf).map_err(|_| TransportError::Disconnected)
        }) {
            Ok(record) => record,
            // Disconnected here is a clean end of stream: the peer process
            // closed or exited. Anything else is a malformed or unreadable
            // record. The two need different investigations, so they are not
            // reported as one reason.
            Err(TransportError::Disconnected) => { teardown(b"rx-peer-closed", 0, 0); break }
            Err(_) => { teardown(b"rx-record-invalid", 0, 0); break }
        };
        let opcode = record.header.opcode;
        let (sequence, hwnd) = (record.header.sequence, record.header.hwnd);
        if opcode == Opcode::Ack {
            let status = wire::u32_at(&record.payload, 0).unwrap_or(u32::MAX);
            if binding.state.lock().queue.acknowledge(sequence, hwnd, status).is_err() {
                teardown(b"rx-ack-unmatched", sequence, hwnd); break;
            }
        } else {
            {
                let mut state = binding.state.lock();
                if record.header.sequence <= state.incoming {
                    let seen = state.incoming; drop(state);
                    teardown(b"rx-sequence-not-increasing", sequence, seen); break;
                }
                state.incoming = record.header.sequence;
            }
            if opcode == Opcode::Monitors {
                match record.monitors() { Ok(monitors) => binding.state.lock().monitors = monitors,
                    Err(_) => { teardown(b"rx-monitors-decode", sequence, hwnd); break } }
            } else if let Some(group) = binding.group.upgrade() {
                // GUI owner alone decides whether an event names a live HWND.
                binding::deliver(&group, &record);
            } else { teardown(b"rx-owner-gone", sequence, hwnd); break; }
        }
        binding.wait.wake_all();
    }
    if !binding.live() { teardown(b"rx-owner-not-live", 0, 0); }
    binding::retire(&binding); drop(binding);
    // SAFETY: reader owns no borrowed task context, spinlocks or pending I/O.
    unsafe { sched::live::kthread_exit(0) }
}

extern "C" fn writer(arg: usize) -> ! {
    // SAFETY: spawn passed exactly one Arc strong reference to this worker.
    let binding = unsafe { Arc::from_raw(arg as *const Binding) };
    while binding.live() {
        let bytes = binding.state.lock().queue.take_send();
        if let Some(bytes) = bytes {
            let deadline = net::sock_clock::monotonic_ns_safe().saturating_add(TRANSFER_TIMEOUT_NS);
            if stream::write_record(&bytes, |slice| write_chunk(&binding, slice, deadline)).is_err() {
                teardown(b"tx-write", 0, 0); break;
            }
            if binding.state.lock().queue.sent().is_err() { teardown(b"tx-sent-unmatched", 0, 0); break; }
            binding.wait.wake_all();
        } else {
            let deadline = net::sock_clock::monotonic_ns_safe().saturating_add(LIFETIME_CHECK_NS);
            // SAFETY: writer holds no queue or socket lock; timed recheck also
            // detects canonical ThreadGroup death if final-exit hook is delayed.
            unsafe { sched::live::wait_event_uninterruptible_until(&binding.wait, deadline,
                net::sock_clock::monotonic_ns_safe, || {
                    let s = binding.state.lock(); s.queue.is_dead() || s.queue.has_send()
                }); }
        }
    }
    binding::retire(&binding); drop(binding);
    // SAFETY: writer has released its record and all socket wait registrations.
    unsafe { sched::live::kthread_exit(0) }
}

fn write_chunk(binding: &Binding, bytes: &[u8], deadline: u64) -> Result<usize, TransportError> {
    loop {
        if !binding.live() { return Err(TransportError::Disconnected); }
        if net::sock_clock::monotonic_ns_safe() >= deadline { return Err(TransportError::Timeout); }
        match binding.capability.write_bounded(bytes) {
            Ok(n) if n > 0 => return Ok(n),
            Err(TransportError::Disconnected) => return Err(TransportError::Disconnected),
            _ => {}
        }
        match binding.pair.arm_stream_write(binding.end, wire::SOCKET_CAP, deadline) {
            net::unix_sock::stream::ArmStreamWrite::PeerClosed => return Err(TransportError::Disconnected),
            net::unix_sock::stream::ArmStreamWrite::Retry => continue,
            net::unix_sock::stream::ArmStreamWrite::Parked => {
                // SAFETY: arm_stream_write registers under the canonical ring
                // lock; consumer capacity changes and cancellation wake it.
                unsafe { binding.pair.writer_waiters(binding.end).wait(); }
                binding.pair.writer_waiters(binding.end).remove_current();
            }
        }
    }
}
