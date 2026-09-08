use alloc::sync::Arc;
use syscall::nt_compositor::{self as wire, Opcode};
use super::{binding::{self, Binding}, stream, Settled, TransportError};

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
/// One line per inbound desktop record and the GUI owner's verdict, so a
/// click or key that never becomes a message can be placed at this boundary.
///
/// Bounded, because this is the input path: a key press is three records and a
/// mouse motion is one, each about fifty bytes on a serial console, written
/// inside the loop that delivers them. Unbounded, a burst of typing spends
/// more time reporting input than delivering it, which is the instrument
/// changing what it measures. The budget covers boot and the first
/// interactions, which is what the boundary is read for.
const EVENT_TRACE_BUDGET: u32 = 64;

fn trace_event(opcode: Opcode, hwnd: u64, accepted: bool) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static SPENT: AtomicU32 = AtomicU32::new(0);
    if SPENT.fetch_add(1, Ordering::Relaxed) >= EVENT_TRACE_BUDGET { return; }
    klog::write_raw(b"[WINDOWS-BRIDGE-EVENT] op=");
    klog::write_hex_u64(opcode as u16 as u64);
    klog::write_raw(b" hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(if accepted { b" accepted=1\n" } else { b" accepted=0\n" });
}

/// One line per record the desktop says it did not carry out. A drawing
/// submission is handed over and nobody waits for its verdict, so a refusal
/// is otherwise invisible: the window keeps its last pixels and every layer
/// above reports success. Bounded, because a refusal that repeats does so per
/// frame and the first few name the boundary just as well.
fn trace_refused(opcode: Opcode, hwnd: u64, sequence: u64, status: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    const BUDGET: u32 = 32;
    static SPENT: AtomicU32 = AtomicU32::new(0);
    if SPENT.fetch_add(1, Ordering::Relaxed) >= BUDGET { return; }
    klog::write_raw(b"[WINDOWS-BRIDGE-REFUSED] op=");
    klog::write_hex_u64(opcode as u16 as u64);
    klog::write_raw(b" hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" seq=");
    klog::write_hex_u64(sequence);
    klog::write_raw(b" status=");
    klog::write_hex_u64(status as u64);
    klog::write_raw(b"\n");
}

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
            match binding.state.lock().queue.acknowledge(sequence, hwnd, status) {
                // The desktop confirming pixels it was handed is the frame
                // milestone; nothing waits on the completion any more, so
                // this is where that acknowledgement is observed.
                Ok(Settled::Presented) => { crate::nt_gdi_frame_trace::acknowledged(sequence); crate::nt_milestone::desktop_ack() }
                Ok(Settled::Carried) => {}
                Ok(Settled::Refused { opcode, status }) => trace_refused(opcode, hwnd, sequence, status),
                Err(_) => { teardown(b"rx-ack-unmatched", sequence, hwnd); break; }
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
                let accepted = binding::deliver(&group, &record);
                trace_event(opcode, hwnd, accepted);
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
        let taken = binding.state.lock().queue.take_send();
        if let Some((sequence, bytes)) = taken {
            crate::nt_gdi_frame_trace::taken(sequence);
            let deadline = net::sock_clock::monotonic_ns_safe().saturating_add(TRANSFER_TIMEOUT_NS);
            if stream::write_record(&bytes, |slice| write_chunk(&binding, slice, deadline)).is_err() {
                teardown(b"tx-write", 0, 0); break;
            }
            crate::nt_gdi_frame_trace::written(sequence);
            if binding.state.lock().queue.sent(sequence).is_err() { teardown(b"tx-sent-unmatched", sequence, 0); break; }
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
