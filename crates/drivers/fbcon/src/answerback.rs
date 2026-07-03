// Deferred VT terminal-answerback delivery — the Linux flip-buffer model.
//
// Terminal answerback (DSR/CPR reply per `CSI n`) is delivered the way
// Linux does it, NOT injected into the tty input ring synchronously under
// the console write lock. In Linux `do_con_write()` on `ESC[6n` calls
// `respond_string()` → `tty_insert_flip_string(port, buf, len)` then
// `tty_flip_buffer_push(port)`: the bytes are QUEUED on the flip buffer
// and a DEFERRED work item (`flush_to_ldisc`) hands them to the line
// discipline — never synchronously under the writer's lock, never from
// printk context, and input-only (never echoed to output).
//
// This module is the flip buffer + `flush_to_ldisc`:
//   * `queue(vt, bytes)`  — `tty_insert_flip_string`: enqueue the reply on
//     VT `vt`'s answerback queue, holding ONLY the per-VT answerback lock
//     (never a tty/console lock). Safe to call while the console write
//     (`VT_STATE`) lock is held.
//   * `drain(sink)`       — `flush_to_ldisc`: pop each VT's queued bytes
//     under its own lock, DROP the lock, then call `sink(vt, bytes)` (which
//     takes the tty input locks) — clean lock order, deferred context.
//     Driven from the timer tick (`tick_poll_combined`), which holds no
//     console write lock and is not printk context.
//
// Host-testable (NOT `cfg(target_os = "oxide-kernel")`): the queue/drain
// decoupling — "the write QUEUES, the tick DRAINS into the input ring" —
// is exercised by `cargo test -p fbcon` without a kernel boot.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use vtdata::N_VT;

/// Total answerback slots: index 0 = system console, 1..=N_VT numbered VTs.
/// # C: const.
pub const N_SLOTS: usize = N_VT + 1;

/// Per-VT answerback queue capacity. A CPR reply is `\x1b[<row>;<col>R`
/// ≈ 12 B; 64 B absorbs back-to-back probes (`ESC[999;999H ESC[6n`).
/// # C: const.
pub const ANSWERBACK_CAP: usize = 64;

struct Answerback {
    data: [u8; ANSWERBACK_CAP],
    len: usize,
}

impl Answerback {
    const fn new() -> Self { Self { data: [0; ANSWERBACK_CAP], len: 0 } }
    /// Append `bytes`, dropping any past the cap (an undrained reply is
    /// stale anyway). # C: O(N).
    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len >= ANSWERBACK_CAP { break; }
            self.data[self.len] = b;
            self.len += 1;
        }
    }
}

/// One answerback queue per VT slot.
static ANSWERBACK: [Spinlock<Answerback, TtyClass>; N_SLOTS] =
    [const { Spinlock::new(Answerback::new()) }; N_SLOTS];

/// True when at least one VT has a pending answerback — a cheap gate so
/// the tick drain skips the per-slot lock scan on the common empty case.
static PENDING: AtomicBool = AtomicBool::new(false);

/// Deferred drain sink: pushes queued answerback bytes into VT `vt`'s tty
/// INPUT ring (Linux `flush_to_ldisc` → ldisc receive). `vt == 0` is the
/// system console; `1..=N_VT` numbered VTs. Provided by the `console`
/// crate at boot; called ONLY from `drain` (timer tick).
pub type ReplyFn = fn(vt: u8, bytes: &[u8]);
static SINK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the deferred answerback drain sink (boot wiring, once).
/// # C: O(1).
pub fn set_sink(f: ReplyFn) {
    SINK.store(f as *mut (), Ordering::Release);
}

/// Clear the deferred answerback drain sink when fbcon unregisters.
/// # C: O(1).
pub fn clear_sink() {
    SINK.store(core::ptr::null_mut(), Ordering::Release);
}

/// `tty_insert_flip_string`: queue an emulator answerback for `vt` for
/// deferred delivery. Holds only the per-VT answerback lock, so it is safe
/// while the console write lock is held. No-op for empty `bytes`.
/// # C: O(N) bytes.
pub fn queue(vt: u8, bytes: &[u8]) {
    if bytes.is_empty() { return; }
    let i = (vt as usize).min(N_SLOTS - 1);
    ANSWERBACK[i].lock().push(bytes);
    PENDING.store(true, Ordering::Release);
}

/// True when any VT has queued answerback bytes awaiting the drain. Test/
/// diagnostic — the drain itself reads-and-clears the flag atomically.
/// # C: O(1).
pub fn has_pending() -> bool { PENDING.load(Ordering::Acquire) }

/// `flush_to_ldisc`: drain every VT's queued answerback into `sink`. Copies
/// each slot's bytes out under its own lock, DROPS the lock, THEN calls
/// `sink` (clean lock order — `sink` takes tty input locks). Deferred:
/// driven from the timer tick, holding no console write lock, not in printk
/// context, input-only. Returns the total bytes drained.
/// # C: O(total queued bytes).
pub fn drain_with(sink: ReplyFn) -> usize {
    if !PENDING.swap(false, Ordering::AcqRel) { return 0; }
    let mut total = 0;
    for i in 0..N_SLOTS {
        let mut buf = [0u8; ANSWERBACK_CAP];
        let n;
        {
            let mut q = ANSWERBACK[i].lock();
            n = q.len;
            if n == 0 { continue; }
            buf[..n].copy_from_slice(&q.data[..n]);
            q.len = 0;
        }
        sink(i as u8, &buf[..n]);
        total += n;
    }
    total
}

/// `flush_to_ldisc` against the registered boot sink. Called from the timer
/// tick. No-op when no sink is installed or nothing is queued.
/// # C: O(total queued bytes).
pub fn drain() {
    if !PENDING.load(Ordering::Acquire) { return; }
    let raw = SINK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: SINK is only set via set_sink with a non-null ReplyFn cast through `as *mut ()`; the reverse cast restores the identical fn signature, and the sink reads its &[u8] argument by length only.
    let f: ReplyFn = unsafe { core::mem::transmute::<*mut (), ReplyFn>(raw) };
    let _ = drain_with(f);
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;
    use vtdata::Emulator;

    // Records (vt, bytes) the drain sink delivered into the "input ring".
    // A Spinlock-guarded static stands in for the tty input ring under
    // no_std (no std thread_local). Tests in this module are serialized
    // (each clears LANDED at its end).
    static LANDED: Spinlock<Vec<(u8, Vec<u8>)>, TtyClass> = Spinlock::new(Vec::new());

    // Serializes the two tests — they share the module-global queue +
    // PENDING flag, so they must not run concurrently. Held for the whole
    // body of each test (cargo runs tests in parallel by default).
    static SERIAL: Spinlock<(), TtyClass> = Spinlock::new(());

    fn record_sink(vt: u8, bytes: &[u8]) {
        let mut v = Vec::new();
        v.extend_from_slice(bytes);
        LANDED.lock().push((vt, v));
    }

    // The decoupling contract (Linux flip-buffer): the write-path QUEUES the
    // answerback (it must NOT reach the input ring synchronously); the
    // deferred tick DRAIN delivers it into the input ring later. Proves the
    // write does not synchronously inject — the exact shape that fixes the
    // boot wedge (no input injection under the console write lock).
    #[test]
    fn write_queues_tick_drains() {
        let _serial = SERIAL.lock();
        LANDED.lock().clear();
        let _ = drain_with(record_sink); // drain any leftover from a prior test
        LANDED.lock().clear();
        // Emulator produces a real CPR answerback for ESC[6n at row1/col1.
        let mut vc = vtdata::Vc::new(80, 24);
        let mut em = Emulator::new();
        em.feed_bytes(&mut vc, b"\x1b[6n");
        let reply = em.take_reply();
        assert!(!reply.is_empty(), "ESC[6n must produce a CPR answerback");
        let mut expect = Vec::new();
        expect.extend_from_slice(reply.as_slice());
        assert_eq!(&expect[..], b"\x1b[1;1R");

        // Queue it for VT 0 (system console) — the write-path action.
        queue(0, &expect);

        // Decoupling: nothing has reached the input ring yet — the write did
        // NOT inject synchronously. Only the pending flag is set.
        assert!(LANDED.lock().is_empty(),
            "answerback reached input ring synchronously — wedge bug");
        assert!(has_pending(), "queued answerback must be marked pending");

        // The deferred tick drain (flush_to_ldisc) delivers into the input
        // ring via the same RX sink keyboard input uses.
        let n = drain_with(record_sink);
        assert_eq!(n, expect.len());
        {
            let v = LANDED.lock();
            assert_eq!(v.len(), 1, "exactly one delivery");
            assert_eq!(v[0].0, 0, "delivered to the system console (vt 0)");
            assert_eq!(v[0].1, expect, "bytes land verbatim in the input ring");
        }
        assert!(!has_pending(), "drain clears the pending flag");

        // Idempotent: a second drain with nothing queued delivers nothing.
        LANDED.lock().clear();
        let n2 = drain_with(record_sink);
        assert_eq!(n2, 0);
        assert!(LANDED.lock().is_empty());
    }

    // Bytes route to the VT they were queued for (a numbered VT here), not
    // unconditionally to the foreground — matches Linux answerback targeting
    // the tty the query was written to.
    #[test]
    fn queue_targets_specific_vt() {
        let _serial = SERIAL.lock();
        LANDED.lock().clear();
        let _ = drain_with(record_sink); // drain any leftover from a prior test
        LANDED.lock().clear();
        queue(3, b"\x1b[0n");
        let _ = drain_with(record_sink);
        {
            let v = LANDED.lock();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].0, 3, "DSR reply targets the VT it was queued for");
            assert_eq!(v[0].1, b"\x1b[0n");
        }
        LANDED.lock().clear();
    }
}
