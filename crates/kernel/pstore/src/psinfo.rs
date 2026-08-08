// The pstore core: which backend is registered, and the capture that runs
// when the kernel is about to stop.
//
// One backend at a time, as in the reference — a second registration is
// refused rather than layered, so there is exactly one place a record can
// come from and exactly one place a record file's contents are read from.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Kernfs as PstoreClass, Spinlock};

use crate::hdr::dump_header;
use crate::kmsg::{capture_window, kmsg_bytes};
use crate::limits::DEFAULT_MAX_REASON;
use crate::ram::RamBackend;
use crate::record::Record;
use crate::uapi::DumpReason;

static BACKEND: Spinlock<Option<Arc<RamBackend>>, PstoreClass> = Spinlock::new(None);

/// The highest-numbered reason a record is captured for. Anything above it
/// is a reason the machine is stopping for on purpose, and the reference
/// does not spend a crash record on it unless a platform asks.
static MAX_REASON: AtomicU32 = AtomicU32::new(DEFAULT_MAX_REASON as u32);

/// Serialises a capture against another CPU's. A crash path never waits for
/// it: a second dump while one is in flight is dropped, because the alternative
/// is spinning on a lock in a kernel that is already failing.
static CAPTURING: AtomicBool = AtomicBool::new(false);

/// How many snapshots have been taken this boot — the reference's
/// `oopscount`, which numbers the header line.
static DUMP_COUNT: AtomicU32 = AtomicU32::new(0);

/// The log snapshot a capture reads into, and the record it composes.
///
/// PREALLOCATED at registration and reused, exactly as the reference keeps a
/// dumper buffer allocated up front: the crash path may be failing because the
/// heap is, so it must not allocate — and it may be running on a kernel stack
/// with only a few KiB left, so the snapshot must not live on the stack either.
/// A 16 KiB array in the dump frame overflowed the 16 KiB kernel stack outright,
/// which is a scribble over the adjacent allocation rather than a fault.
static DUMP_BUFS: Spinlock<Option<DumpBufs>, PstoreClass> = Spinlock::new(None);

struct DumpBufs { log: Vec<u8>, out: Vec<u8> }

/// Bytes of kernel log a capture snapshots. The `kmsg_bytes` window is applied
/// to this snapshot, so it bounds what any record can carry.
pub const DUMP_SNAPSHOT_BYTES: usize = 16 * 1024;

/// Register the persistent-RAM backend. A second call is refused, leaving
/// the first backend in place.
///
/// The dump buffers are allocated HERE, while allocation is still safe: a
/// capture never allocates. # C: O(snapshot)
pub fn register(b: Arc<RamBackend>) -> bool {
    let mut g = BACKEND.lock();
    if g.is_some() { return false; }
    let room = b.dump_room();
    *g = Some(b);
    let mut bufs = DUMP_BUFS.lock();
    if bufs.is_none() {
        let mut log = Vec::new();
        let mut out = Vec::new();
        if log.try_reserve_exact(DUMP_SNAPSHOT_BYTES).is_err() { return true; }
        if out.try_reserve_exact(room + DUMP_SNAPSHOT_BYTES).is_err() { return true; }
        log.resize(DUMP_SNAPSHOT_BYTES, 0);
        *bufs = Some(DumpBufs { log, out });
    }
    true
}

/// Take a snapshot of the kernel log and capture it as a record.
///
/// `read_log(dst) -> (n, total)` fills `dst` with the newest log bytes and
/// reports the stream total. Nothing here allocates and nothing large lands on
/// the stack: both buffers were allocated at registration.
/// # C: O(captured length)
/// # Ctx: any, including a failing kernel with locks held
pub fn capture_snapshot(reason: DumpReason, now: (u64, u32),
                        read_log: impl FnOnce(&mut [u8]) -> (usize, usize)) {
    if !should_capture(reason, max_reason()) { return; }
    let Some(b) = backend() else { return };
    if CAPTURING.swap(true, Ordering::AcqRel) { return; }
    let mut g = DUMP_BUFS.lock();
    if let Some(bufs) = g.as_mut() {
        let (n, total) = read_log(&mut bufs.log);
        let count = DUMP_COUNT.fetch_add(1, Ordering::AcqRel) + 1;
        let (log, out) = (&bufs.log, &mut bufs.out);
        out.clear();
        compose_into(out, reason, count, &log[..n], total, kmsg_bytes(), b.dump_room());
        b.write_dmesg(now.0, now.1, out);
    }
    drop(g);
    CAPTURING.store(false, Ordering::Release);
}

/// The registered backend, if any. # C: O(1)
pub fn backend() -> Option<Arc<RamBackend>> { BACKEND.lock().clone() }

/// Install the reason ceiling (`ramoops.max_reason=`). # C: O(1)
pub fn set_max_reason(r: u8) { MAX_REASON.store(r as u32, Ordering::Release); }

/// The reason ceiling. # C: O(1)
pub fn max_reason() -> u8 { MAX_REASON.load(Ordering::Acquire) as u8 }

/// Whether a dump for `reason` is recorded, given a ceiling of `max`.
///
/// Ungated and separate from the capture so the filter is testable without a
/// backend: a reason numerically above the ceiling is skipped, which is why
/// a normal shutdown does not consume a crash record by default.
/// # C: O(1)
pub fn should_capture(reason: DumpReason, max: u8) -> bool {
    reason != DumpReason::Undef && (reason as u8) <= max
}

/// What one capture writes: the header line naming the reason, then the tail
/// of the log the current `kmsg_bytes` allows.
///
/// The whole `kmsg_bytes` effect lives here, which is why it is a pure
/// function of the log contents rather than something the backend decides.
/// # C: O(captured length)
pub fn compose(reason: DumpReason, count: u32, log: &[u8], total: usize, bytes: u32, room: usize)
    -> Vec<u8>
{
    let mut out = Vec::new();
    compose_into(&mut out, reason, count, log, total, bytes, room);
    out
}

/// [`compose`] into a caller-owned buffer, so the crash path can use one that
/// was allocated before the kernel started failing. # C: O(captured length)
pub fn compose_into(out: &mut Vec<u8>, reason: DumpReason, count: u32, log: &[u8], total: usize,
                    bytes: u32, room: usize) {
    let head = dump_header(reason, count, 1);
    let room = room.saturating_sub(head.len());
    let (start, len) = capture_window(total, bytes, room);
    // `log` is the tail of the stream that is still resident: its last byte
    // is stream position `total`, so the window maps to its end.
    let from = log.len().saturating_sub(total - start);
    let take = core::cmp::min(len, log.len() - from);
    out.extend_from_slice(&head);
    out.extend_from_slice(&log[from..from + take]);
}

/// Capture a record for `reason`, if a backend is registered and the reason
/// is one the backend records.
///
/// `now` supplies the wall clock; `read_log` fills a caller-provided buffer
/// with the newest log bytes and reports the stream total. Both are passed in
/// so this — the decision half — has no dependency on the log or the clock.
/// # C: O(captured length)
/// # Ctx: any, including a failing kernel with locks held
pub fn capture(reason: DumpReason, now: (u64, u32), log: &[u8], total: usize) {
    if !should_capture(reason, max_reason()) { return; }
    let Some(b) = backend() else { return };
    if CAPTURING.swap(true, Ordering::AcqRel) { return; }
    let count = DUMP_COUNT.fetch_add(1, Ordering::AcqRel) + 1;
    let body = compose(reason, count, log, total, kmsg_bytes(), b.dump_room());
    b.write_dmesg(now.0, now.1, &body);
    CAPTURING.store(false, Ordering::Release);
}

/// Every record the registered backend holds. Empty when no backend exists —
/// "having no backend is fine, no records appear".
/// # C: O(region length)
pub fn records() -> Vec<Record> {
    match backend() { Some(b) => b.records(), None => Vec::new() }
}

#[cfg(test)]
#[path = "tests/psinfo.rs"]
mod tests;
