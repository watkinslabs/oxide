// Console line assembly — Linux `vprintk_store`'s `LOG_CONT` /
// `prb_reserve_in_last` (`kernel/printk/printk.c`).
//
// `lock.rs` serialises ONE `emit_bytes_at` call. It does not serialise a LINE:
// every trace site in this kernel builds a line out of many calls —
//
//     klog::write_raw(b"[SIGDELIV tid="); klog::write_dec_u64(tid);
//     klog::write_raw(b" sig=");          klog::write_dec_u64(sig);  ...
//
// — and the lock is dropped between each. Two emitters therefore splice
// mid-token: `[SIGDELIV tid=[SIGDELIV tid=43304327 sig= sig=3333`. B1471 made
// signal delivery run on EVERY return to user mode (syscall, IRQ, exception),
// which multiplied the emitters and turned a rare race into the normal case.
//
// Linux has the identical shape and the identical answer: a `pr_cont` fragment
// appends to the last record only while `caller_id` matches
// (`prb_reserve_in_last` compares it), and the record is finalized — made
// visible to consoles — only on `LOG_NEWLINE`. A different caller gets its own
// record rather than splicing into someone else's.
//
// So: buffer bytes per CPU until `\n`, hand the assembled line to the ring and
// the consoles in ONE fan-out, and flush early when the caller identity changes
// (a hard IRQ logging while task context is mid-line) or the buffer fills. A
// line can still be SPLIT in two; it can no longer be SPLICED.
//
// Reentrancy: a sink that itself logs (fbcon diagnostics) re-enters here on the
// same CPU while that slot is mid-append. Such a call bypasses the buffer and
// emits directly, exactly as `lock.rs` lets same-CPU nesting proceed without
// blocking — a lock or a buffer that wedges the console is worse than a split
// line. The exposed window is one `memcpy`, not the whole multi-call line.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

/// Longest line assembled before a forced partial flush. Sized for the widest
/// trace line in the tree (an `execve` path plus argv counts); longer output
/// flushes in pieces rather than truncating.
const CONT_LINE_MAX: usize = 512;
/// One slot per CPU, mirroring `cpu::MAX_CPUS`. klog has no dependencies (`sync`
/// depends on klog), so the bound is restated here rather than imported.
const NR_SLOTS: usize = 64;
/// Sentinel: slot holds no partial line.
const NO_CALLER: u32 = u32::MAX;

/// Destination for an assembled line. The primary route skips auxiliary
/// consoles, which can allocate — `write_primary_raw`'s callers may hold a leaf
/// allocator lock.
pub(crate) const ROUTE_FANOUT: u32 = 0;
/// Ring + primary serial console only.
pub(crate) const ROUTE_PRIMARY: u32 = 1;

/// Linux `printk_caller_id()`: the task pid in task context, `CALLER_ID_MASK +
/// cpu` in interrupt context. Installed by the kernel once a scheduler exists;
/// until then every caller reports the same identity, which is correct because
/// the console is still single-threaded.
pub type CallerFn = fn() -> u32;

static CALLER_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the caller-identity thunk (Linux `printk_caller_id`).
/// # C: O(1)
pub fn set_caller_fn(f: CallerFn) {
    CALLER_FN.store(f as *mut (), Ordering::Release);
}

/// Detach the caller-identity thunk.
/// # C: O(1)
pub fn clear_caller_fn() {
    CALLER_FN.store(core::ptr::null_mut(), Ordering::Release);
}

/// # C: O(1)
fn caller_id() -> u32 {
    let raw = CALLER_FN.load(Ordering::Acquire);
    if raw.is_null() { return 0; }
    // SAFETY: CALLER_FN is only ever populated by set_caller_fn, which stores a
    // valid CallerFn fn-pointer cast through `as *mut ()`; the reverse
    // transmute restores the identical signature. CallerFn carries no unsafe
    // contract.
    let f: CallerFn = unsafe { core::mem::transmute::<*mut (), CallerFn>(raw) };
    f()
}

struct Slot {
    buf:   UnsafeCell<[u8; CONT_LINE_MAX]>,
    len:   AtomicUsize,
    owner: AtomicU32,
    lvl:   AtomicU32,
    route: AtomicU32,
    /// Set for the duration of an append/flush on this slot. A nested emit
    /// (sink that logs) sees it and takes the direct path instead of corrupting
    /// the partially written buffer.
    busy:  AtomicBool,
}

// SAFETY: every access is bracketed by the console owner lock (`lock.rs`) and
// by this slot's `busy` flag, and each slot is indexed by the CPU that owns it,
// so the UnsafeCell has one writer at a time. The lock's bounded-spin steal can
// in principle break that on a presumed-dead holder; the outcome is a garbled
// diagnostic line, the same tolerance `DmesgRing` documents, never a wild write
// (`len` is bounds-checked against CONT_LINE_MAX on every push).
unsafe impl Sync for Slot {}

impl Slot {
    const fn new() -> Self {
        Slot {
            buf:   UnsafeCell::new([0u8; CONT_LINE_MAX]),
            len:   AtomicUsize::new(0),
            owner: AtomicU32::new(NO_CALLER),
            lvl:   AtomicU32::new(0),
            route: AtomicU32::new(ROUTE_FANOUT),
            busy:  AtomicBool::new(false),
        }
    }
}

static SLOTS: [Slot; NR_SLOTS] = [const { Slot::new() }; NR_SLOTS];

/// This CPU's slot, or `None` before the cpu-id thunk exists (still UP, so
/// there is nothing to serialise and the pre-B1474 direct path is correct).
/// # C: O(1)
fn slot() -> Option<&'static Slot> {
    let cpu = crate::lock::cpu_index()?;
    SLOTS.get(cpu)
}

/// Emit the slot's assembled bytes and reset it. Caller holds the console lock
/// and the slot's `busy` flag.
fn drain(s: &Slot, route_override: Option<u32>) {
    let len = s.len.swap(0, Ordering::AcqRel);
    s.owner.store(NO_CALLER, Ordering::Release);
    if len == 0 { return; }
    let route = route_override.unwrap_or_else(|| s.route.load(Ordering::Acquire));
    let lvl = s.lvl.load(Ordering::Acquire);
    // SAFETY: `busy` is held by this call and `len` was just taken, so no other
    // append can be mid-write into this slot; `len <= CONT_LINE_MAX` by the
    // bounds check in `push`.
    let buf = unsafe { &*s.buf.get() };
    crate::flush_line(&buf[..len], lvl, route);
    // A FORCED drain (owner change, full buffer, emergency write) publishes an
    // unterminated fragment. Terminate it: otherwise the next line begins on
    // the same output line and a reader sees `foo` + `bar` as `foobar` — a
    // split that reads as a splice, which is the defect this module exists to
    // remove. A drain on `\n` already ends the line and adds nothing.
    if buf[len - 1] != b'\n' { crate::flush_line(b"\n", lvl, route); }
}

/// Append `bytes` (no `\n` inside) to the slot, flushing first if it would
/// overflow. Caller holds the console lock and `busy`.
fn push(s: &Slot, bytes: &[u8], lvl: u32, route: u32, id: u32) {
    let mut off = 0usize;
    while off < bytes.len() {
        let len = s.len.load(Ordering::Acquire);
        if len >= CONT_LINE_MAX { drain(s, None); continue; }
        let take = core::cmp::min(CONT_LINE_MAX - len, bytes.len() - off);
        // SAFETY: `busy` is held, so this slot has a single writer; `len + take
        // <= CONT_LINE_MAX` by the `min` above.
        let buf = unsafe { &mut *s.buf.get() };
        buf[len..len + take].copy_from_slice(&bytes[off..off + take]);
        s.len.store(len + take, Ordering::Release);
        s.owner.store(id, Ordering::Release);
        s.lvl.store(lvl, Ordering::Release);
        s.route.store(route, Ordering::Release);
        off += take;
    }
}

/// Assemble `bytes` into this CPU's line buffer, emitting each completed line
/// as one fan-out. Caller holds the console lock.
/// # C: O(bytes.len())
pub(crate) fn append(bytes: &[u8], lvl: u32, route: u32) {
    let Some(s) = slot() else { return crate::flush_line(bytes, lvl, route) };
    if s.busy.swap(true, Ordering::AcqRel) {
        // Nested emit from inside a sink: the buffer is mid-write, so go direct.
        return crate::flush_line(bytes, lvl, route);
    }
    let id = caller_id();
    // Linux `prb_reserve_in_last`: a fragment only joins the pending record
    // when the caller matches. A different caller (or route) publishes what is
    // pending and starts its own line rather than splicing into this one.
    let pending = s.len.load(Ordering::Acquire) != 0;
    if pending && (s.owner.load(Ordering::Acquire) != id || s.route.load(Ordering::Acquire) != route) {
        drain(s, None);
    }
    let mut start = 0usize;
    while start < bytes.len() {
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'\n' { end += 1; }
        let newline = end < bytes.len();
        if newline { end += 1; }
        push(s, &bytes[start..end], lvl, route, id);
        // Linux finalizes the record on LOG_NEWLINE; consoles never observe a
        // half-assembled line.
        if newline { drain(s, None); }
        start = end;
    }
    s.busy.store(false, Ordering::Release);
}

/// Publish this CPU's partial line on the primary route before an emergency
/// write. Primary-only because `write_primary_raw`'s callers may hold a leaf
/// allocator lock and an auxiliary console can allocate. Caller holds the
/// console lock.
/// # C: O(CONT_LINE_MAX)
pub(crate) fn flush_local_primary() {
    let Some(s) = slot() else { return };
    if s.busy.swap(true, Ordering::AcqRel) { return; }
    drain(s, Some(ROUTE_PRIMARY));
    s.busy.store(false, Ordering::Release);
}

/// Publish every CPU's partial line on the primary route. For panic/oops paths,
/// where the bytes still sitting in a buffer are the ones that name the fault.
/// # C: O(NR_SLOTS × CONT_LINE_MAX)
pub fn flush() {
    let h = crate::lock::acquire();
    let mut i = 0usize;
    while i < NR_SLOTS {
        let s = &SLOTS[i];
        // A panic can interrupt an append mid-write; publishing a torn tail is
        // better than dropping the line that explains the panic.
        s.busy.store(true, Ordering::Release);
        drain(s, Some(ROUTE_PRIMARY));
        s.busy.store(false, Ordering::Release);
        i += 1;
    }
    crate::lock::release(h);
}
