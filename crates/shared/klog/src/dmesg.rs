use super::{bootcon, cont, console, emit_bytes, emit_bytes_at, lock, now_ns, ratelimit, syslog};

#[cfg(test)]
use super::test_claim;

// ---------------------------------------------------------------
// Klog ring buffer — the in-memory dmesg log. The boot ring starts in static
// storage so faults before the allocator is live are recordable; `log_buf_len`
// later hands the owner a larger early-allocated ring and existing bytes are
// migrated before the new storage is published.
// ---------------------------------------------------------------

const RING_BYTES: usize = 64 * 1024;

/// Current ring capacity for `syslog(SYSLOG_ACTION_SIZE_BUFFER)`.
/// # C: O(1)
pub fn ring_size() -> usize { RING.capacity.load(core::sync::atomic::Ordering::Acquire) }

/// Replace the early static ring with boot-allocated storage. Linux performs
/// this during printk setup, before SMP/userspace readers exist; the caller
/// invokes it during that boot-only window. The allocation is leaked for
/// kernel lifetime, as is Linux's boot-time printk storage.
/// # C: O(old capacity)
pub fn install_ring_storage(storage: &'static mut [u8]) -> bool {
    if storage.len() <= ring_size() { return false; }
    let h = lock::acquire();
    let old_capacity = ring_size();
    let total = RING.total.load(core::sync::atomic::Ordering::Acquire);
    let old_ptr = ring_ptr();
    let retained = core::cmp::min(total, old_capacity);
    let start = total.saturating_sub(retained);
    let new_ptr = storage.as_mut_ptr();
    for i in 0..retained {
        // SAFETY: both regions are valid for their published capacities; the
        // boot-only install window and klog lock exclude concurrent emitters.
        unsafe {
            *new_ptr.add((start + i) % storage.len()) = *old_ptr.add((start + i) % old_capacity);
        }
    }
    RING.head.store(total % storage.len(), core::sync::atomic::Ordering::Release);
    RING.storage.store(new_ptr, core::sync::atomic::Ordering::Release);
    // Publish capacity last so readers that observe it also observe the new
    // pointer and migrated bytes.
    RING.capacity.store(storage.len(), core::sync::atomic::Ordering::Release);
    lock::release(h);
    true
}

/// Total bytes ever written into the ring (monotonic). syslog
/// SYSLOG_ACTION_SIZE_UNREAD reports `min(total, RING_BYTES)`.
/// # C: O(1)
pub fn ring_total() -> usize {
    use core::sync::atomic::Ordering;
    RING.total.load(Ordering::Acquire)
}

/// Position of the oldest byte the ring still holds, in the same total-stream
/// terms as `ring_total`. Anything before it has been overwritten and cannot
/// be replayed to a console registering now.
/// # C: O(1)
pub fn ring_oldest() -> usize { ring_total().saturating_sub(ring_size()) }

struct DmesgRing {
    buf:  core::cell::UnsafeCell<[u8; RING_BYTES]>,
    storage: core::sync::atomic::AtomicPtr<u8>,
    capacity: core::sync::atomic::AtomicUsize,
    head: core::sync::atomic::AtomicUsize,
    /// Total bytes ever written; `head = total % RING_BYTES`.
    /// Exposing total lets readers detect "older bytes overwritten"
    /// without growing the buffer.
    total: core::sync::atomic::AtomicUsize,
}

// SAFETY: DmesgRing's UnsafeCell access is mediated via Acquire/Release
// on `head` / `total` and a single-writer / multi-reader contract:
// invoke_sink calls ring_push from any CPU but each call is a
// short bounded copy that races with concurrent ring_read but
// readers tolerate seeing partially-written bytes (klog isn't a
// reliable transport — UART is the durable copy).
unsafe impl Sync for DmesgRing {}

static RING: DmesgRing = DmesgRing {
    buf:  core::cell::UnsafeCell::new([0u8; RING_BYTES]),
    storage: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    capacity: core::sync::atomic::AtomicUsize::new(RING_BYTES),
    head: core::sync::atomic::AtomicUsize::new(0),
    total: core::sync::atomic::AtomicUsize::new(0),
};

#[inline]
fn ring_ptr() -> *mut u8 {
    let ptr = RING.storage.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() {
        RING.buf.get().cast::<u8>()
    } else {
        ptr
    }
}

#[inline]
pub(crate) fn ring_push(bytes: &[u8]) {
    if bytes.is_empty() { return; }
    use core::sync::atomic::Ordering;
    let capacity = RING.capacity.load(Ordering::Acquire);
    let ptr = ring_ptr();
    // SAFETY: see DmesgRing's Sync impl — racy writes are tolerated;
    // total + head bound the readable window.
    let mut h = RING.head.load(Ordering::Relaxed);
    for &b in bytes {
        // SAFETY: `h` is always below the active ring capacity.
        unsafe { *ptr.add(h) = b; }
        h += 1;
        if h >= capacity { h = 0; }
    }
    RING.head.store(h, Ordering::Release);
    RING.total.fetch_add(bytes.len(), Ordering::AcqRel);
}

/// Read up to `out.len()` bytes from the ring. `cursor` is the
/// caller's position in the total stream (start at 0; persist
/// across calls to read incremental output). Returns
/// `(bytes_read, new_cursor)`. Bytes overwritten since last call
/// are silently dropped — caller sees a contiguous tail of the
/// log even if the cursor lagged.
/// # C: O(out.len())
pub fn ring_read(cursor: usize, out: &mut [u8]) -> (usize, usize) {
    use core::sync::atomic::Ordering;
    let capacity = RING.capacity.load(Ordering::Acquire);
    let total = RING.total.load(Ordering::Acquire);
    if cursor >= total { return (0, total); }
    // Effective start = max(cursor, total - active capacity).
    let start = if total > capacity && cursor < total - capacity {
        total - capacity
    } else {
        cursor
    };
    let avail = total - start;
    let take = core::cmp::min(out.len(), avail);
    // SAFETY: DmesgRing has a Sync impl proven by single-writer head/tail
    // discipline; reader holds head Acquire.
    let ptr = ring_ptr();
    let head = RING.head.load(Ordering::Acquire);
    // Position of `start` in the ring: head - (total - start), mod RING_BYTES.
    let back = total - start;
    let begin = if back <= head { head - back } else { capacity - (back - head) };
    for i in 0..take {
        // SAFETY: `begin + i` is reduced modulo the active ring capacity.
        out[i] = unsafe { *ptr.add((begin + i) % capacity) };
    }
    (take, start + take)
}

/// Emit raw bytes through the configured sink with no prefix or
/// newline. For exception handlers and bring-up diagnostics that
/// need to format hex values; production paths use the level macros
/// which carry the InternedFormat metadata.
/// # C: O(len(bytes))
pub fn write_raw(bytes: &[u8]) {
    emit_bytes(bytes);
}

/// Emit lock-held emergency diagnostics to dmesg and the primary serial
/// console only. Auxiliary console sinks can allocate, so callers holding a
/// leaf allocator lock must use this rather than `write_raw`.
/// # C: O(bytes.len())
pub fn write_primary_raw(bytes: &[u8]) {
    #[cfg(test)]
    test_claim::assert_claimed();
    // Serialised too: an emergency diagnostic spliced by another CPU's normal
    // output is exactly the message we can least afford to lose. Safe from a
    // leaf-lock holder because acquisition is bounded and same-CPU reentrant.
    //
    // Unbuffered by design: this route exists for callers that may not survive
    // to emit a terminating `\n`, so its bytes must reach the wire now. Any
    // partial line this CPU had pending is published first, on the same
    // primary route, so the emergency text lands after it instead of inside it.
    let h = lock::acquire();
    cont::flush_local_primary();
    ring_push(bytes);
    console::primary_only(bytes);
    lock::release(h);
}

/// Emit a 64-bit hexadecimal value through the lock-held diagnostic route.
/// # C: O(16)
pub fn write_primary_hex_u64(v: u64) {
    let mut buf = [0u8; 16];
    let mut i = 0u32;
    while i < 16 {
        let nibble = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        buf[i as usize] = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
        i += 1;
    }
    write_primary_raw(&buf);
}

/// Emit an unsigned decimal value through the non-allocating primary route.
/// # C: O(20)
pub fn write_primary_dec_u64(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut start = buf.len();
    loop {
        start -= 1;
        buf[start] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 { break; }
    }
    write_primary_raw(&buf[start..]);
}

/// `/dev/kmsg` write path: inject a userspace-originated record into the
/// kernel log ring + console. UNGATED by design — unlike the debug klog
/// macros (R06), this is the kmsg device's real write side (early systemd,
/// `logger`, journald-forward), which must function in every build, not a
/// per-subsystem debug trace gated to zero bytes by default.
/// # C: O(len(bytes))
pub fn kmsg_write(bytes: &[u8]) {
    match bootcon::devkmsg_mode() {
        bootcon::DEVKMSG_OFF => return,
        bootcon::DEVKMSG_RATELIMIT if !ratelimit::devkmsg_allow(now_ns()) => return,
        _ => {}
    }
    emit_bytes_at(bytes, kmsg_level(bytes));
}

/// Linux `devkmsg_write` prefix parse: a leading `<N>` carries
/// `facility * 8 + level`; the level is the low 3 bits. Absent or
/// malformed prefix falls back to `default_message_loglevel`.
/// # C: O(1) — reads at most 5 leading bytes.
fn kmsg_level(bytes: &[u8]) -> u32 {
    if bytes.first() != Some(&b'<') { return syslog::DEFAULT_MESSAGE_LOGLEVEL; }
    let mut v: u32 = 0;
    let mut i = 1usize;
    while i < bytes.len() && i < 5 {
        let c = bytes[i];
        if c == b'>' {
            if i == 1 { return syslog::DEFAULT_MESSAGE_LOGLEVEL; }
            return v & 7;
        }
        if !c.is_ascii_digit() { return syslog::DEFAULT_MESSAGE_LOGLEVEL; }
        v = v * 10 + (c - b'0') as u32;
        i += 1;
    }
    syslog::DEFAULT_MESSAGE_LOGLEVEL
}

/// Emit a 64-bit value as 16 lower-case hex digits, no `0x` prefix,
/// no surrounding whitespace. Useful inside fault printers where
/// allocation and formatting machinery are unavailable.
/// # C: O(16)
pub fn write_hex_u64(v: u64) {
    let mut buf = [0u8; 16];
    let mut i = 0u32;
    while i < 16 {
        let nibble = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        buf[i as usize] = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
        i += 1;
    }
    emit_bytes(&buf);
}
