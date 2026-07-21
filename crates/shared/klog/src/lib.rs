// Minimal kernel logger skeleton per docs/04 (FROZEN).
// Format strings interned in `.klog_strings` (per `04` format-interning OQ
// resolution = defmt-style linker section). Userspace decoder resolves
// strings by virtual address. UART backend is HAL-pluggable; the wiring
// lands once HAL is frozen and `kernel/_start` exists.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod ring;
pub use ring::{Full, Record, Ring, MAIN_RING_CAP, NMI_RING_CAP};

pub mod console;
pub use console::{
    register_console, unregister_console, ConsoleSink, CON_ENABLED, MAX_CONSOLES,
};

/// Maximum base-10 digits in a `u64` (`18446744073709551615`).
const U64_DECIMAL_BYTES: usize = 20;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
    Trace = 4,
}

/// UART-shaped sink. HAL or test code provides an impl.
///
/// # C: O(1) per byte
pub trait Uart {
    /// # C: O(1)
    fn write_byte(&mut self, b: u8);

    /// # C: O(n) n=bytes.len()
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }
}

#[doc(hidden)]
pub struct InternedFormat {
    pub level: Level,
    pub bytes: &'static [u8],
}

/// Byte-level sink installed at boot. The boot crate constructs a
/// 16550 / PL011 driver and registers a thunk via `set_byte_sink`.
/// Until that happens (`__klog_emit` called pre-boot, or no UART
/// available), the emit path is a single Acquire load + branch and
/// returns without touching the formatter.
///
/// Stored as a raw `*mut ()` so we can keep `LogSink` as a plain
/// `fn(&[u8])` without a `dyn` trait object (`07§5` bans `dyn HAL`).
pub type LogSink = fn(&[u8]);

/// Install the primary byte sink (the serial console). Thin shim over the
/// `console` registry's reserved `SLOT_BYTE` so historical callers + the
/// ring→serial→fbcon ordering are preserved (Linux: a UART registering its
/// `struct console`). `f` is called with prefix + message + `\n` for every
/// klog event whose level isn't suppressed.
/// # C: O(1)
pub fn set_byte_sink(f: LogSink) {
    console::install_slot(console::SLOT_BYTE, f);
}

/// Install the secondary sink (the fbcon VT console). Thin shim over the
/// `console` registry's reserved `SLOT_AUX`; fires after the byte sink for
/// every emitted record. Used to route klog text to a framebuffer console,
/// network log target, or any other downstream consumer.
/// # C: O(1)
pub fn set_aux_sink(f: LogSink) {
    console::install_slot(console::SLOT_AUX, f);
}

/// Detach the aux sink (clears reserved `SLOT_AUX`).
/// # C: O(1)
pub fn clear_aux_sink() {
    console::clear_slot(console::SLOT_AUX);
}

/// Detach the primary byte sink (clears reserved `SLOT_BYTE`). Subsequent
/// `__klog_emit` calls skip it until `set_byte_sink` is called again.
/// # C: O(1)
pub fn clear_byte_sink() {
    console::clear_slot(console::SLOT_BYTE);
}

/// Optional clock thunk: returns "ns since boot" for record
/// timestamping. Boot installs this once the timer is calibrated;
/// until then klog emits without a timestamp prefix.
pub type ClockFn = fn() -> u64;

static CLOCK_FN: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static LINE_START: core::sync::atomic::AtomicBool
    = core::sync::atomic::AtomicBool::new(true);

/// Install a `now_ns` callback. Subsequent klog records get a
/// `[<sec>.<ms>] ` prefix before the level marker.
/// # C: O(1)
pub fn set_clock_fn(f: ClockFn) {
    CLOCK_FN.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Detach the clock. Subsequent klog records skip the timestamp.
/// # C: O(1)
pub fn clear_clock_fn() {
    CLOCK_FN.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
}

#[inline]
fn now_ns() -> Option<u64> {
    let raw = CLOCK_FN.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: CLOCK_FN is only ever populated via set_clock_fn,
    // which casts a non-null fn-pointer into the *mut () slot;
    // reverse-cast restores the original. ClockFn has no unsafe
    // contract beyond returning a u64.
    let f: ClockFn = unsafe { core::mem::transmute::<*mut (), ClockFn>(raw) };
    Some(f())
}

/// Emit `v` as a decimal natural-width integer through the sink.
/// # C: O(log10(v)) ≤ 20 bytes for u64::MAX.
pub fn write_dec_u64(v: u64) {
    let mut buf = [0u8; U64_DECIMAL_BYTES];
    let n = write_dec(&mut buf, v, false);
    emit_bytes(&buf[..n]);
}

/// Write decimal `v` into `out`. If `pad3` is true, zero-pads to 3
/// digits; otherwise emits the natural width. Returns bytes written.
fn write_dec(out: &mut [u8], mut v: u64, pad3: bool) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while v > 0 && n < tmp.len() {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    if pad3 {
        while n < 3 { tmp[n] = b'0'; n += 1; }
    }
    let mut i = 0usize;
    while n > 0 {
        n -= 1;
        if i >= out.len() { break; }
        out[i] = tmp[n];
        i += 1;
    }
    i
}

/// Emit `[<sec>.<frac3>] ` via the sink — seconds + millisecond
/// fractional, padded to 3 digits.
fn emit_timestamp(ns: u64) {
    let secs = ns / 1_000_000_000;
    let ms   = (ns % 1_000_000_000) / 1_000_000;
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    buf[i] = b'['; i += 1;
    i += write_dec(&mut buf[i..], secs, false);
    buf[i] = b'.'; i += 1;
    i += write_dec(&mut buf[i..], ms, true);
    buf[i] = b']'; i += 1;
    buf[i] = b' '; i += 1;
    invoke_sink(&buf[..i]);
}

#[inline]
fn invoke_sink(bytes: &[u8]) {
    ring_push(bytes);
    // printk fan-out (Linux `console_unlock`): the dmesg ring first, then
    // every registered console (reserved BYTE=serial, AUX=fbcon, then any
    // `register_console` slots) in order. The transmute safety lives in
    // `console::fan_out`.
    console::fan_out(bytes);
}

fn emit_bytes(bytes: &[u8]) {
    let Some(_) = now_ns() else {
        invoke_sink(bytes);
        return;
    };
    if bytes.is_empty() { return; }

    let mut start = 0usize;
    while start < bytes.len() {
        if LINE_START.swap(false, core::sync::atomic::Ordering::AcqRel) {
            if let Some(ns) = now_ns() {
                emit_timestamp(ns);
            }
        }

        let mut end = start;
        while end < bytes.len() && bytes[end] != b'\n' {
            end += 1;
        }
        if end < bytes.len() {
            end += 1;
            invoke_sink(&bytes[start..end]);
            LINE_START.store(true, core::sync::atomic::Ordering::Release);
        } else {
            invoke_sink(&bytes[start..end]);
        }
        start = end;
    }
}

// ---------------------------------------------------------------
// Klog ring buffer — the in-memory dmesg log. 64 KiB ring; older
// bytes get overwritten by newer ones (no allocation, no waiters).
// ---------------------------------------------------------------

const RING_BYTES: usize = 64 * 1024;

/// Public copy of the ring buffer size for `syslog(SYSLOG_ACTION_SIZE_BUFFER)`.
/// # C: O(1)
pub const fn ring_size() -> usize { RING_BYTES }

/// Total bytes ever written into the ring (monotonic). syslog
/// SYSLOG_ACTION_SIZE_UNREAD reports `min(total, RING_BYTES)`.
/// # C: O(1)
pub fn ring_total() -> usize {
    use core::sync::atomic::Ordering;
    RING.total.load(Ordering::Acquire)
}

struct DmesgRing {
    buf:  core::cell::UnsafeCell<[u8; RING_BYTES]>,
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
    head: core::sync::atomic::AtomicUsize::new(0),
    total: core::sync::atomic::AtomicUsize::new(0),
};

#[inline]
fn ring_push(bytes: &[u8]) {
    if bytes.is_empty() { return; }
    use core::sync::atomic::Ordering;
    // SAFETY: see DmesgRing's Sync impl — racy writes are tolerated;
    // total + head bound the readable window.
    let buf = unsafe { &mut *RING.buf.get() };
    let mut h = RING.head.load(Ordering::Relaxed);
    for &b in bytes {
        buf[h] = b;
        h += 1;
        if h >= RING_BYTES { h = 0; }
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
    let total = RING.total.load(Ordering::Acquire);
    if cursor >= total { return (0, total); }
    // Effective start = max(cursor, total - RING_BYTES).
    let start = if total > RING_BYTES && cursor < total - RING_BYTES {
        total - RING_BYTES
    } else {
        cursor
    };
    let avail = total - start;
    let take = core::cmp::min(out.len(), avail);
    // SAFETY: DmesgRing has a Sync impl proven by single-writer head/tail discipline; reader holds head Acquire.
    let buf = unsafe { &*RING.buf.get() };
    let head = RING.head.load(Ordering::Acquire);
    // Position of `start` in the ring: head - (total - start), mod RING_BYTES.
    let back = total - start;
    let begin = if back <= head { head - back } else { RING_BYTES - (back - head) };
    for i in 0..take {
        out[i] = buf[(begin + i) % RING_BYTES];
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
    ring_push(bytes);
    console::primary_only(bytes);
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
    emit_bytes(bytes);
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

/// Format and emit one klog event: `[LEVEL] msg\n`. Falls through to
/// a no-op when no sink is installed.
/// # C: O(len(msg))
#[doc(hidden)]
#[inline(always)]
pub fn __klog_emit(entry: &'static InternedFormat) {
    let prefix: &[u8] = match entry.level {
        Level::Error => b"[ERROR] ",
        Level::Warn  => b"[WARN]  ",
        Level::Info  => b"[INFO]  ",
        Level::Debug => b"[DEBUG] ",
        Level::Trace => b"[TRACE] ",
    };
    emit_bytes(prefix);
    emit_bytes(entry.bytes);
    emit_bytes(b"\n");
}

/// Emit an interned format string at the given level. `$msg` must be
/// a `&'static str` literal per `07§5` (compile-time interning).
///
/// Expansion places the format string into `.klog_strings` (a custom
/// linker section per `07§6`), then calls into `__klog_emit` with a
/// pointer into that section. The userspace decoder reads
/// `.klog_strings` from the kernel image and resolves the address.
#[macro_export]
macro_rules! klog {
    ($lvl:ident, $msg:literal $(,)?) => {{
        #[link_section = ".klog_strings"]
        static __KLOG_STR: $crate::InternedFormat = $crate::InternedFormat {
            level: $crate::Level::$lvl,
            bytes: $msg.as_bytes(),
        };
        $crate::__klog_emit(&__KLOG_STR);
    }};
}

/// Convenience wrappers per `04` log surface.
#[macro_export]
macro_rules! kerror { ($msg:literal $(,)?) => { $crate::klog!(Error, $msg) }; }
#[macro_export]
macro_rules! kwarn  { ($msg:literal $(,)?) => { $crate::klog!(Warn,  $msg) }; }
#[macro_export]
macro_rules! kinfo  { ($msg:literal $(,)?) => { $crate::klog!(Info,  $msg) }; }
#[macro_export]
macro_rules! kdebug { ($msg:literal $(,)?) => { $crate::klog!(Debug, $msg) }; }
#[macro_export]
macro_rules! ktrace { ($msg:literal $(,)?) => { $crate::klog!(Trace, $msg) }; }

#[cfg(test)]
mod tests;
