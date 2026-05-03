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

static BYTE_SINK: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Install a UART-style byte sink. `f` is called with prefix +
/// message + `\n` for every klog event whose level isn't suppressed.
/// # C: O(1)
pub fn set_byte_sink(f: LogSink) {
    BYTE_SINK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Detach the sink. Subsequent `__klog_emit` calls become no-ops
/// until `set_byte_sink` is called again.
/// # C: O(1)
pub fn clear_byte_sink() {
    BYTE_SINK.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
}

/// Optional clock thunk: returns "ns since boot" for record
/// timestamping. Boot installs this once the timer is calibrated;
/// until then klog emits without a timestamp prefix.
pub type ClockFn = fn() -> u64;

static CLOCK_FN: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

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
    let raw = BYTE_SINK.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: BYTE_SINK is only ever populated via set_byte_sink, which casts a non-null LogSink fn-pointer into the *mut () slot; reverse-cast restores the original; LogSink has no unsafe contract beyond &[u8] validity, which we hold.
    let f: LogSink = unsafe { core::mem::transmute::<*mut (), LogSink>(raw) };
    f(bytes);
}

/// Emit raw bytes through the configured sink with no prefix or
/// newline. For exception handlers and bring-up diagnostics that
/// need to format hex values; production paths use the level macros
/// which carry the InternedFormat metadata.
/// # C: O(len(bytes))
pub fn write_raw(bytes: &[u8]) {
    invoke_sink(bytes);
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
    invoke_sink(&buf);
}

/// Format and emit one klog event: `[LEVEL] msg\n`. Falls through to
/// a no-op when no sink is installed.
/// # C: O(len(msg))
#[doc(hidden)]
#[inline(always)]
pub fn __klog_emit(entry: &'static InternedFormat) {
    if let Some(ns) = now_ns() {
        emit_timestamp(ns);
    }
    let prefix: &[u8] = match entry.level {
        Level::Error => b"[ERROR] ",
        Level::Warn  => b"[WARN]  ",
        Level::Info  => b"[INFO]  ",
        Level::Debug => b"[DEBUG] ",
        Level::Trace => b"[TRACE] ",
    };
    invoke_sink(prefix);
    invoke_sink(entry.bytes);
    invoke_sink(b"\n");
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
mod tests {
    use super::*;

    struct VecUart(pub alloc::vec::Vec<u8>);
    extern crate alloc;

    impl Uart for VecUart {
        fn write_byte(&mut self, b: u8) { self.0.push(b); }
    }

    #[test]
    fn levels_are_distinct() {
        assert_ne!(Level::Error as u8, Level::Trace as u8);
    }

    #[test]
    fn macro_expands_and_links() {
        kerror!("error path");
        kinfo!("hello");
        kdebug!("dbg");
    }

    #[test]
    fn uart_default_write_bytes_iterates() {
        let mut u = VecUart(alloc::vec::Vec::new());
        u.write_bytes(b"abc");
        assert_eq!(u.0, b"abc");
    }

    // ---------------------------------------------------------------------
    // Byte-sink tests. The sink is process-global; tests serialize on
    // SINK_SERIAL to keep concurrent `cargo test` honest.
    // ---------------------------------------------------------------------

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static SINK_SERIAL: Mutex<()> = Mutex::new(());

    static SINK_BYTES: Mutex<alloc::vec::Vec<u8>> = Mutex::new(alloc::vec::Vec::new());
    fn test_sink(bytes: &[u8]) {
        SINK_BYTES.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(bytes);
    }

    fn drain_sink() -> alloc::vec::Vec<u8> {
        let mut g = SINK_BYTES.lock().unwrap_or_else(|e| e.into_inner());
        let out = g.clone();
        g.clear();
        out
    }

    fn lock_sink() -> std::sync::MutexGuard<'static, ()> {
        SINK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn no_sink_emit_is_noop() {
        let _g = lock_sink();
        clear_byte_sink();
        let _ = drain_sink();
        kinfo!("vanishes without sink");
        assert!(drain_sink().is_empty());
    }

    #[test]
    fn kinfo_with_sink_writes_prefix_message_newline() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kinfo!("init started");
        let out = drain_sink();
        clear_byte_sink();
        assert_eq!(&out[..], b"[INFO]  init started\n");
    }

    #[test]
    fn each_level_uses_its_own_prefix() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kerror!("e");
        kwarn!("w");
        kinfo!("i");
        kdebug!("d");
        ktrace!("t");
        let out = drain_sink();
        clear_byte_sink();
        let expected = b"[ERROR] e\n[WARN]  w\n[INFO]  i\n[DEBUG] d\n[TRACE] t\n";
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn clear_byte_sink_stops_emit() {
        let _g = lock_sink();
        let _ = drain_sink();
        set_byte_sink(test_sink);
        kinfo!("a");
        clear_byte_sink();
        kinfo!("b");
        let out = drain_sink();
        // Only "a" got through; "b" emitted to the cleared sink.
        assert_eq!(&out[..], b"[INFO]  a\n");
    }

    #[test]
    fn sink_invocations_count() {
        let _g = lock_sink();
        let _ = drain_sink();
        // Replace the sink with one that just counts calls.
        static N: AtomicUsize = AtomicUsize::new(0);
        fn counting(_b: &[u8]) { N.fetch_add(1, Ordering::Relaxed); }
        N.store(0, Ordering::Relaxed);
        set_byte_sink(counting);
        kinfo!("hi");
        clear_byte_sink();
        // Three calls per event: prefix, message, newline.
        assert_eq!(N.load(Ordering::Relaxed), 3);
    }
}
