// What a fatal kernel event does, and how it says so.
//
// Two boot parameters live here because both arch shims and both arch fault
// printers already depend on this crate and on nothing else in common. A copy
// per arch would be two answers to "did the boot line ask for a panic", and
// the aarch64 copy is exactly the one that would be forgotten — its panic
// handler printed nothing at all before this module existed.

use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicBool, Ordering};

/// `panic=0`: stop and keep the console text on screen. The default, because
/// a machine that restarts takes its own evidence away.
pub const PANIC_TIMEOUT_WAIT_FOREVER: i32 = 0;

static PANIC_TIMEOUT: AtomicI32 = AtomicI32::new(PANIC_TIMEOUT_WAIT_FOREVER);
static PANIC_ON_OOPS: AtomicBool = AtomicBool::new(false);
static PANIC_ON_WARN: AtomicBool = AtomicBool::new(false);
static RESTART_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Machine-restart callback, installed by the boot path once the power
/// subsystem is up. `panic=` cannot restart without it.
pub type RestartFn = fn() -> !;

/// Seconds to wait after a panic before restarting; `0` waits forever and a
/// negative value restarts immediately. # C: O(1)
pub fn panic_timeout() -> i32 { PANIC_TIMEOUT.load(Ordering::Acquire) }

/// Record the boot line's `panic=` request. # C: O(1)
pub fn set_panic_timeout(secs: i32) { PANIC_TIMEOUT.store(secs, Ordering::Release); }

/// Does an unhandled kernel fault escalate to a full panic rather than
/// halting the faulting CPU? # C: O(1)
pub fn panic_on_oops() -> bool { PANIC_ON_OOPS.load(Ordering::Acquire) }

/// Record the boot line's `oops=panic` request. # C: O(1)
pub fn set_panic_on_oops(on: bool) { PANIC_ON_OOPS.store(on, Ordering::Release); }

/// THE `oops=panic` escalation, for both arches: an unrecoverable kernel fault
/// becomes a panic, so the panic path's reporting and the `panic=` restart
/// apply instead of the CPU halting, where a wedge looks identical.
///
/// Cold and never inlined so the panic machinery's frame stays here rather
/// than in the callers: both arch fault printers sit on the same stack chain
/// as syscall entry, which runs within 4 KiB of a 16 KiB stack's ceiling, and
/// a path that merely CHECKS this flag should not carry the cost of the branch
/// it does not take.
/// # C: O(1) to decide; diverges when it escalates
#[inline(never)]
#[cold]
pub fn escalate_oops() -> ! { panic!("oops=panic: unrecoverable kernel fault") }

/// Does the FIRST broken invariant stop the machine, rather than being
/// reported and stepped over? # C: O(1)
pub fn panic_on_warn() -> bool { PANIC_ON_WARN.load(Ordering::Acquire) }

/// Record the boot line's `panic_on_warn` request. # C: O(1)
pub fn set_panic_on_warn(on: bool) { PANIC_ON_WARN.store(on, Ordering::Release); }

/// Install the machine-restart callback. # C: O(1)
pub fn set_restart_hook(f: RestartFn) { RESTART_HOOK.store(f as *mut (), Ordering::Release); }

/// The installed restart callback, if any. # C: O(1)
pub fn restart_hook() -> Option<RestartFn> {
    let raw = RESTART_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: RESTART_HOOK is populated only by set_restart_hook, which casts a valid RestartFn pointer into the slot; the reverse cast restores the identical signature and RestartFn carries no unsafe contract.
    Some(unsafe { core::mem::transmute::<*mut (), RestartFn>(raw) })
}

/// What a panic should do once it has finished reporting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterPanic {
    /// Stop this CPU and keep the console text.
    Halt,
    /// Restart the machine after waiting `secs` seconds.
    RestartAfter(u32),
}

/// Decide the post-panic action from a `panic=` value and whether a restart
/// callback is available. Global-free so the decision is testable without
/// panicking. # C: O(1)
pub fn after_panic(timeout: i32, can_restart: bool) -> AfterPanic {
    if !can_restart || timeout == PANIC_TIMEOUT_WAIT_FOREVER { return AfterPanic::Halt; }
    AfterPanic::RestartAfter(if timeout < 0 { 0 } else { timeout as u32 })
}

/// Render a panic to the emergency console route. Non-allocating throughout:
/// a panic reached from inside the allocator must not re-enter it.
/// # C: O(message length)
pub fn report(info: &core::panic::PanicInfo) {
    crate::write_primary_raw(b"\n[PANIC] ");
    if let Some(loc) = info.location() {
        crate::write_primary_raw(loc.file().as_bytes());
        crate::write_primary_raw(b":");
        crate::write_primary_dec_u64(loc.line() as u64);
        crate::write_primary_raw(b": ");
    }
    if let Some(s) = info.message().as_str() {
        crate::write_primary_raw(s.as_bytes());
    } else {
        render_message(info);
    }
    crate::write_primary_raw(b"\n");
}

/// Report `info`, then take the action the boot line asked for. Never
/// returns: either the restart callback takes the machine, or this CPU stops.
/// # C: O(infinity) — by definition
pub fn panic_and_stop(info: &core::panic::PanicInfo) -> ! {
    report(info);
    // Snapshot the log for whatever is registered to keep it across the
    // restart. After the report, so the panic text is inside the snapshot,
    // and here rather than in each arch's handler: when it lived per-arch,
    // one arch had it and the other had a bare spin loop.
    crate::kmsg_dump(crate::kmsg_dump::REASON_PANIC);
    match after_panic(panic_timeout(), restart_hook().is_some()) {
        AfterPanic::Halt => {
            crate::write_primary_raw(b"[PANIC] halted\n");
        }
        AfterPanic::RestartAfter(secs) => {
            crate::write_primary_raw(b"[PANIC] Rebooting in ");
            crate::write_primary_dec_u64(secs as u64);
            crate::write_primary_raw(b" seconds..\n");
            wait_seconds(secs);
            if let Some(restart) = restart_hook() { restart(); }
        }
    }
    loop { core::hint::spin_loop(); }
}

/// Spin until `secs` have elapsed on the monotonic clock. Falls through
/// immediately when no clock is installed — a panic before timekeeping has
/// no way to measure the wait, and stalling forever there would hide the
/// restart the boot line asked for.
/// # C: O(secs)
fn wait_seconds(secs: u32) {
    if secs == 0 { return; }
    let Some(start) = crate::monotonic_ns() else { return };
    let deadline = start.saturating_add(secs as u64 * 1_000_000_000);
    while crate::monotonic_ns().unwrap_or(deadline) < deadline { core::hint::spin_loop(); }
}

/// Render an interpolated panic message (an allocation failure reports the
/// size, so the text must not be dropped) through a STATIC buffer.
///
/// Not a stack buffer: this handler is reachable from the syscall entry path,
/// where its frame sums into every chain that can panic — on aarch64 that
/// pushed the deepest path over the kernel stack ceiling. A panic is one-shot
/// and this CPU is not continuing, so a single claimed buffer is enough; a
/// nested panic that finds it taken prints a marker rather than racing.
/// # C: O(message length)
fn render_message(info: &core::panic::PanicInfo) {
    use core::fmt::Write as _;
    if RENDERING.swap(true, Ordering::AcqRel) {
        crate::write_primary_raw(b"<nested panic>");
        return;
    }
    // SAFETY: RENDERING is claimed by exactly one caller (the swap above returned false), and it is never released, so this is the only reference to MESSAGE_BUF for the remaining life of the machine.
    let buf = unsafe { &mut *MESSAGE_BUF.0.get() };
    let mut sink = StaticSink { buf, len: 0 };
    let _ = core::write!(&mut sink, "{}", info.message());
    let len = sink.len;
    crate::write_primary_raw(&buf[..len]);
}

/// Longest panic message rendered; longer text is truncated rather than
/// allocated for.
const MESSAGE_BUF_LEN: usize = 192;

static RENDERING: AtomicBool = AtomicBool::new(false);

struct MessageBuf(core::cell::UnsafeCell<[u8; MESSAGE_BUF_LEN]>);

// SAFETY: MESSAGE_BUF's cell is reached only through render_message, which
// claims RENDERING with an AcqRel swap and never releases it, so at most one
// caller ever obtains a reference to the buffer.
unsafe impl Sync for MessageBuf {}

static MESSAGE_BUF: MessageBuf = MessageBuf(core::cell::UnsafeCell::new([0; MESSAGE_BUF_LEN]));

/// A bounded formatting sink over the static panic buffer. Truncates rather
/// than allocating — a panic reached from inside the allocator must not
/// re-enter it.
struct StaticSink<'a> { buf: &'a mut [u8; MESSAGE_BUF_LEN], len: usize }

impl core::fmt::Write for StaticSink<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_keeps_the_console_text() {
        assert_eq!(after_panic(PANIC_TIMEOUT_WAIT_FOREVER, true), AfterPanic::Halt);
    }

    #[test]
    fn a_timeout_restarts_after_that_many_seconds() {
        assert_eq!(after_panic(30, true), AfterPanic::RestartAfter(30));
    }

    #[test]
    fn a_negative_timeout_restarts_immediately() {
        assert_eq!(after_panic(-1, true), AfterPanic::RestartAfter(0));
    }

    #[test]
    fn without_a_restart_path_the_machine_halts_whatever_the_line_said() {
        assert_eq!(after_panic(30, false), AfterPanic::Halt, "a restart that cannot happen must not be announced");
        assert_eq!(after_panic(-1, false), AfterPanic::Halt);
    }

    #[test]
    fn the_knobs_round_trip() {
        set_panic_timeout(15);
        assert_eq!(panic_timeout(), 15);
        set_panic_timeout(PANIC_TIMEOUT_WAIT_FOREVER);
        set_panic_on_oops(true);
        assert!(panic_on_oops());
        set_panic_on_oops(false);
        assert!(!panic_on_oops());
    }

    #[test]
    fn the_render_sink_truncates_rather_than_growing() {
        use core::fmt::Write as _;
        let mut buf = [0u8; MESSAGE_BUF_LEN];
        let mut s = StaticSink { buf: &mut buf, len: 0 };
        for _ in 0..40 { let _ = core::write!(&mut s, "0123456789"); }
        assert_eq!(s.len, MESSAGE_BUF_LEN, "the panic path must never allocate to say what happened");
    }

    #[test]
    fn panic_on_warn_round_trips() {
        set_panic_on_warn(true);
        assert!(panic_on_warn());
        set_panic_on_warn(false);
        assert!(!panic_on_warn());
    }
}
