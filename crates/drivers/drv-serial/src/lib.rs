#![no_std]
//! Serial console **core** — arch-independent RX sink/prefilter + a thin
//! delegation layer over the per-arch UART driver crate.
//!
//! drivers-plan D4: the two UART backends now live in their own `drv-*`
//! crates (`drv-uart-16550` on x86, `drv-uart-pl011` on arm; docs/35§3).
//! This crate keeps the tty RX sink + sysrq prefilter + `deliver` (which
//! has no place in a per-device driver), and re-exposes the unchanged
//! public API (`emit`/`init`/`poll`/`rx_isr`/`present`) by delegating to
//! the cfg-appropriate UART crate. `init` passes this crate's own
//! `deliver` fn down as the RX callback — that parameter is the
//! cycle-break that lets the UART crates avoid depending on `drv-serial`.
//!
//! The firmware-elected console (ACPI SPCR) wins; a machine with no
//! serial port simply has no serial console. docs/53 (kernel = glue).

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use drv_uart_16550 as uart;
#[cfg(target_arch = "aarch64")]
use drv_uart_pl011 as uart;
// Host/other arches: fall back to the 16550 shell so the crate builds.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use drv_uart_16550 as uart;

/// RX byte sink — the tty line discipline (`push_and_wake_fg`). Wired by
/// the kernel; keeps this crate free of any tty dependency.
static RX_SINK: AtomicU64 = AtomicU64::new(0);
/// Optional RX pre-filter (sysrq). Returns true if it consumed the byte
/// (don't forward to the tty sink). Lets the kernel snoop a magic
/// sequence on the console for an on-demand diagnostic dump (`27`
/// `kernel.sysrq`) without the tty/sched layers reaching into drv-serial.
static RX_PREFILTER: AtomicU64 = AtomicU64::new(0);

/// Install the RX byte sink. Call once at boot before `init`.
/// # C: O(1)
pub fn set_rx_sink(f: fn(u8)) { RX_SINK.store(f as usize as u64, Ordering::Release); }

/// Install the RX pre-filter (sysrq snoop). Checked before the sink on
/// every received byte; a `true` return drops the byte from the tty.
/// # C: O(1)
pub fn set_rx_prefilter(f: fn(u8) -> bool) { RX_PREFILTER.store(f as usize as u64, Ordering::Release); }

/// RX delivery: run the sysrq prefilter, then forward to the tty sink.
/// Passed to the UART crate as its RX callback (the cycle-break).
#[inline]
fn deliver(b: u8) {
    let pf = RX_PREFILTER.load(Ordering::Acquire);
    if pf != 0 {
        // SAFETY: pf was stored from a `fn(u8) -> bool` by set_rx_prefilter; transmute back to that type.
        let f: fn(u8) -> bool = unsafe { core::mem::transmute(pf as usize) };
        if f(b) { return; }
    }
    let p = RX_SINK.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: p was stored from a `fn(u8)` by set_rx_sink; transmute back to that type.
    let f: fn(u8) = unsafe { core::mem::transmute(p as usize) };
    f(b);
}

/// True once a UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { uart::present() }

/// Console TX — delegates to the active UART crate.
/// # C: O(len(bytes))
pub fn emit(bytes: &[u8]) { uart::emit(bytes); }

/// Timer-tick fallback RX poll — delegates to the active UART crate,
/// passing this crate's `deliver` as the byte callback.
/// # SAFETY: forwards to the UART crate's poll; same single-CPU / port-
/// I/O / published-MMIO-VA invariants documented on that crate's rx_poll.
/// # C: O(N_bytes_drained)
pub unsafe fn poll() {
    // SAFETY: UART crate rx_poll owns the port-I/O / PL011-VA + single-CPU invariants; deliver is a valid fn(u8).
    unsafe { uart::rx_poll(deliver); }
}

/// RX interrupt drain — delegates to the active UART crate, passing this
/// crate's `deliver` as the byte callback.
/// # C: O(bytes pending)
pub fn rx_isr() { uart::rx_isr(deliver); }

/// The active UART's driver-model handle (per-arch: "8250-serial" on x86,
/// "pl011-serial" on arm). The kernel registers this in the drv model +
/// binds it to platform/serial0 (drivers-plan D1a).
/// # C: O(1)
pub fn uart_driver() -> &'static dyn drv::Driver { uart::UART_DRIVER }

/// Detect + register the serial console (TX sink + RX IRQ on x86). No-op
/// when no UART responds. `dev_window_base` is the kernel device-MMIO
/// window. Returns true if a UART was found. Delegates to the active UART
/// crate, handing it this crate's `deliver` as the RX callback.
/// # SAFETY: post-ACPI + post-LAPIC-enable + MmuOps live; single-CPU,
/// IRQs masked. Forwards to the UART crate init, which maps the I/O APIC
/// + programs IRQ4 (x86) / reads the published PL011 VA (arm).
/// # C: O(1)
pub unsafe fn init(bsp_apic: u8, dev_window_base: u64) -> bool {
    // SAFETY: forwards to the UART crate init under the documented boot preconditions; deliver is a valid fn(u8).
    unsafe { uart::init(bsp_apic, dev_window_base, deliver) }
}
