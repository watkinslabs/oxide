#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
// Boot-parameter application: the boot console the command line asks for, and
// the printk policy it installs.
//
// The boot console is the console that exists BEFORE device init, driven
// straight from the UART the boot command line names.
//
// This is the answer to a boot that produces no output at all. The real
// console registers late — after the driver model, the platform bus and the
// device probe — so everything before that point reaches no wire. A boot that
// hangs earlier than that is, today, completely silent. A boot console writes
// to the port directly with no allocation, no driver model and no lock that
// depends on later init, so the window becomes visible.
//
// Module manifest:
// - `access`: how a register is reached (port I/O or one of the MMIO strides).
// - `uart8250`: 8250/16550 register model — init and transmit.
// - `pl011`: PL011 transmit.
// - `install`: the live boot-console state and the klog sink it registers.
// - `policy`: applying the line's printk parameters to klog.

#[cfg(test)]
extern crate std;

pub mod access;
pub mod uart8250;
pub mod pl011;
pub mod install;
pub mod policy;

pub use install::{emit, install, installed, spec};
pub use policy::{apply, Applied};

/// Resolve the line's boot-console request and bring it up, then apply the
/// line's printk policy. The single entry point an arch boot path calls as
/// soon as it has a command line and a usable direct map.
///
/// # SAFETY: caller is the boot path with a single CPU, and `defaults` must
/// name this platform's real boot UART.
/// # C: O(line length)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init(line: &[u8], defaults: cmdline::ArchDefaults, direct_map_offset: u64) -> bool {
    // Console first, policy second: the policy step reports each parameter it
    // cannot honour, and those reports are worth nothing if they are emitted
    // before there is anything to emit them on.
    let brought_up = match cmdline::earlycon_request(line, defaults) {
        // SAFETY: forwarded boot-path contract; `spec` names a UART of the
        // stated kind at the address the boot line supplied, and no other code
        // drives it before device init.
        Some(spec) => unsafe { install(spec, direct_map_offset) },
        None => false,
    };
    let _ = policy::apply(line);
    brought_up
}

/// Bound on any transmit poll loop. A boot console that spins forever on a
/// back-pressured emulated UART replaces a diagnosable hang with an
/// undiagnosable one, so a byte is dropped instead.
pub const SPIN_CAP: u32 = 5_000_000;
