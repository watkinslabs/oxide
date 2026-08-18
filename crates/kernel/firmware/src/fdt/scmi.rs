//! SCMI FDT binding and direct CPU-performance provider.
//!
//! Module manifest: `platform` — aarch64 SMC shared-memory transport and
//! cpufreq policy publication.

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod platform;

/// Kernel-owned GIC installation for one SCMI completion interrupt.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub type CompletionIrqInstaller = fn(u32, bool) -> bool;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
static COMPLETION_IRQ_INSTALLER: AtomicUsize = AtomicUsize::new(0);

/// Install the GIC line-registration bridge before SCMI devices probe.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn set_completion_irq_installer(installer: CompletionIrqInstaller) {
    COMPLETION_IRQ_INSTALLER.store(installer as usize, Ordering::Release);
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn install_completion_irq(irq: ::fdt::ScmiCompletionIrq) -> bool {
    let raw = COMPLETION_IRQ_INSTALLER.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: this atomic is written only by set_completion_irq_installer with
    // CompletionIrqInstaller's ABI before any SCMI transport is published.
    let installer: CompletionIrqInstaller = unsafe { core::mem::transmute(raw) };
    installer(irq.intid, irq.level)
}

/// Route an owned SCMI completion line from the architecture IRQ dispatcher.
/// # C: O(number of SCMI controllers)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn handle_completion_irq(intid: u32) -> bool { platform::handle_completion_irq(intid) }

/// Publish usable SCMI Performance CPU-frequency policies. # C: O(FDT × SCMI)
pub fn init() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { return platform::init(); }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Admit SCMI completion-channel probing after workers and timer waits exist.
/// # C: O(1)
pub fn start_deferred() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { platform::start_deferred(); }
}
