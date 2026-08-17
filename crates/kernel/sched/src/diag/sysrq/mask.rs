// The `kernel.sysrq` enable policy: which commands a machine will run, and the
// live setting itself.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::table::Cmd;

/// Bits of the enable mask (`kernel.sysrq`), as the reference numbers them.
/// A mask of exactly `1` enables everything; otherwise a command runs only
/// when its own bit is set.
pub const ENABLE_ALL: u32 = 1;
/// Loglevel changes.
pub const ENABLE_LOG: u32 = 0x0002;
/// Debugging dumps.
pub const ENABLE_DUMP: u32 = 0x0004;
/// Reboot and power off.
pub const ENABLE_BOOT: u32 = 0x0080;

/// Which mask bit `cmd` is gated by.
/// # C: O(1)
pub fn enable_bit(cmd: Cmd) -> u32 {
    match cmd {
        Cmd::Crash | Cmd::ShowTasks | Cmd::ShowBlocked
        | Cmd::ShowBacktraceAllCpus | Cmd::ShowRegisters => ENABLE_DUMP,
        Cmd::Reboot | Cmd::PowerOff => ENABLE_BOOT,
        Cmd::Help | Cmd::Unbound(_) => ENABLE_LOG,
    }
}

/// May `cmd` run under `mask`?
///
/// `1` is not a bit pattern — it is the spelling of "all of them", and a mask
/// read bit-wise would enable nothing but the loglevel keys on the setting
/// almost every machine uses.
/// # C: O(1)
pub fn mask_allows(mask: u32, cmd: Cmd) -> bool {
    mask == ENABLE_ALL || (mask & enable_bit(cmd)) != 0
}

/// The mask a key press is actually judged against.
///
/// `kernel.sysrq` is userspace policy, and a distribution's `sysctl.d` sets it
/// after any value the boot line asked for — so on the one machine that needs
/// the keys, the machine whose userspace has stopped answering, they are
/// refused. The boot parameter is the setting userspace cannot overwrite, and
/// the reference gives it exactly this meaning: enable everything, whatever
/// the sysctl later holds.
/// # C: O(1)
pub fn effective_mask(mask: u32, always: bool) -> u32 { if always { ENABLE_ALL } else { mask } }

/// The live `kernel.sysrq` setting.
/// # C: O(1)
pub fn mask_value() -> u32 { MASK.load(Ordering::Relaxed) }

static MASK: AtomicU32 = AtomicU32::new(ENABLE_ALL);

/// Publish a new `kernel.sysrq` value. # C: O(1)
pub fn set_mask(v: u32) { MASK.store(v, Ordering::Relaxed); }

static ALWAYS: AtomicBool = AtomicBool::new(false);

/// Did the boot line ask for `sysrq_always_enabled`? # C: O(1)
pub fn always_enabled() -> bool { ALWAYS.load(Ordering::Relaxed) }

/// Record the boot line's `sysrq_always_enabled` request. Announced when set,
/// because a machine whose keys answer regardless of `kernel.sysrq` is a
/// deliberate configuration an operator should see stated once.
/// # C: O(1)
pub fn set_always_enabled(on: bool) {
    ALWAYS.store(on, Ordering::Relaxed);
    if on { klog::announce("[sysrq] always enabled by the boot line"); }
}
