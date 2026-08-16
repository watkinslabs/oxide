// Boot-time configuration of the security server.

use selinux::status::{parse_boot_config, BootConfig};

/// Read the boot parameters that configure the module. # C: O(cmdline)
pub fn boot_config() -> BootConfig {
    parse_boot_config(
        |name| cmdline::parameter_value(name),
        |name| cmdline::parameter_value(name).is_none() && cmdline_has_bare(name),
    )
}

/// Whether the command line carries a bare flag with no value. # C: O(cmdline)
fn cmdline_has_bare(name: &[u8]) -> bool {
    cmdline::slot::get().split(|b| *b == b' ').any(|t| t == name)
}

/// Install the security server for this boot. # C: O(cmdline)
///
/// The module is installed even when the command line disables it: a disabled
/// server still answers "allow" and still reports its state to userspace,
/// which is what a distribution's early scripts read to decide what to do. Not
/// installing it at all would leave those reads failing rather than answering
/// truthfully.
pub fn init() {
    let config = boot_config();
    if !crate::install(config) { return; }
    if config.enabled {
        klog::kinfo!("selinux: enabled, awaiting policy");
    } else {
        klog::kinfo!("selinux: disabled by the kernel command line");
    }
}
