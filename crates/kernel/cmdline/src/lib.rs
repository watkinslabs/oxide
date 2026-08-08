#![no_std]
// Boot command line: the one transport for the bootloader's line and the one
// owner of every kernel-parameter decision taken from it. Consumers ask this
// crate what a parameter means; nobody re-scans the line for themselves,
// because two scanners disagree the first time a value contains a `=` or a
// name is a prefix of another name.
//
// Every decision module is ungated and global-free (it takes the line as an
// argument), so the whole parameter grammar is hosted-testable without a
// kernel target. Only `slot` touches a global, and only from boot.
//
// Module manifest:
// - `slot`: the boot-installed command-line bytes; `/proc/cmdline`'s source.
// - `token`: tokenisation and scalar parsing shared by every decision module.
// - `console`: `console=` grammar — classes, preferred device, line settings.
// - `earlycon`: `earlycon=` / `earlyprintk=` boot-console requests.
// - `printk`: loglevel, verbosity, timestamping and `/dev/kmsg` policy.
// - `faults`: what a fatal kernel event does (`panic=`, `oops=`).
// - `init_path`: `init=` / `rdinit=`.
// - `tests`: parser contract tests.

pub mod token;
pub mod slot;
pub mod console;
pub mod earlycon;
pub mod printk;
pub mod faults;
pub mod init_path;

pub use slot::{get, install_arch_default, is_set, set};
pub use console::{console_classes, console_classes_in, preferred_console, preferred_console_in, ConsoleKind};
pub use earlycon::{earlycon_request, keep_bootcon, ArchDefaults, Driver, EarlyconSpec, IoType};
pub use init_path::{init_path, init_path_in};

/// Value of the last exact `name=value` boot parameter.
/// # C: O(cmdline length)
pub fn parameter_value(name: &[u8]) -> Option<&'static [u8]> { token::value(get(), name) }

/// Global-free form of [`parameter_value`]. # C: O(line length)
pub fn parameter_value_in<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> { token::value(line, name) }

#[cfg(test)]
mod tests;
