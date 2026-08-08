// `init=` / `rdinit=`: which executable PID 1 runs.

use crate::token::value;

/// `init=<path>` — the executable PID 1 should run. Matched only as a whole
/// token so it never matches `systemd.unit=` or a similar tail.
/// # C: O(cmdline length)
pub fn init_path() -> Option<&'static [u8]> { init_path_in(crate::get()) }

/// Global-free form of [`init_path`]. # C: O(line length)
pub fn init_path_in(line: &[u8]) -> Option<&[u8]> { value(line, b"init").filter(|v| !v.is_empty()) }

/// `rdinit=<path>` — the executable PID 1 runs from an initramfs, taking
/// precedence over `init=` while the initramfs is the root.
/// # C: O(line length)
pub fn rdinit_path_in(line: &[u8]) -> Option<&[u8]> { value(line, b"rdinit").filter(|v| !v.is_empty()) }
