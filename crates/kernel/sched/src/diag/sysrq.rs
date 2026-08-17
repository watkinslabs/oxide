// The magic-SysRq surface: ONE decoding of a key, consulted by both entries
// into it.
//
// There are two ways a command arrives — the serial line's break-then-key
// sequence, and a write to `/proc/sysrq-trigger` — and they must agree on what
// a key means. They did not: the serial path had its own `match` in which `c`
// dumped per-CPU heartbeats and `b` printed backtraces, so a key that halts a
// machine everywhere else printed a table here, and the key that CRASHES a
// machine everywhere else was bound to a harmless dump. An operator carries
// those letters in muscle memory; a second private table is how they get a
// machine that does not do what they asked.
//
// Module manifest — split by what each part OWNS, so the decision logic stays
// reachable from a hosted test and only the side effects need a kernel:
//
// | module    | owns |
// |---|---|
// | `table`   | the key table: `Cmd`, `decode`, `KEYS` |
// | `mask`    | the `kernel.sysrq` enable policy and its live setting |
// | `help`    | rendering and printing the key list |
// | `rx`      | the serial line's arm-then-key state machine and its deadline |
// | `perform` | the side effects, and the `/proc/sysrq-trigger` entry |

pub mod help;
pub mod mask;
pub mod perform;
pub mod rx;
pub mod table;

pub use help::{emit_help, render_help, HELP_MAX, HELP_PREFIX};
pub use mask::{always_enabled, effective_mask, enable_bit, mask_allows, mask_value, set_always_enabled,
               set_mask, ENABLE_ALL, ENABLE_BOOT, ENABLE_DUMP, ENABLE_LOG};
pub use perform::{perform, trigger};
pub use rx::{decide, rx, RxStep, ARM_WINDOW_NS, DISARMED, SYSRQ_ARM};
pub use table::{decode, Cmd, KEYS};

#[cfg(test)]
mod tests;
