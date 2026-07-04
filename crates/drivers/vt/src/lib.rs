// Linux Virtual Terminal layer per docs/50. /dev/tty0..tty63 +
// /dev/console + /dev/tty (controlling). Multiplexes 63 consoles
// over the fbcon glyph backend (49). Owns KDSETMODE/KDSKBMODE,
// VT_OPENQRY/VT_GETSTATE/VT_ACTIVATE/VT_RELDISP per
// linux/include/uapi/linux/vt.h + kd.h.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod tiocl;

use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

mod uapi;
pub use uapi::*;

mod state;
pub use state::{Error, KResult, VtSlotSnap};
use state::{
    fire_signal, fire_switch, owner_alive, VtSlot, ACTIVE_VT, PENDING_SWITCH, SLOTS,
};
pub use state::{set_owner_alive_hook, set_signal_hook, set_switch_hook};
#[cfg(test)]
use state::{ON_SWITCH, OWNER_ALIVE};

mod runtime;
pub use runtime::{
    activate, active, blank, disallocate, get_state, init, lock_switch, openqry, reldisp,
    resize, scrolldelta, set_kb_mode, set_kd_mode, set_leds, set_vt_mode, slot, unblank,
};

#[cfg(test)]
mod tests;
