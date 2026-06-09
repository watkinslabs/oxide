// TTY driver registry — Linux `tty_register_driver` / `tty_std_termios`
// keyed lookup (`drivers/tty/tty_io.c`, `tty_drivers` list). Device nodes
// (`/dev/ttyN`, `/dev/ttyS0`, `/dev/pts/*` in T5/T6/T8) resolve their
// backing tty by (major, minor).
//
// No `dyn` (07§5): the registry is generic over one concrete tty type
// `T` (the boot wires one VT-console tty type and one serial tty type;
// each gets its own registry instance). This keeps every `TtyStruct<D,W>`
// monomorphized while still giving the device-node layer a (major,minor)
// → tty lookup. Heterogeneous classes use separate registries rather than
// a `dyn` table.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Tty as TtyClass};

/// Linux char-device majors for the tty classes (`Documentation/admin-
/// guide/devices.txt`). Typed so device-node registration never hard-codes
/// the bare number.
pub mod major {
    /// `/dev/tty` (controlling tty) — major 5, minor 0.
    pub const TTY: u32 = 5;
    /// `/dev/console` — major 5, minor 1.
    pub const CONSOLE: u32 = 5;
    /// VT consoles `/dev/ttyN` — major 4, minor N.
    pub const VC: u32 = 4;
    /// Serial ttys `/dev/ttyS*` — major 4, minor 64+.
    pub const SERIAL: u32 = 4;
    /// PTY slaves `/dev/pts/*` — major 136..143.
    pub const PTS: u32 = 136;
}

/// A (major, minor) device id.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DevId {
    pub major: u32,
    pub minor: u32,
}

impl DevId {
    /// # C: O(1)
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// (major, minor) → `Arc<T>` table. `T` is the concrete tty type for one
/// device class. Small linear table (a handful of VTs + one serial line);
/// no allocation churn after boot.
pub struct TtyRegistry<T> {
    table: Spinlock<Vec<(DevId, Arc<T>)>, TtyClass>,
}

impl<T> Default for TtyRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TtyRegistry<T> {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { table: Spinlock::new(Vec::new()) }
    }

    /// Register `tty` under `id`. Replaces any prior entry for `id`
    /// (re-registration on a re-open is allowed).
    /// # C: O(N) entries
    pub fn register(&self, id: DevId, tty: Arc<T>) {
        let mut g = self.table.lock();
        if let Some(slot) = g.iter_mut().find(|(d, _)| *d == id) {
            slot.1 = tty;
        } else {
            g.push((id, tty));
        }
    }

    /// Look up the tty registered under `id`.
    /// # C: O(N) entries
    pub fn lookup(&self, id: DevId) -> Option<Arc<T>> {
        self.table
            .lock()
            .iter()
            .find(|(d, _)| *d == id)
            .map(|(_, t)| Arc::clone(t))
    }

    /// Remove the entry for `id` (driver unregister / hangup teardown).
    /// # C: O(N) entries
    pub fn unregister(&self, id: DevId) {
        self.table.lock().retain(|(d, _)| *d != id);
    }

    /// Number of registered ttys.
    /// # C: O(1)
    pub fn len(&self) -> usize {
        self.table.lock().len()
    }

    /// True when no tty is registered.
    /// # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.table.lock().is_empty()
    }
}
