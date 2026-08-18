//! The registry of mapping types a table line may name.
//!
//! One registry, and it is this one. A target that could be reached by any
//! other path would be a mapping the version report does not list and the
//! table loader cannot refuse.

extern crate alloc;
use alloc::vec::Vec;

use sync::{StackedBlock as DmClass, Spinlock};

use crate::target::TargetType;

static TYPES: Spinlock<Vec<TargetType>, DmClass> = Spinlock::new(Vec::new());

/// Register a mapping type. Re-registering a name replaces it, which is what
/// makes a test that installs its own target deterministic regardless of what
/// ran before it. # C: O(N_types)
pub fn register(tt: TargetType) {
    let mut v = TYPES.lock();
    match v.iter().position(|t| t.name == tt.name) {
        Some(i) => v[i] = tt,
        None => v.push(tt),
    }
}

/// Remove a registered mapping type. # C: O(N_types)
pub fn unregister(name: &str) {
    TYPES.lock().retain(|t| t.name != name);
}

/// Look one up by the name a table line used. # C: O(N_types)
pub fn get(name: &str) -> Option<TargetType> {
    TYPES.lock().iter().find(|t| t.name == name).copied()
}

/// Every registered type, in registration order — the order the version
/// report walks. # C: O(N_types)
pub fn list() -> Vec<TargetType> { TYPES.lock().clone() }

/// Install the mapping types this crate implements. Idempotent, so a second
/// call from a test harness is harmless. # C: O(N_types)
pub fn register_builtin() {
    register(crate::targets::linear::TYPE);
    register(crate::targets::stripe::TYPE);
    register(crate::targets::zero::TYPE);
    register(crate::targets::error::TYPE);
    register(crate::targets::delay::TYPE);
    register(crate::targets::crypt::TYPE);
}
