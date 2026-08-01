// No rights register on this target (hosted builds). Every operation is inert
// and reads answer 0 — nothing is denied — rather than fabricating a register
// state the target does not have.

/// # C: O(1)
pub fn supported() -> bool { false }
/// # C: O(1)
pub fn init_value() -> u64 { 0 }
/// # C: O(1)
pub fn read_live() -> u64 { 0 }
/// # C: O(1)
pub fn write_live(v: u64) { let _ = v; }
