// No rights register on this target: hosted builds, and aarch64 until its
// permission-overlay enablement lands. Every operation is inert and reads
// answer 0 — nothing is denied — rather than fabricating a register state.

/// # C: O(1)
pub fn supported() -> bool { false }
/// # C: O(1)
pub fn init_value() -> u32 { 0 }
/// # C: O(1)
pub fn read_live() -> u32 { 0 }
/// # C: O(1)
pub fn write_live(v: u32) { let _ = v; }
