// Off-target shell: aarch64 (no i8042) and host x86 test builds (no kernel
// crates). Only the detection predicate is reachable off the x86 kernel target.

/// Always false off the x86 kernel target. # C: O(1)
pub fn present() -> bool { false }
