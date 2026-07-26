// Task `comm` (Linux `task_struct.comm`) accessors: spinlock-guarded
// TASK_COMM_LEN byte buffer, mutable per-thread via `prctl(PR_SET_NAME)` /
// `pthread_setname_np`, readable by procfs and diagnostics from a foreign
// CPU (`docs/53` hollow-shell owner: sched). Sole comm storage in the
// crate — every reader (procfs `comm`/`stat`, coredump, sysrq task dump,
// sched_switch tracepoint) routes through here, never a second field.

extern crate alloc;
use alloc::string::String;

use super::{Task, TASK_COMM_LEN};

impl Task {
    /// NUL-pad `bytes` into a fixed `TASK_COMM_LEN` buffer, truncating at
    /// `TASK_COMM_LEN - 1` like Linux `strscpy_pad(tsk->comm, buf, ...)`.
    /// # C: O(TASK_COMM_LEN)
    fn pack(bytes: &[u8]) -> [u8; TASK_COMM_LEN] {
        let mut buf = [0u8; TASK_COMM_LEN];
        let n = bytes.len().min(TASK_COMM_LEN - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf
    }

    /// Trim a NUL-padded comm buffer to its printable prefix.
    /// # C: O(TASK_COMM_LEN)
    pub fn comm_trim(b: &[u8; TASK_COMM_LEN]) -> &str {
        let end = b.iter().position(|&c| c == 0).unwrap_or(TASK_COMM_LEN);
        core::str::from_utf8(&b[..end]).unwrap_or("")
    }

    /// Raw NUL-padded comm buffer snapshot — zero-alloc, for hot paths
    /// (context-switch tracepoint) that only need a momentary `&str` via
    /// `comm_trim`. # C: O(1)
    pub fn comm_bytes(&self) -> [u8; TASK_COMM_LEN] {
        *self.name.lock()
    }

    /// Non-blocking `comm_bytes`, for hard-IRQ callers (sysrq/watchdog dump).
    /// # C: O(1) # Ctx: any, including hard IRQ
    pub fn try_comm_bytes(&self) -> Option<[u8; TASK_COMM_LEN]> {
        Some(*self.name.try_lock()?)
    }

    /// `comm` as an owned string for a task dump / procfs `comm` — the
    /// real per-thread name (spawn literal, exec'd basename, or an
    /// explicit `prctl(PR_SET_NAME)` rename), UTF-8-lossy decoded.
    /// # C: O(TASK_COMM_LEN)
    pub fn comm(&self) -> String {
        String::from(Self::comm_trim(&self.comm_bytes()))
    }

    /// `comm` for HARD-IRQ callers (the sysrq dump): never spins on the
    /// `name` lock, falling back to a `<locked>` placeholder when held.
    /// # C: O(TASK_COMM_LEN) # Ctx: any, including hard IRQ
    pub fn comm_irq_safe(&self) -> String {
        match self.try_comm_bytes() {
            Some(b) => String::from(Self::comm_trim(&b)),
            None => String::from("<locked>"),
        }
    }

    /// Overwrite comm from a UTF-8 string — spawn seed, execve basename,
    /// fork/clone inherit. # C: O(TASK_COMM_LEN)
    pub fn set_comm(&self, s: &str) {
        *self.name.lock() = Self::pack(s.as_bytes());
    }

    /// Overwrite comm from raw bytes, no UTF-8 requirement — Linux `comm`
    /// is untyped bytes; `prctl(PR_SET_NAME)` copies the user buffer
    /// as-is. # C: O(TASK_COMM_LEN)
    pub fn set_comm_raw(&self, bytes: &[u8]) {
        *self.name.lock() = Self::pack(bytes);
    }

    /// Overwrite comm from an already-packed buffer (fork/clone inherit,
    /// copying a parent's `comm_bytes()` snapshot verbatim, no re-pack).
    /// # C: O(TASK_COMM_LEN)
    pub fn set_comm_bytes(&self, b: [u8; TASK_COMM_LEN]) {
        *self.name.lock() = b;
    }

    /// Pack a spawn-time `&str` literal into the initial comm buffer —
    /// `Task::new*` constructors only. # C: O(TASK_COMM_LEN)
    pub(super) fn pack_spawn_name(s: &str) -> [u8; TASK_COMM_LEN] {
        Self::pack(s.as_bytes())
    }
}
