// Task `comm` (Linux `task_struct.comm`) accessors: spinlock-guarded
// TASK_COMM_LEN byte buffer, mutable per-thread via `prctl(PR_SET_NAME)` /
// `pthread_setname_np`, readable by procfs and diagnostics from a foreign
// CPU (`docs/53` hollow-shell owner: sched). Sole comm storage in the
// crate — every reader (procfs `comm`/`stat`, coredump, sysrq task dump,
// sched_switch tracepoint) routes through here, never a second field.

extern crate alloc;
use alloc::string::String;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::{Task, TASK_COMM_LEN};

// ---- comm-change notification -------------------------------------------
//
// Linux emits `PERF_RECORD_COMM` from `__set_task_comm()` — the single
// function that writes `task_struct.comm` — never from its callers. That is
// what makes `prctl(PR_SET_NAME)`, a `/proc/<pid>/comm` write and an `execve`
// rename all report, without any of them knowing perf exists.
//
// The emitter lives in `fs`, a crate above this one, so it arrives as a
// function pointer. Keeping the hook in the module that OWNS the comm buffer
// is what stops a second notion of "the task was renamed" from growing beside
// the storage: there is one setter, and it reports.

/// `perf_event_comm(task, exec)` — `(tid, cpu, name, exec)`.
pub type CommFn = fn(u32, i32, &[u8], bool);

static COMM_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `PERF_RECORD_COMM` emitter. # C: O(1)
pub fn set_comm_hook(f: CommFn) { COMM_HOOK.store(f as *mut (), Ordering::Release); }

/// Report a completed rename. Called with the `name` lock already RELEASED —
/// the emitter takes the perf registry and a ring lock, which rank below it.
/// # C: O(events)
fn notify(t: &Task, buf: &[u8; TASK_COMM_LEN], exec: bool) {
    let p = COMM_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: installed via `set_comm_hook` with the `CommFn` signature; the
    // Acquire load pairs with that setter's Release store and the pointer is a
    // `'static` fn address.
    let f: CommFn = unsafe { core::mem::transmute::<*mut (), CommFn>(p) };
    let end = buf.iter().position(|&c| c == 0).unwrap_or(TASK_COMM_LEN);
    f(t.tid, t.cpu.load(Ordering::Relaxed) as i32, &buf[..end], exec);
}

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

    /// `__set_task_comm(tsk, buf, exec)` — the ONE writer. Stores the packed
    /// buffer, releases the lock, then reports the rename.
    ///
    /// `exec` marks the change as an `execve` rather than a `prctl` rename,
    /// which is what `PERF_RECORD_MISC_COMM_EXEC` tells a consumer apart.
    /// # C: O(TASK_COMM_LEN + events)
    fn write_comm(&self, buf: [u8; TASK_COMM_LEN], exec: bool) {
        // The guard is a temporary and drops at the end of this statement: the
        // notify below must not run under the `name` lock.
        *self.name.lock() = buf;
        notify(self, &buf, exec);
    }

    /// Overwrite comm from a UTF-8 string — spawn seed and diagnostics.
    /// # C: O(TASK_COMM_LEN)
    pub fn set_comm(&self, s: &str) {
        self.write_comm(Self::pack(s.as_bytes()), false);
    }

    /// `execve`'s rename to the new image's basename. Distinguished from every
    /// other rename by `PERF_RECORD_MISC_COMM_EXEC`.
    /// # C: O(TASK_COMM_LEN)
    pub fn set_comm_exec(&self, s: &str) {
        self.write_comm(Self::pack(s.as_bytes()), true);
    }

    /// Overwrite comm from raw bytes, no UTF-8 requirement — Linux `comm`
    /// is untyped bytes; `prctl(PR_SET_NAME)` copies the user buffer
    /// as-is. # C: O(TASK_COMM_LEN)
    pub fn set_comm_raw(&self, bytes: &[u8]) {
        self.write_comm(Self::pack(bytes), false);
    }

    /// Overwrite comm from an already-packed buffer — a `/proc/<pid>/comm`
    /// write, which is `prctl(PR_SET_NAME)` through the filesystem and reports
    /// the same way. # C: O(TASK_COMM_LEN)
    pub fn set_comm_bytes(&self, b: [u8; TASK_COMM_LEN]) {
        self.write_comm(b, false);
    }

    /// fork/clone inherit: copy a parent's `comm_bytes()` snapshot verbatim.
    ///
    /// Reports NOTHING. The reference copies `comm` as part of
    /// `dup_task_struct`'s structure copy rather than through
    /// `__set_task_comm`, so a fork produces a `PERF_RECORD_FORK` and never a
    /// `PERF_RECORD_COMM` — the child did not rename, it was born named.
    /// # C: O(TASK_COMM_LEN)
    pub fn set_comm_inherited(&self, b: [u8; TASK_COMM_LEN]) {
        *self.name.lock() = b;
    }

    /// Pack a spawn-time `&str` literal into the initial comm buffer —
    /// `Task::new*` constructors only. # C: O(TASK_COMM_LEN)
    pub(super) fn pack_spawn_name(s: &str) -> [u8; TASK_COMM_LEN] {
        Self::pack(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::types::SchedClass;
    use core::sync::atomic::AtomicU32;

    /// `COMM_HOOK` is one global, so the tests that install one run in turn.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static CALLS: AtomicU32 = AtomicU32::new(0);
    static EXECS: AtomicU32 = AtomicU32::new(0);
    /// A hook body cannot capture, so the observed name is parked here.
    static SEEN: [core::sync::atomic::AtomicU8; TASK_COMM_LEN] =
        [const { core::sync::atomic::AtomicU8::new(0) }; TASK_COMM_LEN];
    static SEEN_LEN: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);

    fn seen_set(b: &[u8]) {
        let n = b.len().min(TASK_COMM_LEN);
        for i in 0..n { SEEN[i].store(b[i], Ordering::Relaxed); }
        SEEN_LEN.store(n, Ordering::Release);
    }

    fn seen() -> alloc::vec::Vec<u8> {
        let n = SEEN_LEN.load(Ordering::Acquire);
        (0..n).map(|i| SEEN[i].load(Ordering::Relaxed)).collect()
    }

    fn hook(_tid: u32, _cpu: i32, name: &[u8], exec: bool) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        if exec { EXECS.fetch_add(1, Ordering::Relaxed); }
        seen_set(name);
    }

    fn armed() -> std::sync::MutexGuard<'static, ()> {
        let g = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_comm_hook(hook);
        CALLS.store(0, Ordering::Relaxed);
        EXECS.store(0, Ordering::Relaxed);
        seen_set(b"");
        g
    }

    fn task() -> Task { Task::new(4711, "orig", SchedClass::Normal { weight: 1024 }) }

    /// `prctl(PR_SET_NAME)` goes through `set_comm_raw`, and the setter is what
    /// reports — so the rename reaches the emitter with the new name and
    /// WITHOUT the exec marker.
    ///
    /// Before this, only `execve` reported: a `prctl` or `pthread_setname_np`
    /// rename changed `comm` and no `PERF_RECORD_COMM` was ever emitted, so a
    /// consumer kept resolving the thread under its old name for the rest of
    /// the recording.
    #[test]
    fn a_prctl_rename_reaches_the_emitter_without_the_exec_marker() {
        let _g = armed();
        let t = task();
        t.set_comm_raw(b"worker");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "the setter reported the rename");
        assert_eq!(EXECS.load(Ordering::Relaxed), 0, "a prctl rename is not an exec");
        assert_eq!(seen(), b"worker".to_vec());
        assert_eq!(t.comm(), "worker", "and the stored comm is the same one reported");
    }

    /// A `/proc/<pid>/comm` write is `prctl(PR_SET_NAME)` through the
    /// filesystem and reports identically.
    #[test]
    fn a_proc_comm_write_reports_the_same_way() {
        let _g = armed();
        let t = task();
        t.set_comm_bytes(Task::pack(b"viafs"));
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(EXECS.load(Ordering::Relaxed), 0);
        assert_eq!(seen(), b"viafs".to_vec());
    }

    /// `execve`'s rename carries the exec marker, which is the only thing that
    /// distinguishes it from the two above.
    #[test]
    fn an_execve_rename_is_marked_as_an_exec() {
        let _g = armed();
        let t = task();
        t.set_comm_exec("bash");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(EXECS.load(Ordering::Relaxed), 1, "PERF_RECORD_MISC_COMM_EXEC");
        assert_eq!(seen(), b"bash".to_vec());
    }

    /// A fork does NOT report a rename: the reference copies `comm` as part of
    /// the structure copy, and the child's birth is a `PERF_RECORD_FORK`. A
    /// `PERF_RECORD_COMM` here would tell a consumer the parent renamed itself.
    #[test]
    fn a_fork_inherit_reports_nothing() {
        let _g = armed();
        let parent = task();
        let child = Task::new(4712, "x", SchedClass::Normal { weight: 1024 });
        child.set_comm_inherited(parent.comm_bytes());
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "a fork is not a rename");
        assert_eq!(child.comm(), "orig", "but the name is still inherited");
    }

    /// The reported name is the TRUNCATED, stored one — a consumer must never
    /// be told a name the task does not have.
    #[test]
    fn an_over_long_name_reports_what_was_actually_stored() {
        let _g = armed();
        let t = task();
        t.set_comm_raw(b"0123456789abcdefOVERFLOW");
        assert_eq!(seen(), t.comm().as_bytes().to_vec());
        assert_eq!(seen().len(), TASK_COMM_LEN - 1);
    }
}
