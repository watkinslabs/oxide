// The helper request record (Linux `struct subprocess_info`) and the
// init/cleanup callback contract.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::uapi::UMH_NO_WAIT;

/// State the `init` callback may mutate before the helper image is loaded.
///
/// Linux runs `init` inside the freshly forked helper thread, just before
/// `kernel_execve`, so the callback sees a process that has a clean descriptor
/// table and a fresh credential set but no program image yet. `HelperCtx` is
/// that same window: installing a descriptor here (the coredump pipe's stdin)
/// or narrowing the credential set is what the callback is for.
pub struct HelperCtx {
    /// The helper process. Its credentials are the fresh kernel set; the
    /// callback may narrow them.
    pub task: Arc<sched::Task>,
    /// The helper's descriptor table — empty on entry, which is why a callback
    /// may rely on descriptor 0 being the next one it installs.
    pub fdt: Arc<vfs::FdTable>,
}

/// Customise the helper before its image is loaded. A non-zero return aborts
/// the helper: no image is loaded and the return value becomes the caller's
/// result under a waiting mode.
pub type InitFn = fn(&mut SubprocessInfo, &HelperCtx) -> i32;

/// Run just before the request record is released, on the same request the
/// caller handed in. Owns whatever `data` refers to.
pub type CleanupFn = fn(&mut SubprocessInfo);

/// One kernel -> userspace exec request.
pub struct SubprocessInfo {
    /// `None` models Linux's NULL `path`, which `call_usermodehelper_exec`
    /// rejects with `EINVAL`. An EMPTY path is a distinct, legal state: it is
    /// the "helpers statically disabled" configuration, and it succeeds as a
    /// no-op rather than erroring.
    pub path: Option<Vec<u8>>,
    /// argv as the helper will see it. `argv[0]` is conventionally the path but
    /// is not forced to be — the coredump pipe pattern chooses it.
    pub argv: Vec<Vec<u8>>,
    /// envp as the helper will see it. Empty means the helper starts with no
    /// environment at all, which is what a NULL `envp` produces.
    pub envp: Vec<Vec<u8>>,
    /// Wait mode this request was submitted with; set by
    /// `call_usermodehelper_exec`.
    pub wait: i32,
    /// Result the wait modes report. Its meaning is wait-mode dependent — see
    /// [`crate::uapi::UMH_WAIT_EXEC`] / [`crate::uapi::UMH_WAIT_PROC`].
    pub retval: i32,
    /// Opaque caller context handed to `init` and `cleanup`.
    pub data: usize,
    init: Option<InitFn>,
    cleanup: Option<CleanupFn>,
}

impl SubprocessInfo {
    /// Build a request. `path` is `None` only to model the NULL-path rejection.
    /// # C: O(argv + envp)
    pub fn new(
        path: Option<&[u8]>,
        argv: &[&[u8]],
        envp: &[&[u8]],
        init: Option<InitFn>,
        cleanup: Option<CleanupFn>,
        data: usize,
    ) -> Box<Self> {
        Box::new(Self {
            path: path.map(|p| p.to_vec()),
            argv: argv.iter().map(|a| a.to_vec()).collect(),
            envp: envp.iter().map(|e| e.to_vec()).collect(),
            wait: UMH_NO_WAIT,
            retval: 0,
            data,
            init,
            cleanup,
        })
    }

    /// True when the request names no program at all. # C: O(1)
    pub fn path_is_null(&self) -> bool { self.path.is_none() }

    /// True when the request names the empty program — helpers statically
    /// disabled, which succeeds as a no-op. # C: O(1)
    pub fn path_is_empty(&self) -> bool {
        matches!(self.path.as_deref(), Some(p) if p.is_empty())
    }

    /// The program path, or an empty slice when none was given. # C: O(1)
    pub fn path_bytes(&self) -> &[u8] { self.path.as_deref().unwrap_or(&[]) }

    /// True when an `init` callback is installed. # C: O(1)
    pub fn has_init(&self) -> bool { self.init.is_some() }

    /// Run the `init` callback against the nascent helper. Returns 0 when there
    /// is no callback — Linux's "nothing to customise" case. # C: O(callback)
    pub fn run_init(&mut self, ctx: &HelperCtx) -> i32 {
        match self.init {
            Some(f) => f(self, ctx),
            None => 0,
        }
    }

    /// Release the request, running `cleanup` first (Linux
    /// `call_usermodehelper_freeinfo`). Consumes the record so the cleanup can
    /// never run twice. # C: O(callback)
    pub fn free(mut self: Box<Self>) {
        if let Some(f) = self.cleanup { f(&mut self); }
    }
}
