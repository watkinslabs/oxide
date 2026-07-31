// `call_usermodehelper` and friends — every decision a caller can observe.

use alloc::boxed::Box;

use syscall::errno::Errno;

use crate::backend::{self, HelperRun};
use crate::gate;
use crate::info::{CleanupFn, InitFn, SubprocessInfo};
use crate::uapi::UMH_NO_WAIT;

/// Build a request without submitting it. Split from the submission so a caller
/// can attach an `init` callback that installs descriptors or narrows
/// credentials, and a `cleanup` callback that owns `data`.
/// # C: O(argv + envp)
pub fn call_usermodehelper_setup(
    path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    init: Option<InitFn>,
    cleanup: Option<CleanupFn>,
    data: usize,
) -> Box<SubprocessInfo> {
    SubprocessInfo::new(Some(path), argv, envp, init, cleanup, data)
}

/// Submit a request.
///
/// Return value by wait mode:
///   * `UMH_NO_WAIT`  — 0 once the request is queued. The helper's own outcome
///     is unobservable; that is what the mode buys.
///   * `UMH_WAIT_EXEC` — 0 if the image was loaded, else the negated errno the
///     exec produced. A missing helper binary is `-ENOENT`, which is the common
///     case and must reach the caller unaltered.
///   * `UMH_WAIT_PROC` — the `wait(2)`-encoded status of the finished helper, or
///     a negated errno if no helper process could be created at all. A helper
///     that could not be exec'd still terminates normally, so this mode reports
///     a zero status for a missing binary; callers that need to know whether the
///     work happened check their own side effect, not this number.
///
/// Refusals that precede any of that:
///   * a request naming no program at all is `-EINVAL`
///   * a request submitted while the gate is closed is `-EBUSY`
///   * a request naming the empty program succeeds as a no-op, which is how
///     helpers are statically disabled
///
/// The request is released here (running its `cleanup`) except under
/// `UMH_NO_WAIT`, where the backend owns it.
/// # C: O(backend)
pub fn call_usermodehelper_exec(mut info: Box<SubprocessInfo>, wait: i32) -> i32 {
    if info.path_is_null() {
        info.free();
        return -(Errno::Einval.as_i32());
    }
    gate::helper_lock();
    let retval = submit(&mut info, wait);
    let detached = matches!(retval, Submitted::Detached);
    let rc = match retval {
        Submitted::Detached => 0,
        Submitted::Result(rc) => rc,
    };
    if !detached { info.free(); }
    gate::helper_unlock();
    rc
}

enum Submitted { Detached, Result(i32) }

/// The gate/empty-path/backend ladder, between `helper_lock` and
/// `helper_unlock`. # C: O(backend)
fn submit(info: &mut Box<SubprocessInfo>, wait: i32) -> Submitted {
    if gate::usermodehelper_disabled() {
        return Submitted::Result(-(Errno::Ebusy.as_i32()));
    }
    // The empty program is the "helpers statically disabled" configuration: the
    // request succeeds and nothing runs. Callers that need a side effect (the
    // coredump pipe needs its write end) detect the no-op by that side effect
    // being absent, not by the return value.
    if info.path_is_empty() { return Submitted::Result(0); }
    let run = match backend::get() {
        Some(f) => f,
        // No helper machinery yet: the gate is the honest answer, since this is
        // exactly "helpers cannot be started right now".
        None => return Submitted::Result(-(Errno::Ebusy.as_i32())),
    };
    info.wait = wait;
    info.retval = 0;
    // Hand the request to the backend and take it back, so the caller's
    // ownership of the record is unbroken for every mode but NO_WAIT.
    let taken = core::mem::replace(info, SubprocessInfo::new(None, &[], &[], None, None, 0));
    match run(taken) {
        HelperRun::Detached => {
            if wait == UMH_NO_WAIT { return Submitted::Detached; }
            // A backend may only detach a request the caller agreed not to
            // observe. Anything else is an unreported helper, so report the
            // failure rather than a zero the caller would read as success.
            Submitted::Result(-(Errno::Einval.as_i32()))
        }
        HelperRun::Done(done) => {
            let rc = done.retval;
            *info = done;
            Submitted::Result(rc)
        }
    }
}

/// Build and submit in one step, with no callbacks. # C: O(argv + envp + backend)
pub fn call_usermodehelper(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], wait: i32) -> i32 {
    let info = call_usermodehelper_setup(path, argv, envp, None, None, 0);
    call_usermodehelper_exec(info, wait)
}
