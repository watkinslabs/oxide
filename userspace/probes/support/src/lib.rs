//! Shared probe output + errno access.
//!
//! Probe verdicts are scraped off the serial console by `tools/boot-smoke-*.sh`,
//! so a line must reach fd 1 even when the guest is mid-failure and the runtime's
//! buffered writer may never flush. Every line here goes out with one `write(2)`.

use std::io::Write;

/// Terminal verdict of a probe run.
pub enum Verdict {
    /// Probe proved its contract. Detail is appended after `PASS`.
    Pass(String),
    /// Probe disproved it, or could not reach a conclusion. `where` names the step.
    Fail(String),
}

/// Write one line to fd 1 in a single unbuffered `write(2)`. # C: O(len)
///
/// `println!` buffers behind a lock and flushes at exit; a probe that aborts, or
/// whose guest wedges, loses the line. The smoke scripts poll for exactly this
/// text, so a lost line reads as a hang.
pub fn line(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Emit `<name>: PASS <detail>` / `<name>: FAIL <where> errno=<n>` and return the
/// process exit code. # C: O(len)
pub fn report(name: &str, verdict: Verdict) -> std::process::ExitCode {
    match verdict {
        Verdict::Pass(detail) if detail.is_empty() => { line(&format!("{name}: PASS")); std::process::ExitCode::SUCCESS }
        Verdict::Pass(detail) => { line(&format!("{name}: PASS {detail}")); std::process::ExitCode::SUCCESS }
        Verdict::Fail(text) => { line(&format!("{name}: FAIL {text}")); std::process::ExitCode::FAILURE }
    }
}

/// The calling thread's `errno`. # C: O(1)
pub fn errno() -> i32 {
    // SAFETY: __errno_location is glibc's per-thread errno accessor and always
    // returns a valid pointer to this thread's slot for the lifetime of the thread.
    unsafe { *libc::__errno_location() }
}

/// `Fail` naming the step plus the current errno — the shape every probe uses so
/// a failed run says where it stopped and why. # C: O(len)
pub fn fail_errno(step: &str) -> Verdict {
    Verdict::Fail(format!("{step} errno={}", errno()))
}

/// `Fail` naming a step that failed its assertion rather than a syscall. # C: O(len)
pub fn fail(step: &str) -> Verdict { Verdict::Fail(step.to_string()) }
