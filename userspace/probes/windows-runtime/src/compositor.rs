//! Lifetime of the inherited desktop bridge capability during PE handoff.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Descriptor the bridge child inherits for its readiness notification, past stdio.
const READY_FD: RawFd = 3;
/// One byte written by the child once its monitor snapshot is queued on the bridge.
const READY_TOKEN: u8 = b'R';
/// Liveness bound only. A child that dies reports as EOF, and a child that is
/// merely slow to open its display measured a few seconds; this is the service
/// start bound, not a race against display connection.
const READY_TIMEOUT: Duration = Duration::from_secs(90);

/// Why the child never reported itself ready.
#[derive(Debug)]
enum ReadyError { Gone, Timeout, Token(u8), Io(io::Error) }

/// Own the child until exec replaces the launcher or launch fails.
pub struct Session {
    child: Child,
    endpoint: UnixStream,
    ready: Option<OwnedFd>,
}

impl Session {
    /// Describe how the bridge child is doing, for a failure report. A signal
    /// or a silent nonzero exit is the whole diagnosis when the child wrote
    /// nothing, which is exactly the case this exists for.
    fn describe_child(&mut self) -> String {
        use std::os::unix::process::ExitStatusExt;
        match self.child.try_wait() {
            Ok(None) => String::from("bridge child still running"),
            Ok(Some(status)) => match (status.code(), status.signal()) {
                (Some(code), _) => format!("bridge child exited with status {code}"),
                (None, Some(signal)) => format!("bridge child killed by signal {signal}"),
                _ => format!("bridge child ended: {status}"),
            },
            Err(error) => format!("bridge child status unavailable: {error}"),
        }
    }

    /// Block until the child publishes its monitor snapshot and says so. The
    /// kernel handshake that follows then reads data already on the socket.
    /// # C: O(child startup)
    fn await_child_ready(&mut self) -> io::Result<()> {
        let reader = self.ready.take().ok_or_else(|| io::Error::other("readiness descriptor already consumed"))?;
        match await_ready(reader.as_fd(), READY_TIMEOUT) {
            Ok(()) => Ok(()),
            Err(ReadyError::Gone) => Err(io::Error::other(format!(
                "desktop bridge never became ready; {}", self.describe_child()))),
            Err(ReadyError::Timeout) => Err(io::Error::new(io::ErrorKind::TimedOut, format!(
                "desktop bridge not ready after {}s; {}", READY_TIMEOUT.as_secs(), self.describe_child()))),
            Err(ReadyError::Token(byte)) => Err(io::Error::other(format!(
                "desktop bridge sent readiness byte 0x{byte:02x}"))),
            Err(ReadyError::Io(error)) => Err(error),
        }
    }
}

/// Wait for the one readiness byte. EOF is the child's death, and the bound is
/// only there so a wedged display server cannot hang the launcher forever.
fn await_ready(fd: BorrowedFd<'_>, timeout: Duration) -> Result<(), ReadyError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(ReadyError::Timeout); }
        let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let millis = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: one initialized pollfd describing a live borrowed descriptor;
        // poll does not retain the pointer past the call.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(ReadyError::Io(error));
        }
        if ready == 0 { return Err(ReadyError::Timeout); }
        let mut byte = 0u8;
        // SAFETY: reads at most one byte into a live local from the borrowed
        // readiness descriptor, which poll just reported as readable or hung up.
        let count = unsafe { libc::read(fd.as_raw_fd(), core::ptr::addr_of_mut!(byte).cast(), 1) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) { continue; }
            return Err(ReadyError::Io(error));
        }
        if count == 0 { return Err(ReadyError::Gone); }
        if byte != READY_TOKEN { return Err(ReadyError::Token(byte)); }
        return Ok(());
    }
}

/// Close-on-exec pipe whose write end the child inherits at READY_FD.
fn ready_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 fills exactly two descriptors in this local array on success
    // and the raw values are wrapped in owning handles immediately.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 { return Err(io::Error::last_os_error()); }
    // SAFETY: both descriptors are fresh from a successful pipe2 and unowned.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Runs between fork and exec: put the readiness write end where the child
/// expects it and make sure exec does not close it.
fn place_ready_fd(raw: RawFd) -> io::Result<()> {
    if raw == READY_FD {
        // SAFETY: async-signal-safe fcntl on this child's own descriptor table,
        // clearing close-on-exec so the readiness end survives exec.
        if unsafe { libc::fcntl(READY_FD, libc::F_SETFD, 0) } < 0 { return Err(io::Error::last_os_error()); }
        return Ok(());
    }
    // SAFETY: async-signal-safe dup2 in the pre-exec child; the duplicate has
    // close-on-exec clear by definition and stdio is already installed.
    if unsafe { libc::dup2(raw, READY_FD) } < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.endpoint.shutdown(std::net::Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start in the Linux desktop session, before changing personality to NT.
/// # C: O(process launch + compositor handshake)
pub fn start() -> io::Result<Session> {
    if std::env::var_os("DISPLAY").is_none_or(|value| value.is_empty()) {
        return Err(io::Error::new(io::ErrorKind::NotConnected,
            "DISPLAY is missing; start Notepad in an X11 or XWayland desktop session"));
    }
    let mut command = Command::new("/usr/local/bin/windows-compositor");
    command.args(["--fd", "0", "--ready-fd"]).arg(READY_FD.to_string());
    let mut session = spawn_bridge(&mut command)?;
    // The kernel's handshake is a backstop, not a race with X startup: wait here
    // for this launcher's own child to report itself ready first.
    session.await_child_ready()?;
    // SAFETY: the descriptor remains owned by session through binding. The
    // kernel validates and retains the connected socket capability, not this
    // userspace descriptor number. No pointers cross this service boundary.
    let status = unsafe {
        libc::syscall(syscall::nt::NtService::BindCompositor.entry() as libc::c_long,
            session.endpoint.as_raw_fd() as libc::c_long)
    };
    if status == -1 { return Err(io::Error::last_os_error()); }
    if status != 0 {
        // The bridge only fails because the child failed, and the child has so
        // far died without writing anything. Its wait status is then the only
        // evidence of why, so it is reported instead of the NTSTATUS alone.
        return Err(io::Error::other(format!("desktop bridge rejected: NTSTATUS 0x{status:08x}; {}",
            session.describe_child())));
    }
    Ok(session)
}

fn spawn_bridge(command: &mut Command) -> io::Result<Session> {
    let (endpoint, peer) = UnixStream::pair()?;
    let peer: OwnedFd = peer.into();
    let (reader, writer) = ready_pipe()?;
    let raw = writer.as_raw_fd();
    // SAFETY: the closure runs in the forked child before exec and calls only
    // async-signal-safe descriptor operations on that child's own table.
    unsafe { command.pre_exec(move || place_ready_fd(raw)); }
    let child = command.stdin(Stdio::from(peer)).stdout(Stdio::null())
        .stderr(Stdio::inherit()).spawn()?;
    drop(writer);
    Ok(Session { child, endpoint, ready: Some(reader) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn child_receives_a_duplex_socket_at_fd_zero() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "read line; printf '%s' \"$line\" >&0"]);
        let mut session = spawn_bridge(&mut command).unwrap();
        session.endpoint.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        session.endpoint.write_all(b"bridge-capability\n").unwrap();
        let mut reply = [0u8; 17];
        session.endpoint.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"bridge-capability");
        assert!(session.child.wait().unwrap().success());
    }

    #[test]
    fn failed_spawn_is_not_a_started_bridge() {
        let error = spawn_bridge(&mut Command::new("/nonexistent-oxide-compositor-fixture"));
        assert!(matches!(error, Err(ref e) if e.kind() == io::ErrorKind::NotFound));
    }

    /// A child that never reports readiness must be distinguishable from one
    /// that died: the launcher acts on the notification, not on a timer.
    #[test]
    fn readiness_token_ends_the_wait() {
        let (reader, writer) = ready_pipe().unwrap();
        // SAFETY: writes the single readiness byte to an owned pipe write end.
        assert_eq!(unsafe { libc::write(writer.as_raw_fd(), [READY_TOKEN].as_ptr().cast(), 1) }, 1);
        assert!(await_ready(reader.as_fd(), Duration::from_millis(500)).is_ok());
    }

    #[test]
    fn a_closed_write_end_is_a_dead_child_not_a_timeout() {
        let (reader, writer) = ready_pipe().unwrap();
        drop(writer);
        assert!(matches!(await_ready(reader.as_fd(), Duration::from_secs(5)), Err(ReadyError::Gone)));
    }

    #[test]
    fn a_silent_live_child_times_out() {
        let (reader, _writer) = ready_pipe().unwrap();
        assert!(matches!(await_ready(reader.as_fd(), Duration::from_millis(30)), Err(ReadyError::Timeout)));
    }

    #[test]
    fn a_foreign_byte_is_not_readiness() {
        let (reader, writer) = ready_pipe().unwrap();
        // SAFETY: writes one non-token byte to an owned pipe write end.
        assert_eq!(unsafe { libc::write(writer.as_raw_fd(), [b'X'].as_ptr().cast(), 1) }, 1);
        assert!(matches!(await_ready(reader.as_fd(), Duration::from_millis(500)), Err(ReadyError::Token(b'X'))));
    }

    #[test]
    fn the_child_inherits_a_writable_readiness_fd_past_stdio() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf R >&3"]);
        let mut session = spawn_bridge(&mut command).unwrap();
        session.await_child_ready().unwrap();
        assert!(session.child.wait().unwrap().success());
    }

    /// The whole point of the notification: by the time the launcher proceeds,
    /// the monitor record the kernel wants is already queued on the bridge.
    #[test]
    fn monitor_data_is_queued_before_readiness_is_reported() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf MON >&0; printf R >&3"]);
        let mut session = spawn_bridge(&mut command).unwrap();
        session.await_child_ready().unwrap();
        session.endpoint.set_read_timeout(Some(std::time::Duration::from_millis(1))).unwrap();
        let mut queued = [0u8; 3];
        session.endpoint.read_exact(&mut queued).unwrap();
        assert_eq!(&queued, b"MON");
    }

    #[test]
    fn a_child_that_dies_before_readiness_reports_the_child_not_a_timeout() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 3"]);
        let mut session = spawn_bridge(&mut command).unwrap();
        let error = session.await_child_ready().unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("never became ready"), "{error}");
    }
}
