//! Lifetime of the inherited desktop bridge capability during PE handoff.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

/// Own the child until exec replaces the launcher or launch fails.
pub struct Session {
    child: Child,
    endpoint: UnixStream,
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
    command.args(["--fd", "0"]);
    let mut session = spawn_bridge(&mut command)?;
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
    let child = command.stdin(Stdio::from(peer)).stdout(Stdio::null())
        .stderr(Stdio::inherit()).spawn()?;
    Ok(Session { child, endpoint })
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
}
