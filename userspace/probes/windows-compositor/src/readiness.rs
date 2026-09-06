//! Explicit startup readiness notification to the process that spawned this one.
//!
//! A client that must not proceed until this service is up waits for a
//! notification, it does not race a timer: the launcher blocks on an inherited
//! descriptor, and this process writes one byte on it only after the monitor
//! snapshot is already queued on the bridge. The kernel handshake that follows
//! therefore observes data that has already been written, and its bounded wait
//! is a liveness backstop rather than a display-startup race.

use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::{BridgeEvent, MonitorSnapshot, NativeTransport, TransportError};

/// Written once, then the descriptor closes. The byte means ready; EOF without
/// it means this process died before reaching readiness.
pub const READY_TOKEN: u8 = b'R';
/// The bridge socket is inherited at fd 0; stdio occupies 0..=2.
const BRIDGE_FD: RawFd = 0;
const MIN_READY_FD: RawFd = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options { pub ready_fd: Option<RawFd> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsageError;

/// Accepts `--fd 0`, optionally followed by `--ready-fd <n>` with n above stdio.
/// Arguments exclude the program name. # C: O(args)
pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<Options, UsageError> {
    let mut bridge = false;
    let mut ready_fd = None;
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).ok_or(UsageError)?.as_ref();
        match args[i].as_ref() {
            "--fd" => { if value.parse::<RawFd>() != Ok(BRIDGE_FD) { return Err(UsageError); } bridge = true; }
            "--ready-fd" => {
                let fd: RawFd = value.parse().map_err(|_| UsageError)?;
                if fd < MIN_READY_FD { return Err(UsageError); }
                ready_fd = Some(fd);
            }
            _ => return Err(UsageError),
        }
        i += 2;
    }
    if bridge { Ok(Options { ready_fd }) } else { Err(UsageError) }
}

/// Consumes the descriptor: the write is followed by a close, so a launcher
/// blocked on it sees either the token or EOF, never an indefinite wait.
/// # C: O(1)
pub fn notify(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: the readiness descriptor is inherited for this single use and is
    // owned by this process from here on; taking ownership closes it exactly once.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    std::fs::File::from(owned).write_all(&[READY_TOKEN])
}

/// Publication precedes readiness. A failed publication signals nothing, so the
/// launcher observes EOF on exit rather than a false ready.
/// # C: O(snapshot)
pub fn publish_then_notify<T: NativeTransport>(transport: &mut T, snapshot: MonitorSnapshot, ready_fd: Option<RawFd>)
    -> Result<(), TransportError> {
    transport.send(BridgeEvent::WorkArea(snapshot))?;
    if let Some(fd) = ready_fd { notify(fd).map_err(TransportError::Io)?; }
    Ok(())
}

#[cfg(test)]
#[path = "tests/readiness.rs"] mod tests;
