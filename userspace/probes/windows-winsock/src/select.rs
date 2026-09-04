//! Windows `select` result projection over native poll readiness.

use alloc::vec::Vec;

use crate::WsaError;

/// Native readiness received from the Linux-shaped socket owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketReadiness {
    pub socket: u64,
    pub events: u32,
    pub valid: bool,
}

/// Native readiness bits consumed by the Winsock projection.
pub const READY_READ: u32 = 1 << 0;
pub const READY_ACCEPT: u32 = 1 << 1;
pub const READY_WRITE: u32 = 1 << 2;
pub const READY_HUP: u32 = 1 << 3;
pub const READY_RESET: u32 = 1 << 4;
pub const READY_OOB: u32 = 1 << 5;
pub const READY_CONNECT_ERROR: u32 = 1 << 6;
pub const READY_ERROR: u32 = 1 << 7;

/// The three result sets produced by the Windows `select` boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectProjection {
    pub read: Vec<u64>,
    pub write: Vec<u64>,
    pub except: Vec<u64>,
}

impl SelectProjection {
    /// Number of ready entries, counted once per result set. # C: O(R + W + X)
    pub fn count(&self) -> usize {
        self.read.len() + self.write.len() + self.except.len()
    }
}

fn append_once(output: &mut Vec<u64>, socket: u64) {
    if !output.iter().any(|entry| *entry == socket) {
        output.push(socket);
    }
}

fn readiness_for(socket: u64, readiness: &[SocketReadiness]) -> Result<u32, WsaError> {
    let Some(entry) = readiness.iter().find(|entry| entry.socket == socket) else {
        return Err(WsaError::NotSocket);
    };
    if !entry.valid {
        return Err(WsaError::NotSocket);
    }
    Ok(entry.events)
}

/// Project native readiness into Windows `fd_set` results.
///
/// The native wait and timeout are deliberately outside this function. Linux
/// returns one result bitmap per requested class; Winsock returns the same
/// three classes as compact descriptor arrays. Readability includes EOF/reset
/// and errors, writability includes errors, and the exception set contains
/// out-of-band data and connect errors.
/// # C: O((R + W + X) * S)
pub fn project_select(
    read: &[u64],
    write: &[u64],
    except: &[u64],
    readiness: &[SocketReadiness],
) -> Result<SelectProjection, WsaError> {
    if read.is_empty() && write.is_empty() && except.is_empty() {
        return Err(WsaError::InvalidArgument);
    }

    let mut result = SelectProjection { read: Vec::new(), write: Vec::new(), except: Vec::new() };
    for &socket in read {
        let events = readiness_for(socket, readiness)?;
        if events & (READY_READ | READY_ACCEPT | READY_HUP | READY_RESET | READY_ERROR) != 0 {
            append_once(&mut result.read, socket);
        }
    }
    for &socket in write {
        let events = readiness_for(socket, readiness)?;
        if events & (READY_WRITE | READY_ERROR) != 0 {
            append_once(&mut result.write, socket);
        }
    }
    for &socket in except {
        let events = readiness_for(socket, readiness)?;
        if events & (READY_OOB | READY_CONNECT_ERROR) != 0 {
            append_once(&mut result.except, socket);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(socket: u64, events: u32) -> SocketReadiness {
        SocketReadiness { socket, events, valid: true }
    }

    #[test]
    fn projects_linux_poll_classes_to_winsock_sets() {
        let result = project_select(
            &[10, 11], &[10, 12], &[13, 14],
            &[ready(10, READY_READ | READY_WRITE), ready(11, READY_HUP),
              ready(12, READY_ERROR), ready(13, READY_OOB), ready(14, READY_CONNECT_ERROR)],
        ).unwrap();
        assert_eq!(result.read, vec![10, 11]);
        assert_eq!(result.write, vec![10, 12]);
        assert_eq!(result.except, vec![13, 14]);
        assert_eq!(result.count(), 6);
    }

    #[test]
    fn fd_set_duplicates_are_returned_once_per_class() {
        let result = project_select(&[7, 7], &[7, 7], &[], &[ready(7, READY_READ | READY_WRITE)]).unwrap();
        assert_eq!(result.read, vec![7]);
        assert_eq!(result.write, vec![7]);
        assert_eq!(result.count(), 2);
    }

    #[test]
    fn invalid_socket_fails_before_a_partial_result_is_observable() {
        assert_eq!(project_select(&[7, 8], &[], &[], &[ready(7, READY_READ), SocketReadiness { socket: 8, events: 0, valid: false }]), Err(WsaError::NotSocket));
    }

    #[test]
    fn an_empty_request_is_winsock_invalid_argument() {
        assert_eq!(project_select(&[], &[], &[], &[]), Err(WsaError::InvalidArgument));
    }
}
