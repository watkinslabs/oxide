// How sockets acquire security labels, and how a socket's recorded peer label
// becomes the context userspace reads back from `SO_PEERSEC`.
//
// A peer label is a property of an established connection, recorded once when
// the connection forms and read back afterwards. This module owns only the
// boundary: the module that labels sockets installs its answers here, and the
// socket owners store the label ids on the connection itself. Keeping a table
// of labels keyed by socket identity here instead would be a second source of
// truth that outlives the sockets it describes.
//
// No target gate: every decision in this file must run under hosted tests.

use alloc::vec::Vec;
use syscall::errno::Errno;
use sync::{Namespace, Spinlock};

/// The label id that means "no label was specified".
///
/// Never a valid label. A socket whose peer label is this reports no context at
/// all, which is also what a caller sees when no module labels sockets.
pub const NO_LABEL: u32 = 0;

/// The answers a module that labels sockets supplies.
///
/// One installed record rather than three separate slots: a build with a create
/// hook but no renderer could record label ids nothing can ever read back, and
/// there would be no single moment at which labelling became available.
#[derive(Copy, Clone)]
pub struct SocketLabelOps {
    /// Label a socket created right now takes, read from the creating task.
    pub create: fn() -> u32,
    /// Label reported for a peer that no label was ever recorded for.
    ///
    /// Not `NO_LABEL`: a socket of a class that reports peer labels has one from
    /// the moment it exists, and before it connects that label is the module's
    /// name for "unlabelled". Reporting nothing instead would make an
    /// unconnected socket indistinguishable from one on a kernel with no
    /// module at all.
    pub unlabeled: u32,
    /// Rendered context of one label id, as userspace reads it.
    pub context: fn(u32) -> Result<Vec<u8>, Errno>,
    /// Label the server end of a new connection takes: the listening socket's
    /// identity carrying the connecting socket's sensitivity.
    ///
    /// Not simply the listener's label. A service accepting from clients at
    /// several sensitivities gets one server end per client sensitivity, and
    /// that is the label the client reads back — collapsing them to the
    /// listener's own would report the same label to every client and lose the
    /// distinction the policy was written to make.
    pub server_end: fn(listener: u32, client: u32) -> u32,
}

static SOCKET_LABEL: Spinlock<Option<SocketLabelOps>, Namespace> = Spinlock::new(None);

/// Install the one module that labels sockets. # C: O(1)
///
/// Refused if one is already installed: a second set of answers could label a
/// socket at creation and render it through a different policy's table.
pub fn install_socket_label(ops: SocketLabelOps) -> bool {
    let mut slot = SOCKET_LABEL.lock();
    if slot.is_some() { return false; }
    *slot = Some(ops);
    true
}

/// Remove the socket-labelling module. # C: O(1)
pub fn remove_socket_label() -> bool { SOCKET_LABEL.lock().take().is_some() }

/// Label a socket created now takes. # C: O(1)
///
/// `NO_LABEL` when nothing labels sockets, so an unlabelled build records the
/// same "no label" every reader already handles.
pub fn new_socket_label() -> u32 {
    // The hook is copied out and the guard dropped before it runs: it reads
    // task state under the task owner's own lock, and holding this one across
    // that would order two locks that have no order between them.
    let ops = *SOCKET_LABEL.lock();
    match ops { Some(ops) => (ops.create)(), None => NO_LABEL }
}

/// Label reported for a peer no label was recorded for. # C: O(1)
pub fn unlabeled_socket_label() -> u32 {
    let ops = *SOCKET_LABEL.lock();
    match ops { Some(ops) => ops.unlabeled, None => NO_LABEL }
}

/// Label the server end of a new connection takes. # C: O(1)
///
/// The listener's label stands when nothing labels sockets, so an unlabelled
/// build records the connection exactly as a labelled one does and simply has
/// `NO_LABEL` on both sides.
pub fn server_end_label(listener: u32, client: u32) -> u32 {
    let ops = *SOCKET_LABEL.lock();
    match ops { Some(ops) => (ops.server_end)(listener, client), None => listener }
}

/// Rendered context of one label id, terminated as userspace reads it.
/// # C: O(label)
///
/// The terminator is appended HERE rather than by the module, because the
/// length published beside this value counts it: a module that returned an
/// unterminated context would have every caller allocate one byte short and
/// read past the end of its own buffer on the retry.
pub fn socket_label_context(label: u32) -> Result<Option<Vec<u8>>, Errno> {
    if label == NO_LABEL { return Ok(None); }
    let ops = *SOCKET_LABEL.lock();
    let Some(ops) = ops else { return Ok(None) };
    let mut bytes = (ops.context)(label)?;
    // A module that already terminated its answer is not given a second NUL:
    // the published length would then exceed the string by two.
    if bytes.last() != Some(&0) { bytes.push(0); }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED: u32 = 41;
    const UNLABELED: u32 = 3;

    fn create() -> u32 { CREATED }
    fn context(label: u32) -> Result<Vec<u8>, Errno> {
        match label {
            CREATED => Ok(Vec::from(&b"system_u:system_r:peer_t:s0"[..])),
            UNLABELED => Ok(Vec::from(&b"unlabeled"[..])),
            // Already terminated, to prove the terminator is not doubled.
            9 => Ok(Vec::from(&b"terminated\0"[..])),
            _ => Err(Errno::Einval),
        }
    }

    /// Stands in for the range copy: the listener's identity in the high half,
    /// the client's sensitivity in the low half, so a test can see BOTH inputs
    /// reached the answer.
    fn server_end(listener: u32, client: u32) -> u32 { (listener << 8) | (client & 0xff) }

    fn ops() -> SocketLabelOps {
        SocketLabelOps { create, unlabeled: UNLABELED, context, server_end }
    }

    /// There is ONE installed module for the whole kernel, so these tests all
    /// write the same slot. libtest runs them concurrently, so without this
    /// they would install over each other and fail on whichever interleaving
    /// the run happened to take — a flake that reads as a real defect.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = remove_socket_label();
        guard
    }

    /// Every read must answer "no label" until a module installs, because that
    /// is the whole difference between a kernel that labels sockets and one
    /// that does not.
    #[test]
    fn nothing_is_labelled_until_a_module_installs() {
        let _exclusive = exclusive();
        assert_eq!(new_socket_label(), NO_LABEL);
        assert_eq!(unlabeled_socket_label(), NO_LABEL);
        assert_eq!(socket_label_context(CREATED), Ok(None));
        assert!(install_socket_label(ops()));
        assert_eq!(new_socket_label(), CREATED);
        assert_eq!(unlabeled_socket_label(), UNLABELED);
        assert!(remove_socket_label());
        assert_eq!(new_socket_label(), NO_LABEL);
    }

    /// A second module would label at creation through one policy and render
    /// through another.
    #[test]
    fn a_second_labelling_module_is_refused() {
        let _exclusive = exclusive();
        assert!(install_socket_label(ops()));
        assert!(!install_socket_label(ops()));
        assert!(remove_socket_label());
        assert!(!remove_socket_label());
    }

    /// The published length counts the terminator, so the value must carry one
    /// — exactly one, whether or not the module supplied it.
    #[test]
    fn a_rendered_context_is_terminated_exactly_once() {
        let _exclusive = exclusive();
        assert!(install_socket_label(ops()));
        let bytes = socket_label_context(CREATED).unwrap().unwrap();
        assert_eq!(bytes, b"system_u:system_r:peer_t:s0\0");
        assert_eq!(bytes.len(), b"system_u:system_r:peer_t:s0".len() + 1);
        // A module that terminated its own answer is not given a second NUL.
        assert_eq!(socket_label_context(9).unwrap().unwrap(), b"terminated\0");
        assert!(remove_socket_label());
    }

    /// A network-namespace teardown removes that namespace's operation hooks
    /// and nothing else. Socket labelling is kernel-wide, so taking it down
    /// with one namespace would unlabel the sockets in all the others.
    #[test]
    fn a_namespace_teardown_leaves_socket_labelling_installed() {
        let _exclusive = exclusive();
        assert!(install_socket_label(ops()));
        assert_eq!(super::super::remove_namespace(31), 0);
        assert_eq!(new_socket_label(), CREATED);
        assert_eq!(unlabeled_socket_label(), UNLABELED);
        assert!(remove_socket_label());
    }

    /// The server end's label must be derived from BOTH ends. A build with no
    /// module records the listener's label unchanged, so the connection is
    /// recorded identically either way and only the value differs.
    #[test]
    fn the_server_end_label_combines_both_ends() {
        let _exclusive = exclusive();
        // With no module the listener's label stands.
        assert_eq!(server_end_label(7, 9), 7);
        assert_eq!(server_end_label(NO_LABEL, NO_LABEL), NO_LABEL);
        assert!(install_socket_label(ops()));
        // Both inputs reach the answer: same listener, different clients, and
        // the results differ.
        assert_eq!(server_end_label(7, 9), (7 << 8) | 9);
        assert_ne!(server_end_label(7, 9), server_end_label(7, 10));
        assert_ne!(server_end_label(7, 9), server_end_label(8, 9));
        assert!(remove_socket_label());
        assert_eq!(server_end_label(7, 9), 7);
    }

    /// The absent-label id is not a lookup that happens to miss: it is refused
    /// before the module is consulted, so no module can ever render it.
    #[test]
    fn absence_and_a_render_failure_remain_distinct() {
        let _exclusive = exclusive();
        assert!(install_socket_label(ops()));
        assert_eq!(socket_label_context(NO_LABEL), Ok(None));
        // An existing label the module cannot render is an error, not absence.
        assert_eq!(socket_label_context(4096), Err(Errno::Einval));
        assert!(remove_socket_label());
    }
}
