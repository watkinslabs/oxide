// Out-of-band arrival notification, shared by every socket family that has an
// urgent channel — AF_UNIX `SOCK_STREAM` and TCP today.
//
// Urgent arrival produces TWO independent notifications, and they have exactly
// one owner each:
//
//   1. An unconditional `SIGURG` to the receiving open file description's
//      `f_owner`. It needs neither `O_ASYNC` nor a fasync registration, so a
//      receiver that only called `fcntl(F_SETOWN)` still gets a signal. Its
//      one owner is `vfs::File::send_sigurg` — this module resolves the
//      description and calls it, and adds no delivery of its own.
//   2. The fasync half, which delivers nothing unless `F_SETSIG` chose a
//      queued signal (a plain `SIGURG` there would duplicate 1). Its one owner
//      is the readiness wake that already carries `POLL_PRI`
//      (`PollSubscribers::notify_mask` / the keyless re-poll), so this module
//      must NOT raise it a second time.
//
// Ungated on purpose: the arrival decision is testable logic, and a
// target-gated module would compile its tests away silently.

extern crate alloc;
use alloc::sync::{Arc, Weak};

/// Notify the receiving description that urgent data arrived (Linux
/// `sk_send_sigurg`). `file` is the receiver's open file description, absent
/// while the socket has no fd bound to it — a socket userspace cannot name has
/// no owner to signal.
///
/// Reports whether an owner was recorded, which is what gates the fasync half
/// at its own owner. # C: O(1)
pub fn sk_send_sigurg(file: Option<Arc<vfs::File>>) -> bool {
    match file { Some(file) => file.send_sigurg(), None => false }
}

/// [`sk_send_sigurg`] against a weak description reference — the form every
/// socket holds, so a closed fd simply resolves to no owner. # C: O(1)
pub fn sk_send_sigurg_weak(file: &Weak<vfs::File>) -> bool {
    sk_send_sigurg(file.upgrade())
}

/// Whether a segment's processing installed a NEW urgent pointer, comparing
/// the receiver's pending urgent `(seq, byte)` before and after.
///
/// Linux announces an urgent pointer exactly once — a retransmit of the same
/// urgent segment, or a duplicate pointer that is not past the one already
/// held, notifies nobody. `pre == post` is that test: a re-delivered pointer
/// leaves the pending record identical, and a consumed one that a later
/// segment re-arms carries a different sequence.
/// # C: O(1)
pub fn urgent_arrived(pre: Option<(u32, u8)>, post: Option<(u32, u8)>) -> bool {
    post.is_some() && post != pre
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_urgent_pointer_is_announced() {
        assert!(urgent_arrived(None, Some((100, b'!'))));
    }

    #[test]
    fn repeated_urgent_pointer_is_announced_once() {
        // A retransmitted URG segment re-presents the same pointer; the
        // receiver already told the world about it.
        assert!(!urgent_arrived(Some((100, b'!')), Some((100, b'!'))));
    }

    #[test]
    fn later_urgent_pointer_is_announced_again() {
        assert!(urgent_arrived(Some((100, b'!')), Some((140, b'?'))));
        // Re-armed after the pending byte was consumed.
        assert!(urgent_arrived(None, Some((140, b'?'))));
    }

    #[test]
    fn consuming_or_dropping_the_pointer_announces_nothing() {
        assert!(!urgent_arrived(Some((100, b'!')), None));
        assert!(!urgent_arrived(None, None));
    }

    #[test]
    fn a_socket_with_no_description_has_no_owner_to_signal() {
        assert!(!sk_send_sigurg(None));
        assert!(!sk_send_sigurg_weak(&Weak::<vfs::File>::new()));
    }
}
