// Per-OPEN hangup revocation — the half of `__tty_hangup` that outlives the
// hangup itself.
//
// A hangup is not a property of the LINE, it is a property of every
// description that was open across it. The reference walks the tty's
// open-file list and swaps each `filp->f_op` to a dead vtable whose read
// returns EOF, write returns EIO and poll returns HUP; it then clears the
// tty's own hung-up flag on the NEXT successful open, so the line works for
// the new session while every descriptor from the old one stays dead
// forever. A single shared flag on the tty cannot express that: clearing it
// for the new opener resurrects the old session's descriptors, which is
// exactly the revocation `login`/`agetty` call `vhangup(2)` to get.
//
// Our `struct file` binds `f_op` once at construction, so instead of a
// mutable vtable pointer plus a registry of open files, each description
// SAMPLES the tty's hangup generation at open and the data path compares.
// Same observable contract, O(1), no list to walk and nothing to keep in
// sync with `open_count`.
//
//   open @ gen G ─── hangup (gen → G+1) ──▶ that open is revoked forever
//                    open @ gen G+1     ──▶ new description works
//
// The tty owns the counter; the description owns only its sample.

/// Generation an unbound description carries (`vfs::File::revoke_gen` default).
/// A tty's generation starts at `FIRST_GEN`, so `NOT_BOUND` never compares as
/// revoked — a description that never passed through a tty open hook (the
/// boot-time `/dev/console` fd table, which predates userspace) is not
/// something a later hangup may kill.
pub const NOT_BOUND: u64 = 0;

/// A tty's generation before its first hangup. Strictly greater than
/// [`NOT_BOUND`] so the two are never confused.
pub const FIRST_GEN: u64 = 1;

/// True when a description opened at `open_gen` predates the tty's current
/// `tty_gen` — the reference's "this file's `f_op` is `hung_up_tty_fops`".
/// Permanent: `tty_gen` only ever rises.
/// # C: O(1)
pub fn revoked(open_gen: u64, tty_gen: u64) -> bool {
    open_gen != NOT_BOUND && open_gen < tty_gen
}

/// `hung_up_tty_read` — a revoked description reads end-of-file, not an
/// error, and not the next session's input. # C: O(1)
pub const HUNG_UP_READ: usize = 0;

/// `hung_up_tty_poll` — every bit at once, HUP included, so a poll/select/
/// epoll waiter on a revoked descriptor returns immediately and forever.
/// # C: O(1)
pub const HUNG_UP_POLL: u32 = vfs::POLL_IN
    | vfs::POLL_OUT
    | vfs::POLL_ERR
    | vfs::POLL_HUP
    | vfs::POLL_RDNORM
    | vfs::POLL_WRNORM;

/// `hung_up_tty_ioctl`: every command on a revoked description is `EIO`,
/// except `TIOCSPGRP`, which is `ENOTTY` — a shell that has lost its terminal
/// must learn it is no longer a terminal, not that the device errored.
/// # C: O(1)
pub fn hung_up_ioctl(cmd: u32) -> vfs::VfsError {
    if cmd == crate::ioctl::req::TIOCSPGRP { vfs::VfsError::Enotty } else { vfs::VfsError::Eio }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_from_before_the_hangup_is_revoked() {
        assert!(revoked(FIRST_GEN, FIRST_GEN + 1));
        assert!(revoked(FIRST_GEN, FIRST_GEN + 9), "still dead many hangups later");
    }

    #[test]
    fn an_open_at_the_current_generation_is_live() {
        assert!(!revoked(FIRST_GEN, FIRST_GEN));
        assert!(!revoked(FIRST_GEN + 1, FIRST_GEN + 1), "reopened after the hangup");
    }

    #[test]
    fn an_unbound_description_is_never_revoked() {
        assert!(!revoked(NOT_BOUND, FIRST_GEN + 100));
    }

    #[test]
    fn a_revoked_tiocspgrp_is_enotty_and_every_other_ioctl_is_eio() {
        use crate::ioctl::req;
        assert_eq!(hung_up_ioctl(req::TIOCSPGRP), vfs::VfsError::Enotty);
        assert_eq!(hung_up_ioctl(req::TIOCGWINSZ), vfs::VfsError::Eio);
        assert_eq!(hung_up_ioctl(req::TCGETS), vfs::VfsError::Eio);
    }

    #[test]
    fn the_hung_up_poll_mask_reports_hangup_and_readiness() {
        assert_ne!(HUNG_UP_POLL & vfs::POLL_HUP, 0, "POLLHUP is the point");
        assert_ne!(HUNG_UP_POLL & vfs::POLL_IN, 0, "a revoked read returns at once");
        assert_ne!(HUNG_UP_POLL & vfs::POLL_ERR, 0);
    }
}
