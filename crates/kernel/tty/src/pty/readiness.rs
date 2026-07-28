// Readiness predicates for a pty pair — Linux `n_tty_poll`
// (`drivers/tty/n_tty.c:2419-2458`) and `pty_write_room`
// (`drivers/tty/pty.c:126-131`).
//
// They live in `tty`, not in the devpts VFS shim, for two reasons: the tty is
// the source of truth for its own state (`28§5`), and
// `crates/kernel/devpts/src/lib.rs` is `#![cfg(target_os = "oxide-kernel")]`,
// so a `#[cfg(test)]` block written there compiles out silently and reports
// "ok" having built nothing.

use super::pair::Pair;

impl Pair {
    /// Linux `n_tty_poll` (`drivers/tty/n_tty.c:2419-2458`) for the MASTER
    /// half of the pair: `EPOLLIN` from `input_available_p`, `EPOLLOUT` while
    /// `tty_write_room(tty) > 0`. `tty_chars_in_buffer` is 0 for a pty (the
    /// pty driver has no `chars_in_buffer` op), so the `< WAKEUP_CHARS` arm is
    /// always satisfied and drops out. Lives here, not in the devpts VFS shim,
    /// so the decision is unit-testable — the shim's file is
    /// `target_os = "oxide-kernel"`-gated and a `#[cfg(test)]` block in it
    /// would compile out silently.
    /// # C: O(1) raw, O(N) queued bytes under ICANON
    pub fn master_poll_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.master_write_room() > 0 { mask |= vfs::POLL_OUT | vfs::POLL_WRNORM; }
        if self.master_readable() { mask |= vfs::POLL_IN | vfs::POLL_RDNORM; }
        mask
    }

    /// `n_tty_poll` for the SLAVE half. `EPOLLHUP` mirrors the
    /// `test_bit(TTY_OTHER_CLOSED, &tty->flags)` arm, which `pty_close` sets on
    /// the link when the master's last descriptor goes away
    /// (`drivers/tty/pty.c:68`) — the end-of-session signal every terminal
    /// event loop watches for.
    /// # C: O(1) raw, O(N) queued bytes under ICANON
    pub fn slave_poll_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.slave_write_room() > 0 { mask |= vfs::POLL_OUT | vfs::POLL_WRNORM; }
        if self.slave_readable() { mask |= vfs::POLL_IN | vfs::POLL_RDNORM; }
        if self.slave_hung_up() { mask |= vfs::POLL_HUP; }
        mask
    }

    /// Linux `pty_write_room` (`drivers/tty/pty.c:126-131`) for the MASTER
    /// half: bytes the master may still push at the slave, i.e. free space in
    /// the peer's buffer. `n_tty_poll` reports `EPOLLOUT` only while this is
    /// non-zero (`drivers/tty/n_tty.c:2452-2455`). # C: O(1)
    pub fn master_write_room(&self) -> usize { self.m_to_s.space() }

    /// `pty_write_room` for the SLAVE half. Linux returns 0 outright while
    /// `tty->flow.stopped` (the ^S / TCOOFF state), so a poll-driven writer
    /// sleeps instead of spinning until ^Q. # C: O(1)
    pub fn slave_write_room(&self) -> usize {
        if self.output_stopped { 0 } else { self.s_to_m.space() }
    }

}
