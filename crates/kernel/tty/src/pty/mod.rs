// Module manifest:
// - `termios`: PTY termios bits, control chars, and winsize layout helpers.
// - `pair`: ring buffers plus master/slave PTY data-path state.
// - `readiness`: `n_tty_poll` / `pty_write_room` predicates for both halves.
// - `revoke`: per-open hangup generation and retired-slave behavior.

mod termios;
mod pair;
mod readiness;
mod revoke;

pub use pair::{
    Pair, Ring, TIOCPKT_DATA, TIOCPKT_DOSTOP, TIOCPKT_FLUSHREAD,
    TIOCPKT_FLUSHWRITE, TIOCPKT_IOCTL, TIOCPKT_NOSTOP, TIOCPKT_START,
    TIOCPKT_STOP,
};
pub use termios::{
    cc, cflag, default_termios, iflag, lflag, oflag, read_iflag, read_lflag, read_oflag,
    read_termios_u32, read_vintr, Winsize, DEFAULT_CFLAG, DEFAULT_IFLAG, DEFAULT_LFLAG,
    DEFAULT_OFLAG, DEFAULT_SPEED,
    DEFAULT_VEOF, DEFAULT_VERASE, DEFAULT_VINTR, DEFAULT_VKILL, DEFAULT_VQUIT, DEFAULT_VSTART,
    DEFAULT_VDISCARD, DEFAULT_VLNEXT, DEFAULT_VMIN, DEFAULT_VREPRINT, DEFAULT_VSTOP,
    DEFAULT_VSUSP, DEFAULT_VWERASE, NCCS, PTY_BUF_BYTES, TERMIOS_BYTES,
    TERMIOS_OFF_CC, TERMIOS_OFF_CFLAG, TERMIOS_OFF_IFLAG, TERMIOS_OFF_ISPEED, TERMIOS_OFF_LFLAG,
    TERMIOS_OFF_LINE, TERMIOS_OFF_OFLAG, TERMIOS_OFF_OSPEED, VINTR,
};

#[cfg(test)]
mod tests;
