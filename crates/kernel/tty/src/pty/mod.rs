// Module manifest:
// - `termios`: PTY termios bits, control chars, and winsize layout helpers.
// - `pair`: ring buffers plus master/slave PTY data-path state.

mod termios;
mod pair;

pub use pair::{Pair, Ring};
pub use termios::{
    cc, default_termios, iflag, lflag, oflag, read_iflag, read_lflag, read_oflag,
    read_termios_u32, read_vintr, Winsize, DEFAULT_IFLAG, DEFAULT_LFLAG, DEFAULT_OFLAG,
    DEFAULT_VEOF, DEFAULT_VERASE, DEFAULT_VINTR, DEFAULT_VKILL, DEFAULT_VQUIT, DEFAULT_VSTART,
    DEFAULT_VSTOP, DEFAULT_VSUSP, DEFAULT_VWERASE, NCCS, PTY_BUF_BYTES, TERMIOS_BYTES,
    TERMIOS_OFF_CC, TERMIOS_OFF_CFLAG, TERMIOS_OFF_IFLAG, TERMIOS_OFF_ISPEED, TERMIOS_OFF_LFLAG,
    TERMIOS_OFF_LINE, TERMIOS_OFF_OFLAG, TERMIOS_OFF_OSPEED, VINTR,
};

#[cfg(test)]
mod tests;
