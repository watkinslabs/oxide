// Hosted tests for the PTY pair core per `28§5`.

use super::*;

fn cooked(pts: u32) -> Pair {
    let mut p = Pair::new(pts);
    p.termios = default_termios();
    p
}

mod ring_and_pair;
mod cooked;
mod flow_and_hangup;
