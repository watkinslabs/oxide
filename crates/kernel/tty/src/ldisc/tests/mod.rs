// N_TTY hosted tests: drive bytes through the discipline with a
// recording driver; assert cooked lines, echo bytes, signals, raw
// passthrough, edit keys, EOF, iflag/oflag mapping, poll. Plus a
// proptest fuzz: random streams never panic / never over-read / never
// return an unterminated canonical line.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use proptest::prelude::*;

use super::{pollmask, LdiscOps, NTty, Sig, TtyDriverHooks};
use crate::pty::{
    cc, default_termios, iflag, lflag, oflag, TERMIOS_BYTES, TERMIOS_OFF_CC,
    TERMIOS_OFF_IFLAG, TERMIOS_OFF_LFLAG, TERMIOS_OFF_OFLAG,
};

/// Captures driver_write bytes + raised signals.
#[derive(Default)]
struct RecordingDriver {
    out: Vec<u8>,
    sigs: Vec<Sig>,
}

impl TtyDriverHooks for RecordingDriver {
    fn driver_write(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        self.sigs.push(sig);
    }
}

fn set_u32(t: &mut [u8; TERMIOS_BYTES], off: usize, v: u32) {
    t[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Read all currently-available bytes via repeated `read` (canonical
/// returns one line per call).
fn drain(n: &mut NTty) -> Vec<u8> {
    let mut all = Vec::new();
    loop {
        let mut buf = [0u8; 256];
        let got = n.read(&mut buf);
        if got == 0 {
            break;
        }
        all.extend_from_slice(&buf[..got]);
    }
    all
}

mod canonical;
mod runtime;
mod properties;
