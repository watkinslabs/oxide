use super::super::{pollmask, LdiscOps, TtyDriverHooks};
use super::state::NTty;
use super::timing::{flow_action, FlowAction, HOLD_CAP};
use crate::pty::{cc, oflag, TERMIOS_BYTES};

impl LdiscOps for NTty {
    fn receive_buf<D: TtyDriverHooks>(&mut self, drv: &mut D, input: &[u8]) {
        if self.hung_up { return; }
        for &raw in input {
            let b = match self.map_input(raw) {
                Some(b) => b,
                None => continue,
            };
            // IXON flow control runs BEFORE everything else in the input
            // path (Linux n_tty: ^S/^Q are intercepted before ISIG/canon).
            match flow_action(self.iflag(), self.cc(cc::VSTOP), self.cc(cc::VSTART), b, self.stopped) {
                FlowAction::Stop => { self.stopped = true; continue; }
                FlowAction::Start => {
                    self.stopped = false;
                    self.flush_hold(drv);
                    // VSTART/^S are consumed; an IXANY restart byte (other
                    // than ^S/^Q) still falls through to be processed.
                    if b == self.cc(cc::VSTART) || (self.cc(cc::VSTOP) != 0 && b == self.cc(cc::VSTOP)) {
                        continue;
                    }
                }
                FlowAction::Normal => {}
            }
            if self.handle_isig(drv, b) {
                continue;
            }
            if self.is_canon() {
                self.canon_byte(drv, b);
            } else {
                // Raw mode: byte straight to the read queue. Echo only
                // when ECHO set (e.g. bash with ECHO on but ICANON off).
                self.echo_byte(drv, b);
                self.readq.push_back(b);
            }
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        self.eof_consumed = false;
        if buf.is_empty() {
            return 0;
        }
        // Hung-up tty: any remaining queued bytes drain first, then EOF.
        if self.hung_up && self.readq.is_empty() {
            self.eof_consumed = true;
            return 0;
        }
        if self.is_canon() {
            // Canonical: return whole lines, never split a partial line.
            // Drain up to a newline/terminator or buf.len(), whichever
            // first. The terminator is part of the line.
            if self.readq.is_empty() {
                // EOF: ^D at line start with nothing queued → 0.
                if self.eof_pending {
                    self.eof_pending = false;
                    self.eof_consumed = true;
                }
                return 0;
            }
            let mut n = 0;
            while n < buf.len() {
                match self.readq.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                        if b == b'\n' {
                            break;
                        }
                    }
                    None => break,
                }
            }
            n
        } else {
            // Raw: VMIN bytes minimum semantics — return what's available
            // up to buf.len(). VTIME is a documented simplification: we
            // do not implement the inter-byte timer (no clock at this
            // layer); the tty core's blocking honours VMIN.
            let vmin = self.cc(cc::VMIN) as usize;
            if self.readq.len() < vmin && vmin > 0 {
                return 0;
            }
            let mut n = 0;
            while n < buf.len() {
                match self.readq.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
    }

    fn write<D: TtyDriverHooks>(&mut self, drv: &mut D, buf: &[u8]) -> usize {
        // Hung-up tty: writes are dropped (Linux returns -EIO; the core
        // maps the hung-up state to EIO — here the byte goes nowhere).
        if self.hung_up { return buf.len(); }
        let mut out = alloc::vec::Vec::with_capacity(buf.len() + 8);
        if self.oflag() & oflag::OPOST == 0 {
            out.extend_from_slice(buf);
        } else {
            for &b in buf { self.output_byte(b, &mut out); }
        }
        // IXON: while flow is stopped (^S), withhold the processed bytes
        // in `out_hold`; they flush in order on ^Q (flush_hold). The
        // caller still sees full consumption (Linux blocks the writer; we
        // buffer, then drop past HOLD_CAP).
        if self.stopped {
            for b in out { if self.out_hold.len() < HOLD_CAP { self.out_hold.push_back(b); } }
        } else {
            drv.driver_write(&out);
        }
        buf.len()
    }

    fn poll(&self) -> u32 {
        let mut mask = pollmask::POLLOUT;
        if self.has_input() {
            mask |= pollmask::POLLIN;
        }
        mask
    }

    fn termios(&self) -> [u8; TERMIOS_BYTES] {
        self.termios
    }

    fn set_termios(&mut self, new: &[u8; TERMIOS_BYTES]) {
        self.termios = *new;
        // Switching out of ICANON exposes any half-built line as raw
        // input (Linux flushes the canon buffer into the read queue).
        if !self.is_canon() {
            while let Some(b) = self.canon.pop_front() {
                self.readq.push_back(b);
            }
        }
    }

    /// TCIFLUSH: drop the unfinished canonical line, the completed read
    /// queue, and the pending-EOF marker. Does NOT touch the hung-up latch
    /// or flow state (Linux `tty_buffer_flush` clears only input). # C: O(1)
    fn flush_input(&mut self) {
        self.canon.clear();
        self.readq.clear();
        self.eof_pending = false;
    }

    /// TCOFLUSH: drop IXON-withheld output queued in `out_hold`. # C: O(1)
    fn flush_output(&mut self) {
        self.out_hold.clear();
    }
}
