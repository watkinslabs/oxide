// `hung_up_tty_fops` — the data path of a description that was open across a
// hangup. The rule and the return values live in `crate::hangup::revoke`;
// this is the tty-side dispatch every driver's `file_operations` calls, so a
// revoked descriptor answers identically on every tty class.

use ::core::sync::atomic::Ordering;

use vfs::VfsError;

use super::super::api::{ReadOutcome, TtyDriver};
use super::TtyStruct;
use crate::hangup::revoke;
use crate::wait::TtyWait;

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
    /// Current hangup generation — the value an open taken right now would
    /// sample. # C: O(1)
    pub fn hup_gen(&self) -> u64 {
        self.hup_gen.load(Ordering::Acquire)
    }

    /// True when the description that sampled `open_gen` was open across a
    /// hangup, and is therefore dead for the rest of its life — the reference's
    /// `tty_hung_up_p(filp)`. # C: O(1)
    pub fn hung_up_open(&self, open_gen: u64) -> bool {
        revoke::revoked(open_gen, self.hup_gen())
    }

    /// Read for one open description. A revoked one reads end-of-file without
    /// touching the line — no job-control gate, no wait, and none of the NEW
    /// session's input. # C: as `read`, O(1) when revoked
    pub fn read_open(&self, open_gen: u64, buf: &mut [u8]) -> ReadOutcome {
        if self.hung_up_open(open_gen) { return ReadOutcome::Bytes(revoke::HUNG_UP_READ); }
        self.read(buf)
    }

    /// Non-blocking read for one open description. Revoked reads EOF (`Ok(0)`),
    /// NOT `EAGAIN`: a dead descriptor is at end of file, not merely empty.
    /// An empty live line is `EAGAIN` as before. # C: O(N) bytes
    pub fn read_nonblock_open(&self, open_gen: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        if self.hung_up_open(open_gen) { return Ok(revoke::HUNG_UP_READ); }
        let n = self.read_nonblock(buf);
        if n == 0 && !buf.is_empty() { return Err(VfsError::Eagain); }
        Ok(n)
    }

    /// Write for one open description — `EIO` once revoked, forever.
    /// # C: as `write`, O(1) when revoked
    pub fn write_open(&self, open_gen: u64, buf: &[u8]) -> Result<usize, VfsError> {
        if self.hung_up_open(open_gen) { return Err(VfsError::Eio); }
        Ok(self.write(buf))
    }

    /// Poll mask for one open description — the full `hung_up_tty_poll` mask
    /// once revoked, so a poll/select/epoll waiter returns POLLHUP immediately
    /// and keeps returning it. # C: O(1)
    pub fn poll_open(&self, open_gen: u64) -> u32 {
        if self.hung_up_open(open_gen) { return revoke::HUNG_UP_POLL; }
        self.poll()
    }

}
