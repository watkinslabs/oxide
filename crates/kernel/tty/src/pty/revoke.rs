use vfs::{KResult, VfsError};

use super::Pair;

impl Pair {
    /// Current generation sampled by a successful slave open. # C: O(1)
    pub fn hup_gen(&self) -> u64 { self.hup_gen }

    /// Retire descriptions opened before the current generation. # C: O(1)
    pub(super) fn retire_opens(&mut self) {
        self.hup_gen = self.hup_gen.wrapping_add(1);
        self.hung_up = true;
    }

    /// Whether a slave description was open across a hangup. # C: O(1)
    pub fn hung_up_open(&self, open_gen: u64) -> bool {
        crate::hangup::revoked(open_gen, self.hup_gen)
    }

    /// Read through one slave description; retired descriptions see EOF.
    /// # C: O(N)
    pub fn slave_read_open(&mut self, open_gen: u64, dst: &mut [u8]) -> usize {
        if self.hung_up_open(open_gen) { return crate::hangup::HUNG_UP_READ; }
        self.slave_read(dst)
    }

    /// Write through one slave description; retired descriptions see EIO.
    /// # C: O(N)
    pub fn slave_write_open(&mut self, open_gen: u64, src: &[u8]) -> KResult<usize> {
        if self.hung_up_open(open_gen) || self.slave_hung_up() { return Err(VfsError::Eio); }
        Ok(self.slave_write(src))
    }

    /// Readiness for one slave description. # C: O(N)
    pub fn slave_poll_open(&self, open_gen: u64) -> u32 {
        if self.hung_up_open(open_gen) { crate::hangup::HUNG_UP_POLL }
        else { self.slave_poll_mask() }
    }
}
