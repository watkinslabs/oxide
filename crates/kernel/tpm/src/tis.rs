// FIFO interface state machine.
//
// The interface is a handshake, not a mailbox: every byte written is only
// accepted while the device says it expects more, the burst count bounds how
// many may be written before re-reading status, and the last byte is written
// separately so the device can drop `dataExpect` exactly once. Skipping a
// step usually still "works" against a permissive device and corrupts
// commands against a strict one, so the ORDER of the register accesses is
// itself the contract — and is what the tests assert.
//
// The device is reached through a generic phy so the whole machine runs
// against a simulated register file in hosted tests. No trait object: the
// phy is a type parameter and monomorphises.

use crate::flags::{
    tpm_access, tpm_data_fifo, tpm_did_vid, tpm_rid, tpm_sts, TPM_ACCESS_ACTIVE_LOCALITY,
    TPM_ACCESS_REQUEST_USE, TPM_ACCESS_VALID, TPM_STS_BURST_MASK, TPM_STS_BURST_SHIFT,
    TPM_STS_COMMAND_READY, TPM_STS_DATA_AVAIL, TPM_STS_DATA_EXPECT, TPM_STS_GO,
    TPM_STS_READ_ZERO, TPM_STS_RESPONSE_RETRY, TPM_STS_VALID, TIS_MAX_LOCALITY,
};
use crate::uapi::{HDR_OFF_LEN, HEADER_SIZE};

/// Why a FIFO transfer failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TisError {
    /// The underlying access failed.
    Phy,
    /// The device did not reach the awaited state within the poll budget.
    Timeout,
    /// The device reported a state the protocol forbids at this point.
    Protocol(&'static str),
    /// The device asked to abort.
    Canceled,
    /// The buffer cannot hold what the device declared.
    TooBig,
    /// A locality outside the interface's range was named.
    BadLocality(u8),
}

/// Register access for the FIFO interface.
pub trait TisPhy {
    /// Read a byte-wide register. # C: O(1)
    fn read8(&mut self, addr: u32) -> Result<u8, TisError>;
    /// Read a word-wide register. # C: O(1)
    fn read32(&mut self, addr: u32) -> Result<u32, TisError>;
    /// Write a byte-wide register. # C: O(1)
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisError>;
    /// Write a word-wide register. # C: O(1)
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisError>;
    /// Read `out.len()` bytes from a FIFO register. # C: O(n)
    fn read_fifo(&mut self, addr: u32, out: &mut [u8]) -> Result<(), TisError>;
    /// Write `data` to a FIFO register. # C: O(n)
    fn write_fifo(&mut self, addr: u32, data: &[u8]) -> Result<(), TisError>;
    /// Let one poll interval pass. # C: O(1)
    fn delay(&mut self);
}

/// A FIFO-interface device.
pub struct Tis<P: TisPhy> {
    phy: P,
    locality: u8,
    /// Poll iterations a wait may take before it is a timeout. Time is the
    /// caller's unit; the machine only counts intervals.
    poll_limit: u32,
}

impl<P: TisPhy> Tis<P> {
    /// Attach to a device, initially owning no locality. # C: O(1)
    pub fn new(phy: P, poll_limit: u32) -> Self { Tis { phy, locality: 0, poll_limit } }

    /// Locality the machine currently drives. # C: O(1)
    pub fn locality(&self) -> u8 { self.locality }

    /// Borrow the phy. # C: O(1)
    pub fn phy(&self) -> &P { &self.phy }

    /// Borrow the phy mutably. # C: O(1)
    pub fn phy_mut(&mut self) -> &mut P { &mut self.phy }

    /// Vendor and device identifier. # C: O(1)
    pub fn did_vid(&mut self) -> Result<u32, TisError> { self.phy.read32(tpm_did_vid(self.locality)) }

    /// Revision identifier. # C: O(1)
    pub fn rid(&mut self) -> Result<u8, TisError> { self.phy.read8(tpm_rid(self.locality)) }

    /// Wait for the device to declare its registers valid after reset.
    /// # C: O(poll_limit)
    pub fn wait_startup(&mut self, loc: u8) -> Result<(), TisError> {
        Self::check_loc(loc)?;
        for _ in 0..self.poll_limit {
            if self.phy.read8(tpm_access(loc))? & TPM_ACCESS_VALID != 0 { return Ok(()); }
            self.phy.delay();
        }
        Err(TisError::Timeout)
    }

    fn check_loc(loc: u8) -> Result<(), TisError> {
        if loc > TIS_MAX_LOCALITY { return Err(TisError::BadLocality(loc)); }
        Ok(())
    }

    /// Whether `loc` is currently active and valid, with no request of its
    /// own still outstanding. # C: O(1)
    pub fn check_locality(&mut self, loc: u8) -> Result<bool, TisError> {
        Self::check_loc(loc)?;
        let a = self.phy.read8(tpm_access(loc))?;
        let want = TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID;
        Ok(a & (want | TPM_ACCESS_REQUEST_USE) == want)
    }

    /// Claim `loc`. Already owning it is success and costs no write.
    /// # C: O(poll_limit)
    pub fn request_locality(&mut self, loc: u8) -> Result<(), TisError> {
        Self::check_loc(loc)?;
        if self.check_locality(loc)? { self.locality = loc; return Ok(()); }
        self.phy.write8(tpm_access(loc), TPM_ACCESS_REQUEST_USE)?;
        for _ in 0..self.poll_limit {
            if self.check_locality(loc)? { self.locality = loc; return Ok(()); }
            self.phy.delay();
        }
        Err(TisError::Timeout)
    }

    /// Release the locality currently held. # C: O(1)
    pub fn relinquish_locality(&mut self) -> Result<(), TisError> {
        self.phy.write8(tpm_access(self.locality), TPM_ACCESS_ACTIVE_LOCALITY)
    }

    /// Status of the active locality. Bits that must read as zero reading
    /// non-zero means the read is not valid — reported as an all-clear status
    /// so no caller acts on it. # C: O(1)
    pub fn status(&mut self) -> Result<u8, TisError> {
        let s = self.phy.read8(tpm_sts(self.locality))?;
        if s & TPM_STS_READ_ZERO != 0 { return Ok(0); }
        Ok(s)
    }

    /// Abort whatever the device is doing and return it to command-ready.
    /// # C: O(1)
    pub fn ready(&mut self) -> Result<(), TisError> {
        self.phy.write8(tpm_sts(self.locality), TPM_STS_COMMAND_READY)
    }

    /// Bytes the device will accept or supply before status must be re-read.
    /// # C: O(poll_limit)
    pub fn burst_count(&mut self) -> Result<u16, TisError> {
        for _ in 0..self.poll_limit {
            let v = self.phy.read32(tpm_sts(self.locality))?;
            let burst = (v >> TPM_STS_BURST_SHIFT) & TPM_STS_BURST_MASK;
            if burst != 0 { return Ok(burst as u16); }
            self.phy.delay();
        }
        Err(TisError::Timeout)
    }

    fn wait_for(&mut self, mask: u8) -> Result<(), TisError> {
        for _ in 0..self.poll_limit {
            if self.status()? & mask == mask { return Ok(()); }
            self.phy.delay();
        }
        Err(TisError::Timeout)
    }

    /// Write a whole command into the FIFO and start it.
    ///
    /// The final byte is written on its own: until it lands the device must
    /// report `dataExpect`, and once it lands the device must clear it. Both
    /// halves are checked, because a device that never clears `dataExpect`
    /// has taken a command of a different length than the one sent.
    /// # C: O(len)
    pub fn send(&mut self, cmd: &[u8]) -> Result<(), TisError> {
        if cmd.len() < HEADER_SIZE { return Err(TisError::TooBig); }
        match self.send_data(cmd) {
            Ok(()) => {}
            Err(e) => { let _ = self.ready(); return Err(e); }
        }
        if let Err(e) = self.phy.write8(tpm_sts(self.locality), TPM_STS_GO) {
            let _ = self.ready();
            return Err(e);
        }
        Ok(())
    }

    fn send_data(&mut self, cmd: &[u8]) -> Result<(), TisError> {
        if self.status()? & TPM_STS_COMMAND_READY == 0 {
            self.ready()?;
            self.wait_for(TPM_STS_COMMAND_READY)?;
        }
        let last = cmd.len() - 1;
        let mut count = 0usize;
        while count < last {
            let burst = self.burst_count()? as usize;
            let n = core::cmp::min(burst, last - count);
            self.phy.write_fifo(tpm_data_fifo(self.locality), &cmd[count..count + n])?;
            count += n;
            self.wait_for(TPM_STS_VALID)?;
            if self.status()? & TPM_STS_DATA_EXPECT == 0 {
                return Err(TisError::Protocol("dataExpect cleared before the last byte"));
            }
        }
        self.phy.write8(tpm_data_fifo(self.locality), cmd[last])?;
        self.wait_for(TPM_STS_VALID)?;
        if self.status()? & TPM_STS_DATA_EXPECT != 0 {
            return Err(TisError::Protocol("dataExpect set after the last byte"));
        }
        Ok(())
    }

    fn recv_bytes(&mut self, out: &mut [u8]) -> Result<(), TisError> {
        let mut got = 0usize;
        while got < out.len() {
            self.wait_for(TPM_STS_DATA_AVAIL | TPM_STS_VALID)?;
            let burst = self.burst_count()? as usize;
            let n = core::cmp::min(burst, out.len() - got);
            self.phy.read_fifo(tpm_data_fifo(self.locality), &mut out[got..got + n])?;
            got += n;
        }
        Ok(())
    }

    /// Read one response into `out`, returning its length.
    ///
    /// The declared length is bounded by the caller's buffer before a single
    /// further byte is read; a device that declares more than fits gets no
    /// chance to write past the end. # C: O(response length)
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize, TisError> {
        if out.len() < HEADER_SIZE { return Err(TisError::TooBig); }
        let r = self.try_recv(out);
        let _ = self.ready();
        r
    }

    fn try_recv(&mut self, out: &mut [u8]) -> Result<usize, TisError> {
        self.recv_bytes(&mut out[..HEADER_SIZE])?;
        let declared = u32::from_be_bytes([
            out[HDR_OFF_LEN], out[HDR_OFF_LEN + 1], out[HDR_OFF_LEN + 2], out[HDR_OFF_LEN + 3],
        ]) as usize;
        if declared < HEADER_SIZE || declared > out.len() { return Err(TisError::TooBig); }
        self.recv_bytes(&mut out[HEADER_SIZE..declared])?;
        self.wait_for(TPM_STS_VALID)?;
        if self.status()? & TPM_STS_DATA_AVAIL != 0 {
            return Err(TisError::Protocol("data still available after the response"));
        }
        Ok(declared)
    }

    /// Ask the device to present the previous response again. # C: O(1)
    pub fn response_retry(&mut self) -> Result<(), TisError> {
        self.phy.write8(tpm_sts(self.locality), TPM_STS_RESPONSE_RETRY)
    }
}
