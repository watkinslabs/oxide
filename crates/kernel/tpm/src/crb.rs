// Command-response-buffer interface state machine.
//
// Unlike the FIFO interface there is no byte-at-a-time handshake: the command
// is written into a shared buffer and one register write starts it. What
// replaces the handshake is a pair of request/acknowledge cycles — goIdle and
// cmdReady — in which the driver SETS a bit and the device CLEARS it. A
// driver that writes the bit and proceeds without waiting for the clear has
// started a command against a device still in the wrong power state; the
// order of accesses is again the contract the tests assert.

use crate::flags::{
    CRB_CANCEL_INVOKE, CRB_CTRL_CANCEL, CRB_CTRL_CMD_SIZE, CRB_CTRL_REQ, CRB_CTRL_REQ_CMD_READY,
    CRB_CTRL_REQ_GO_IDLE, CRB_CTRL_RSP_SIZE, CRB_CTRL_START, CRB_CTRL_STS, CRB_CTRL_STS_ERROR,
    CRB_LOC_CTRL, CRB_LOC_CTRL_RELINQUISH, CRB_LOC_CTRL_REQUEST_ACCESS, CRB_LOC_STATE,
    CRB_LOC_STATE_LOC_ASSIGNED, CRB_LOC_STATE_TPM_REG_VALID_STS, CRB_START_INVOKE,
};
use crate::uapi::{HDR_OFF_LEN, HEADER_SIZE};

/// Why a control-buffer transfer failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CrbError {
    /// The underlying access failed.
    Phy,
    /// The device did not acknowledge within the poll budget.
    Timeout,
    /// The device reports an unrecoverable condition.
    DeviceError,
    /// The command is larger than the command buffer, or the response is
    /// larger than the caller's buffer.
    TooBig,
    /// The device declared a response the protocol forbids.
    Protocol(&'static str),
}

/// Register and buffer access for the control-buffer interface.
pub trait CrbPhy {
    /// Read a control-area register. # C: O(1)
    fn read32(&mut self, addr: u32) -> Result<u32, CrbError>;
    /// Write a control-area register. # C: O(1)
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), CrbError>;
    /// Copy `data` into the command buffer at `off`. # C: O(n)
    fn write_cmd(&mut self, off: usize, data: &[u8]) -> Result<(), CrbError>;
    /// Copy from the response buffer at `off` into `out`. # C: O(n)
    fn read_rsp(&mut self, off: usize, out: &mut [u8]) -> Result<(), CrbError>;
    /// Let one poll interval pass. # C: O(1)
    fn delay(&mut self);
}

/// Bytes of a response read before its declared length is known. Reading a
/// whole quadword keeps every later read aligned.
const RSP_PROBE_LEN: usize = 8;

/// A control-buffer interface device.
pub struct Crb<P: CrbPhy> {
    phy: P,
    poll_limit: u32,
    /// Whether this start method implements the idle/ready power states.
    has_idle: bool,
}

impl<P: CrbPhy> Crb<P> {
    /// Attach to a device. `has_idle` is false for start methods that do not
    /// implement the idle state, whose request cycles are no-ops. # C: O(1)
    pub fn new(phy: P, poll_limit: u32, has_idle: bool) -> Self { Crb { phy, poll_limit, has_idle } }

    /// Borrow the phy. # C: O(1)
    pub fn phy(&self) -> &P { &self.phy }

    /// Borrow the phy mutably. # C: O(1)
    pub fn phy_mut(&mut self) -> &mut P { &mut self.phy }

    /// Size of the command buffer the device advertises. # C: O(1)
    pub fn cmd_size(&mut self) -> Result<u32, CrbError> { self.phy.read32(CRB_CTRL_CMD_SIZE) }

    /// Size of the response buffer the device advertises. # C: O(1)
    pub fn rsp_size(&mut self) -> Result<u32, CrbError> { self.phy.read32(CRB_CTRL_RSP_SIZE) }

    fn wait_reg(&mut self, addr: u32, mask: u32, value: u32) -> Result<(), CrbError> {
        for _ in 0..self.poll_limit {
            if self.phy.read32(addr)? & mask == value { return Ok(()); }
            self.phy.delay();
        }
        Err(CrbError::Timeout)
    }

    fn request_cycle(&mut self, bit: u32) -> Result<(), CrbError> {
        if !self.has_idle { return Ok(()); }
        self.phy.write32(CRB_CTRL_REQ, bit)?;
        self.wait_reg(CRB_CTRL_REQ, bit, 0)
    }

    /// Ask the device to enter the idle state and wait for the
    /// acknowledgement. # C: O(poll_limit)
    pub fn go_idle(&mut self) -> Result<(), CrbError> { self.request_cycle(CRB_CTRL_REQ_GO_IDLE) }

    /// Ask the device to leave the idle state and wait for the
    /// acknowledgement. # C: O(poll_limit)
    pub fn cmd_ready(&mut self) -> Result<(), CrbError> { self.request_cycle(CRB_CTRL_REQ_CMD_READY) }

    /// Claim the locality and wait for it to be assigned. # C: O(poll_limit)
    pub fn request_locality(&mut self) -> Result<(), CrbError> {
        let want = CRB_LOC_STATE_LOC_ASSIGNED | CRB_LOC_STATE_TPM_REG_VALID_STS;
        self.phy.write32(CRB_LOC_CTRL, CRB_LOC_CTRL_REQUEST_ACCESS)?;
        self.wait_reg(CRB_LOC_STATE, want, want)
    }

    /// Release the locality and wait for it to be unassigned.
    /// # C: O(poll_limit)
    pub fn relinquish_locality(&mut self) -> Result<(), CrbError> {
        let mask = CRB_LOC_STATE_LOC_ASSIGNED | CRB_LOC_STATE_TPM_REG_VALID_STS;
        self.phy.write32(CRB_LOC_CTRL, CRB_LOC_CTRL_RELINQUISH)?;
        self.wait_reg(CRB_LOC_STATE, mask, CRB_LOC_STATE_TPM_REG_VALID_STS)
    }

    /// Whether the device has finished the command it was started on.
    /// # C: O(1)
    pub fn complete(&mut self) -> Result<bool, CrbError> {
        Ok(self.phy.read32(CRB_CTRL_START)? & CRB_START_INVOKE != CRB_START_INVOKE)
    }

    /// Write a command into the command buffer and start it.
    ///
    /// The cancel register is cleared first: a cancel left standing from the
    /// previous command would abort this one before it ran. # C: O(len)
    pub fn send(&mut self, cmd: &[u8]) -> Result<(), CrbError> {
        if cmd.len() < HEADER_SIZE { return Err(CrbError::TooBig); }
        self.phy.write32(CRB_CTRL_CANCEL, 0)?;
        let cap = self.cmd_size()? as usize;
        if cmd.len() > cap { return Err(CrbError::TooBig); }
        self.phy.write_cmd(0, cmd)?;
        self.phy.write32(CRB_CTRL_START, CRB_START_INVOKE)
    }

    /// Read one response into `out`, returning its length. # C: O(length)
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize, CrbError> {
        if out.len() < HEADER_SIZE { return Err(CrbError::TooBig); }
        if self.phy.read32(CRB_CTRL_STS)? & CRB_CTRL_STS_ERROR != 0 { return Err(CrbError::DeviceError); }
        self.phy.read_rsp(0, &mut out[..RSP_PROBE_LEN])?;
        let declared = u32::from_be_bytes([
            out[HDR_OFF_LEN], out[HDR_OFF_LEN + 1], out[HDR_OFF_LEN + 2], out[HDR_OFF_LEN + 3],
        ]) as usize;
        if declared < HEADER_SIZE { return Err(CrbError::Protocol("response shorter than a header")); }
        if declared > out.len() { return Err(CrbError::TooBig); }
        self.phy.read_rsp(RSP_PROBE_LEN, &mut out[RSP_PROBE_LEN..declared])?;
        Ok(declared)
    }

    /// Abort the running command. # C: O(1)
    pub fn cancel(&mut self) -> Result<(), CrbError> { self.phy.write32(CRB_CTRL_CANCEL, CRB_CANCEL_INVOKE) }

    /// Whether a cancel is outstanding. # C: O(1)
    pub fn canceled(&mut self) -> Result<bool, CrbError> {
        Ok(self.phy.read32(CRB_CTRL_CANCEL)? & CRB_CANCEL_INVOKE == CRB_CANCEL_INVOKE)
    }
}
