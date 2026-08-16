// Test support: hex conversion and the simulated devices the transport state
// machines are driven against.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::crb::{CrbError, CrbPhy};
use crate::flags::{
    tpm_access, tpm_data_fifo, tpm_did_vid, tpm_sts, CRB_CTRL_CANCEL, CRB_CTRL_CMD_SIZE,
    CRB_CTRL_REQ, CRB_CTRL_RSP_SIZE, CRB_CTRL_START, CRB_CTRL_STS, CRB_LOC_CTRL,
    CRB_LOC_CTRL_RELINQUISH, CRB_LOC_CTRL_REQUEST_ACCESS, CRB_LOC_STATE,
    CRB_LOC_STATE_LOC_ASSIGNED, CRB_LOC_STATE_TPM_REG_VALID_STS, CRB_START_INVOKE,
    TPM_ACCESS_ACTIVE_LOCALITY, TPM_ACCESS_REQUEST_USE, TPM_ACCESS_VALID, TPM_STS_COMMAND_READY,
    TPM_STS_DATA_AVAIL, TPM_STS_DATA_EXPECT, TPM_STS_GO, TPM_STS_VALID,
};
use crate::tis::{TisError, TisPhy};
use crate::uapi::HEADER_SIZE;

/// Decode a hex string into bytes.
pub fn hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len().is_multiple_of(2), "hex string must have even length");
    (0..b.len() / 2).map(|i| u8::from_str_radix(core::str::from_utf8(&b[2 * i..2 * i + 2]).unwrap(), 16).unwrap()).collect()
}

/// A response buffer with a correct header: tag, total length, response code.
pub fn response(tag: u16, rc: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&((HEADER_SIZE + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&rc.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// One recorded register access.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Access {
    Read(u32),
    Write(u32, u32),
    Fifo(u32, usize),
}

/// A simulated FIFO-interface device.
pub struct FakeTis {
    pub access: [u8; 5],
    pub sts: u8,
    pub burst: u32,
    /// Bytes the driver has written.
    pub rx: Vec<u8>,
    /// Bytes the device will hand back.
    pub tx: VecDeque<u8>,
    /// The response the device produces when started.
    pub canned: Vec<u8>,
    pub log: Vec<Access>,
    /// When set, the locality request is never granted.
    pub deny_locality: bool,
    /// When set, the device never asserts dataExpect.
    pub no_data_expect: bool,
    pub did_vid: u32,
}

impl FakeTis {
    /// A device idling with a canned response ready to serve.
    pub fn new(canned: Vec<u8>) -> Self {
        FakeTis {
            access: [TPM_ACCESS_VALID; 5], sts: TPM_STS_VALID, burst: 64, rx: Vec::new(),
            tx: VecDeque::new(), canned, log: Vec::new(), deny_locality: false,
            no_data_expect: false, did_vid: 0x0000_15D1,
        }
    }

    /// Length the command under construction declares, once enough of its
    /// header has arrived.
    fn declared_len(&self) -> Option<usize> {
        if self.rx.len() < 6 { return None; }
        Some(u32::from_be_bytes([self.rx[2], self.rx[3], self.rx[4], self.rx[5]]) as usize)
    }

    fn after_fifo_write(&mut self) {
        let more = match self.declared_len() { Some(n) => self.rx.len() < n, None => true };
        self.sts = TPM_STS_VALID | if more && !self.no_data_expect { TPM_STS_DATA_EXPECT } else { 0 };
    }

    /// Register writes only, in order.
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.log.iter().filter_map(|a| match a { Access::Write(x, v) => Some((*x, *v)), _ => None }).collect()
    }
}

impl TisPhy for FakeTis {
    fn read8(&mut self, addr: u32) -> Result<u8, TisError> {
        self.log.push(Access::Read(addr));
        for l in 0..5u8 { if addr == tpm_access(l) { return Ok(self.access[l as usize]); } }
        if addr == tpm_sts(0) { return Ok(self.sts); }
        Ok(0)
    }

    fn read32(&mut self, addr: u32) -> Result<u32, TisError> {
        self.log.push(Access::Read(addr));
        if addr == tpm_sts(0) { return Ok((self.burst << 8) | self.sts as u32); }
        if addr == tpm_did_vid(0) { return Ok(self.did_vid); }
        Ok(0)
    }

    fn write8(&mut self, addr: u32, value: u8) -> Result<(), TisError> {
        self.log.push(Access::Write(addr, value as u32));
        for l in 0..5u8 {
            if addr == tpm_access(l) {
                if value & TPM_ACCESS_REQUEST_USE != 0 && !self.deny_locality {
                    self.access[l as usize] = TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY;
                } else if value & TPM_ACCESS_ACTIVE_LOCALITY != 0 {
                    self.access[l as usize] = TPM_ACCESS_VALID;
                }
                return Ok(());
            }
        }
        if addr == tpm_sts(0) {
            if value & TPM_STS_COMMAND_READY != 0 {
                self.sts = TPM_STS_VALID | TPM_STS_COMMAND_READY;
                self.rx.clear();
                self.tx.clear();
            } else if value & TPM_STS_GO != 0 {
                self.tx = self.canned.iter().copied().collect();
                self.sts = TPM_STS_VALID | TPM_STS_DATA_AVAIL;
            }
            return Ok(());
        }
        if addr == tpm_data_fifo(0) {
            self.rx.push(value);
            self.after_fifo_write();
            return Ok(());
        }
        Ok(())
    }

    fn write32(&mut self, addr: u32, value: u32) -> Result<(), TisError> {
        self.log.push(Access::Write(addr, value));
        Ok(())
    }

    fn read_fifo(&mut self, addr: u32, out: &mut [u8]) -> Result<(), TisError> {
        self.log.push(Access::Fifo(addr, out.len()));
        for b in out.iter_mut() { *b = self.tx.pop_front().unwrap_or(0); }
        if self.tx.is_empty() { self.sts = TPM_STS_VALID; }
        Ok(())
    }

    fn write_fifo(&mut self, addr: u32, data: &[u8]) -> Result<(), TisError> {
        self.log.push(Access::Fifo(addr, data.len()));
        self.rx.extend_from_slice(data);
        self.after_fifo_write();
        Ok(())
    }

    fn delay(&mut self) {}
}

/// A simulated control-buffer device.
pub struct FakeCrb {
    pub loc_state: u32,
    pub ctrl_req: u32,
    pub ctrl_sts: u32,
    pub ctrl_start: u32,
    pub ctrl_cancel: u32,
    pub cmd: Vec<u8>,
    pub rsp: Vec<u8>,
    pub cmd_size: u32,
    pub log: Vec<Access>,
    /// When set the device never clears a request bit.
    pub stall_request: bool,
    /// When set the locality is never assigned.
    pub deny_locality: bool,
}

impl FakeCrb {
    /// A device idling with a canned response in its buffer.
    pub fn new(canned: Vec<u8>) -> Self {
        FakeCrb {
            loc_state: CRB_LOC_STATE_TPM_REG_VALID_STS, ctrl_req: 0, ctrl_sts: 0, ctrl_start: 0,
            ctrl_cancel: 0, cmd: vec![0u8; 4096], rsp: canned, cmd_size: 4096, log: Vec::new(),
            stall_request: false, deny_locality: false,
        }
    }

    /// Register writes only, in order.
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.log.iter().filter_map(|a| match a { Access::Write(x, v) => Some((*x, *v)), _ => None }).collect()
    }
}

impl CrbPhy for FakeCrb {
    fn read32(&mut self, addr: u32) -> Result<u32, CrbError> {
        self.log.push(Access::Read(addr));
        Ok(match addr {
            CRB_LOC_STATE => self.loc_state,
            CRB_CTRL_REQ => self.ctrl_req,
            CRB_CTRL_STS => self.ctrl_sts,
            CRB_CTRL_START => self.ctrl_start,
            CRB_CTRL_CANCEL => self.ctrl_cancel,
            CRB_CTRL_CMD_SIZE => self.cmd_size,
            CRB_CTRL_RSP_SIZE => self.rsp.len() as u32,
            _ => 0,
        })
    }

    fn write32(&mut self, addr: u32, value: u32) -> Result<(), CrbError> {
        self.log.push(Access::Write(addr, value));
        match addr {
            CRB_CTRL_REQ => { self.ctrl_req = if self.stall_request { value } else { 0 }; }
            CRB_CTRL_START => {
                self.ctrl_start = value;
                if value & CRB_START_INVOKE != 0 { self.ctrl_start = 0; }
            }
            CRB_CTRL_CANCEL => { self.ctrl_cancel = value; }
            CRB_LOC_CTRL => {
                if value & CRB_LOC_CTRL_REQUEST_ACCESS != 0 && !self.deny_locality {
                    self.loc_state = CRB_LOC_STATE_TPM_REG_VALID_STS | CRB_LOC_STATE_LOC_ASSIGNED;
                } else if value & CRB_LOC_CTRL_RELINQUISH != 0 {
                    self.loc_state = CRB_LOC_STATE_TPM_REG_VALID_STS;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_cmd(&mut self, off: usize, data: &[u8]) -> Result<(), CrbError> {
        self.log.push(Access::Fifo(off as u32, data.len()));
        if off + data.len() > self.cmd.len() { return Err(CrbError::TooBig); }
        self.cmd[off..off + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn read_rsp(&mut self, off: usize, out: &mut [u8]) -> Result<(), CrbError> {
        self.log.push(Access::Fifo(off as u32, out.len()));
        for (i, b) in out.iter_mut().enumerate() { *b = self.rsp.get(off + i).copied().unwrap_or(0); }
        Ok(())
    }

    fn delay(&mut self) {}
}
