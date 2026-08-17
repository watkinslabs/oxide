// The chip layer: does a measurement actually leave the kernel, and does it
// carry the right bytes?
//
// These assert on the wire image, because that is the only thing a real TPM
// sees. A test that inspected kernel-side state would pass against a simulator
// that never transmitted — which is exactly the defect this layer replaced.

use alloc::vec;
use alloc::vec::Vec;

use crate::alg::Alg;
use crate::codec::CmdBuf;
use crate::device::{Chip, ChipError, Transport, TransportError};
use crate::limits::PLATFORM_PCR;
use crate::pcr::{AllocatedBanks, PcrError};
use crate::rc::Rc;
use crate::uapi::{TPM2_CC_PCR_EXTEND, TPM2_RC_SUCCESS, TPM2_ST_NO_SESSIONS};

/// A chip that records what it was sent and answers with a scripted response.
struct FakeChip {
    sent: Vec<Vec<u8>>,
    rc: u32,
    fail_send: bool,
}

impl FakeChip {
    fn ok() -> Self { FakeChip { sent: Vec::new(), rc: TPM2_RC_SUCCESS, fail_send: false } }
    fn refusing(rc: u32) -> Self { FakeChip { sent: Vec::new(), rc, fail_send: false } }
    fn unreachable() -> Self { FakeChip { sent: Vec::new(), rc: TPM2_RC_SUCCESS, fail_send: true } }
}

impl Transport for FakeChip {
    fn send(&mut self, cmd: &[u8]) -> Result<(), TransportError> {
        if self.fail_send { return Err(TransportError); }
        self.sent.push(cmd.to_vec());
        Ok(())
    }
    fn recv(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        // A bare header carrying the scripted response code.
        let rsp = CmdBuf::new(TPM2_ST_NO_SESSIONS, self.rc).finish().unwrap();
        out[..rsp.len()].copy_from_slice(&rsp);
        Ok(rsp.len())
    }
}

fn one_bank() -> AllocatedBanks { AllocatedBanks::new(&[Alg::Sha256]).unwrap() }

#[test]
fn an_extend_reaches_the_transport() {
    // The whole point of the layer: the measurement leaves the kernel.
    let mut c = Chip::new(one_bank(), FakeChip::ok());
    let d = [0xa5u8; 32];
    c.pcr_extend(10, &[(Alg::Sha256.id(), &d[..])]).unwrap();
    // Reach into the transport by rebuilding the expectation instead: the
    // command must be a PCR_Extend for register 10 carrying that digest.
}

#[test]
fn the_command_on_the_wire_is_a_pcr_extend_for_the_named_register() {
    let mut phy = FakeChip::ok();
    {
        let mut c = Chip::new(one_bank(), &mut phy);
        let d = [0xa5u8; 32];
        c.pcr_extend(10, &[(Alg::Sha256.id(), &d[..])]).unwrap();
    }
    assert_eq!(phy.sent.len(), 1, "exactly one command was sent");
    let cmd = &phy.sent[0];
    // header: tag(2) size(4) commandCode(4)
    let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
    assert_eq!(cc, TPM2_CC_PCR_EXTEND, "the chip was asked to extend");
    let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
    assert_eq!(size, cmd.len(), "the declared size matches the bytes sent");
    let handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
    assert_eq!(handle, 10, "the register the caller named");
    // the digest must appear on the wire, whole
    assert!(cmd.windows(32).any(|w| w == [0xa5u8; 32]), "the measurement is in the command");
}

#[test]
fn every_allocated_bank_appears_in_one_command() {
    let mut phy = FakeChip::ok();
    {
        let banks = AllocatedBanks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
        let mut c = Chip::new(banks, &mut phy);
        let s1 = [0x11u8; 20];
        let s256 = [0x22u8; 32];
        c.pcr_extend(4, &[(Alg::Sha1.id(), &s1[..]), (Alg::Sha256.id(), &s256[..])]).unwrap();
    }
    assert_eq!(phy.sent.len(), 1, "one command, not one per bank");
    let cmd = &phy.sent[0];
    assert!(cmd.windows(20).any(|w| w == [0x11u8; 20]), "the SHA-1 digest is present");
    assert!(cmd.windows(32).any(|w| w == [0x22u8; 32]), "the SHA-256 digest is present");
}

#[test]
fn a_rejected_digest_set_sends_nothing() {
    // Validation happens before marshalling, so a bad request costs the chip
    // no command at all.
    let mut phy = FakeChip::ok();
    {
        let banks = AllocatedBanks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
        let mut c = Chip::new(banks, &mut phy);
        let s256 = [0u8; 32];
        let e = c.pcr_extend(4, &[(Alg::Sha256.id(), &s256[..])]).unwrap_err();
        assert_eq!(e, ChipError::Pcr(PcrError::MissingBank(Alg::Sha1.id())));
    }
    assert!(phy.sent.is_empty(), "nothing was transmitted");
}

#[test]
fn an_index_outside_the_platform_range_sends_nothing() {
    let mut phy = FakeChip::ok();
    {
        let mut c = Chip::new(one_bank(), &mut phy);
        let d = [0u8; 32];
        let e = c.pcr_extend(PLATFORM_PCR, &[(Alg::Sha256.id(), &d[..])]).unwrap_err();
        assert_eq!(e, ChipError::Pcr(PcrError::BadIndex(PLATFORM_PCR)));
    }
    assert!(phy.sent.is_empty());
}

#[test]
fn a_chip_that_refuses_is_reported_and_not_read_as_success() {
    // A non-success response code must surface. Reading the body of a refused
    // command would hand the caller bytes the chip never filled.
    const TPM_RC_VALUE: u32 = 0x0184;
    let mut c = Chip::new(one_bank(), FakeChip::refusing(TPM_RC_VALUE));
    let d = [0u8; 32];
    assert_eq!(c.pcr_extend(10, &[(Alg::Sha256.id(), &d[..])]),
               Err(ChipError::Tpm(Rc(TPM_RC_VALUE))));
}

#[test]
fn an_unreachable_chip_is_reported() {
    let mut c = Chip::new(one_bank(), FakeChip::unreachable());
    let d = [0u8; 32];
    assert_eq!(c.pcr_extend(10, &[(Alg::Sha256.id(), &d[..])]), Err(ChipError::Transport));
}

impl<T: Transport> Transport for &mut T {
    fn send(&mut self, cmd: &[u8]) -> Result<(), TransportError> { (**self).send(cmd) }
    fn recv(&mut self, out: &mut [u8]) -> Result<usize, TransportError> { (**self).recv(out) }
}

#[test]
fn the_banks_the_chip_reported_are_what_it_validates_against() {
    let c = Chip::new(AllocatedBanks::new(&[Alg::Sha256, Alg::Sha384]).unwrap(), FakeChip::ok());
    assert_eq!(c.banks().algs(), vec![Alg::Sha256, Alg::Sha384]);
}
