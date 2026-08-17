// FIFO interface. These drive the real state machine against a simulated
// register file that records every access IN ORDER, so a handshake step
// performed early, late or not at all is visible as a different log — not
// merely as a different outcome.

use alloc::vec;
use alloc::vec::Vec;

use super::support::{response, Access, FakeTis};
use crate::flags::{tpm_access, tpm_data_fifo, tpm_sts, TPM_ACCESS_ACTIVE_LOCALITY, TPM_ACCESS_REQUEST_USE, TPM_STS_COMMAND_READY, TPM_STS_GO};
use crate::tis::{Tis, TisError};
use crate::uapi::{HEADER_SIZE, TPM2_ST_NO_SESSIONS};

fn canned() -> Vec<u8> { response(TPM2_ST_NO_SESSIONS, 0, &[0xAA; 4]) }

fn cmd() -> Vec<u8> {
    let mut v = vec![0x80, 0x01];
    v.extend_from_slice(&12u32.to_be_bytes());
    v.extend_from_slice(&0x0000_017Bu32.to_be_bytes());
    v.extend_from_slice(&[0x00, 0x14]);
    v
}

#[test]
fn a_command_and_its_response_survive_a_round_trip() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    t.request_locality(0).unwrap();
    t.send(&cmd()).unwrap();
    assert_eq!(t.phy().rx, cmd());
    let mut out = [0u8; 64];
    let n = t.recv(&mut out).unwrap();
    assert_eq!(&out[..n], canned().as_slice());
}

#[test]
fn the_transfer_writes_go_only_after_every_byte_of_the_command() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    t.request_locality(0).unwrap();
    t.send(&cmd()).unwrap();
    let log = &t.phy().log;
    let go = log.iter().position(|a| *a == Access::Write(tpm_sts(0), TPM_STS_GO as u32))
        .expect("the command must be started");
    let last_fifo = log.iter().rposition(|a| matches!(a, Access::Fifo(x, _) if *x == tpm_data_fifo(0))
        || matches!(a, Access::Write(x, _) if *x == tpm_data_fifo(0)))
        .expect("the command must be written");
    assert!(last_fifo < go, "the start write must follow the last data byte");
    // Command-ready is requested before any data is written.
    let ready = log.iter().position(|a| *a == Access::Write(tpm_sts(0), TPM_STS_COMMAND_READY as u32))
        .expect("the device must be put in command-ready");
    let first_fifo = log.iter().position(|a| matches!(a, Access::Fifo(x, _) if *x == tpm_data_fifo(0)))
        .expect("the command must be written");
    assert!(ready < first_fifo, "command-ready must precede the first data byte");
}

#[test]
fn a_one_byte_burst_still_transfers_the_whole_command() {
    let mut f = FakeTis::new(canned());
    f.burst = 1;
    let mut t = Tis::new(f, 64);
    t.request_locality(0).unwrap();
    t.send(&cmd()).unwrap();
    assert_eq!(t.phy().rx, cmd());
    let mut out = [0u8; 64];
    let n = t.recv(&mut out).unwrap();
    assert_eq!(&out[..n], canned().as_slice());
}

#[test]
fn a_device_that_stops_expecting_data_early_fails_the_send() {
    let mut f = FakeTis::new(canned());
    f.no_data_expect = true;
    let mut t = Tis::new(f, 16);
    t.request_locality(0).unwrap();
    assert_eq!(t.send(&cmd()), Err(TisError::Protocol("dataExpect cleared before the last byte")));
    // A failed send leaves the device aborted, not mid-command.
    assert!(t.phy().writes().iter().any(|(a, v)| *a == tpm_sts(0) && *v == TPM_STS_COMMAND_READY as u32));
}

#[test]
fn a_response_larger_than_the_buffer_is_refused_before_it_is_read() {
    let mut big = canned();
    big[2..6].copy_from_slice(&4096u32.to_be_bytes());
    let mut t = Tis::new(FakeTis::new(big), 16);
    t.request_locality(0).unwrap();
    t.send(&cmd()).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(t.recv(&mut out), Err(TisError::TooBig));
}

#[test]
fn a_response_shorter_than_a_header_is_refused() {
    let mut short = canned();
    short[2..6].copy_from_slice(&4u32.to_be_bytes());
    let mut t = Tis::new(FakeTis::new(short), 16);
    t.request_locality(0).unwrap();
    t.send(&cmd()).unwrap();
    let mut out = [0u8; 64];
    assert_eq!(t.recv(&mut out), Err(TisError::TooBig));
    // and a caller buffer too small to hold a header is refused outright
    let mut tiny = [0u8; HEADER_SIZE - 1];
    assert_eq!(t.recv(&mut tiny), Err(TisError::TooBig));
}

#[test]
fn claiming_a_locality_writes_that_localitys_register() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    t.request_locality(2).unwrap();
    assert_eq!(t.locality(), 2);
    assert!(t.phy().writes().contains(&(tpm_access(2), TPM_ACCESS_REQUEST_USE as u32)));
    assert_eq!(tpm_access(2), 0x2000);
    t.relinquish_locality().unwrap();
    assert!(t.phy().writes().contains(&(tpm_access(2), TPM_ACCESS_ACTIVE_LOCALITY as u32)));
}

#[test]
fn an_ungranted_locality_times_out_rather_than_proceeding() {
    let mut f = FakeTis::new(canned());
    f.deny_locality = true;
    let mut t = Tis::new(f, 4);
    assert_eq!(t.request_locality(0), Err(TisError::Timeout));
}

#[test]
fn a_locality_outside_the_interface_is_rejected() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    assert_eq!(t.request_locality(5), Err(TisError::BadLocality(5)));
    assert_eq!(t.wait_startup(9), Err(TisError::BadLocality(9)));
}

#[test]
fn an_already_held_locality_costs_no_write() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    t.request_locality(0).unwrap();
    let before = t.phy().writes().len();
    t.request_locality(0).unwrap();
    assert_eq!(t.phy().writes().len(), before);
}

#[test]
fn identity_registers_are_readable() {
    let mut t = Tis::new(FakeTis::new(canned()), 16);
    assert_eq!(t.did_vid().unwrap(), 0x0000_15D1);
}
