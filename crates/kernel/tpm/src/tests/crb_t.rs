// Control-buffer interface. As with the FIFO tests, the simulated device
// records accesses in order: the request/acknowledge cycles and the
// cancel-then-write-then-start sequence are asserted as ORDER, not just as a
// set of writes that happened.

use alloc::vec;
use alloc::vec::Vec;

use super::support::{response, Access, FakeCrb};
use crate::crb::{Crb, CrbError};
use crate::flags::{
    CRB_CANCEL_INVOKE, CRB_CTRL_CANCEL, CRB_CTRL_REQ, CRB_CTRL_REQ_CMD_READY,
    CRB_CTRL_REQ_GO_IDLE, CRB_CTRL_START, CRB_CTRL_STS_ERROR, CRB_LOC_CTRL,
    CRB_LOC_CTRL_RELINQUISH, CRB_LOC_CTRL_REQUEST_ACCESS, CRB_LOC_STATE_LOC_ASSIGNED,
    CRB_START_INVOKE,
};
use crate::uapi::{HEADER_SIZE, TPM2_ST_NO_SESSIONS};

fn canned() -> Vec<u8> { response(TPM2_ST_NO_SESSIONS, 0, &[0xAA; 6]) }

fn cmd() -> Vec<u8> {
    let mut v = vec![0x80, 0x01];
    v.extend_from_slice(&12u32.to_be_bytes());
    v.extend_from_slice(&0x0000_017Bu32.to_be_bytes());
    v.extend_from_slice(&[0x00, 0x14]);
    v
}

#[test]
fn the_ready_cycle_waits_for_the_device_to_clear_the_request() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    c.cmd_ready().unwrap();
    let log = &c.phy().log;
    let w = log.iter().position(|a| *a == Access::Write(CRB_CTRL_REQ, CRB_CTRL_REQ_CMD_READY)).unwrap();
    let r = log.iter().skip(w).position(|a| *a == Access::Read(CRB_CTRL_REQ));
    assert!(r.is_some(), "the request write must be followed by a read of the acknowledgement");
    c.go_idle().unwrap();
    assert!(c.phy().writes().contains(&(CRB_CTRL_REQ, CRB_CTRL_REQ_GO_IDLE)));
}

#[test]
fn a_device_that_never_acknowledges_times_out() {
    let mut f = FakeCrb::new(canned());
    f.stall_request = true;
    let mut c = Crb::new(f, 4, true);
    assert_eq!(c.cmd_ready(), Err(CrbError::Timeout));
    assert_eq!(c.go_idle(), Err(CrbError::Timeout));
}

#[test]
fn a_start_method_without_idle_performs_no_request_cycle() {
    let mut f = FakeCrb::new(canned());
    f.stall_request = true;
    let mut c = Crb::new(f, 4, false);
    c.cmd_ready().unwrap();
    c.go_idle().unwrap();
    assert!(c.phy().writes().is_empty(), "no request cycle is performed");
}

#[test]
fn send_clears_the_cancel_before_writing_and_starts_last() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    c.send(&cmd()).unwrap();
    let log = &c.phy().log;
    let cancel = log.iter().position(|a| *a == Access::Write(CRB_CTRL_CANCEL, 0)).expect("cancel cleared");
    let write = log.iter().position(|a| matches!(a, Access::Fifo(0, _))).expect("command written");
    let start = log.iter().position(|a| *a == Access::Write(CRB_CTRL_START, CRB_START_INVOKE)).expect("started");
    assert!(cancel < write, "a stale cancel would abort the command being written");
    assert!(write < start, "the command must be in the buffer before it is started");
    assert_eq!(&c.phy().cmd[..cmd().len()], cmd().as_slice());
}

#[test]
fn a_command_larger_than_the_buffer_is_refused() {
    let mut f = FakeCrb::new(canned());
    f.cmd_size = 16;
    let mut c = Crb::new(f, 8, true);
    let big = vec![0u8; 32];
    assert_eq!(c.send(&big), Err(CrbError::TooBig));
    let tiny = vec![0u8; HEADER_SIZE - 1];
    assert_eq!(c.send(&tiny), Err(CrbError::TooBig));
}

#[test]
fn recv_probes_the_length_before_reading_the_body() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    let mut out = [0u8; 64];
    let n = c.recv(&mut out).unwrap();
    assert_eq!(&out[..n], canned().as_slice());
    let fifos: Vec<(u32, usize)> = c.phy().log.iter().filter_map(|a| match a { Access::Fifo(o, l) => Some((*o, *l)), _ => None }).collect();
    assert_eq!(fifos[0], (0, 8), "the length is read from a first quadword");
    assert_eq!(fifos[1], (8, canned().len() - 8));
}

#[test]
fn a_response_the_buffer_cannot_hold_is_refused_before_the_body_is_read() {
    let mut big = canned();
    big[2..6].copy_from_slice(&4096u32.to_be_bytes());
    let mut c = Crb::new(FakeCrb::new(big), 8, true);
    let mut out = [0u8; 32];
    assert_eq!(c.recv(&mut out), Err(CrbError::TooBig));
}

#[test]
fn a_response_shorter_than_a_header_is_refused() {
    let mut short = canned();
    short[2..6].copy_from_slice(&4u32.to_be_bytes());
    let mut c = Crb::new(FakeCrb::new(short), 8, true);
    let mut out = [0u8; 64];
    assert_eq!(c.recv(&mut out), Err(CrbError::Protocol("response shorter than a header")));
}

#[test]
fn an_error_state_is_reported_rather_than_parsed() {
    let mut f = FakeCrb::new(canned());
    f.ctrl_sts = CRB_CTRL_STS_ERROR;
    let mut c = Crb::new(f, 8, true);
    let mut out = [0u8; 64];
    assert_eq!(c.recv(&mut out), Err(CrbError::DeviceError));
}

#[test]
fn locality_is_claimed_and_released_through_loc_ctrl() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    c.request_locality().unwrap();
    assert!(c.phy().writes().contains(&(CRB_LOC_CTRL, CRB_LOC_CTRL_REQUEST_ACCESS)));
    assert!(c.phy().loc_state & CRB_LOC_STATE_LOC_ASSIGNED != 0);
    c.relinquish_locality().unwrap();
    assert!(c.phy().writes().contains(&(CRB_LOC_CTRL, CRB_LOC_CTRL_RELINQUISH)));
    assert!(c.phy().loc_state & CRB_LOC_STATE_LOC_ASSIGNED == 0);
}

#[test]
fn an_unassigned_locality_times_out() {
    let mut f = FakeCrb::new(canned());
    f.deny_locality = true;
    let mut c = Crb::new(f, 4, true);
    assert_eq!(c.request_locality(), Err(CrbError::Timeout));
}

#[test]
fn a_cancel_is_visible_to_the_driver_that_issued_it() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    assert!(!c.canceled().unwrap());
    c.cancel().unwrap();
    assert!(c.canceled().unwrap());
    assert!(c.phy().writes().contains(&(CRB_CTRL_CANCEL, CRB_CANCEL_INVOKE)));
}

#[test]
fn completion_is_read_from_the_start_register() {
    let mut c = Crb::new(FakeCrb::new(canned()), 8, true);
    assert!(c.complete().unwrap());
    c.phy_mut().ctrl_start = CRB_START_INVOKE;
    assert!(!c.complete().unwrap());
}
