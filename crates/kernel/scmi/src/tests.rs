use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::VecDeque;
use std::sync::Mutex;

use super::*;

struct Call { command: u8, tx: Vec<u8>, response: Result<Vec<u8>> }
struct Mock { calls: Mutex<VecDeque<Call>> }

impl Mock {
    fn new(calls: Vec<Call>) -> Arc<Self> { Arc::new(Self { calls: Mutex::new(calls.into()) }) }
}

impl Transport for Mock {
    fn call(&self, protocol: u8, command: u8, tx: &[u8], rx: &mut [u8]) -> Result<usize> {
        assert_eq!(protocol, 0x13);
        let call = self.calls.lock().expect("mock lock").pop_front().expect("unexpected SCMI call");
        assert_eq!(command, call.command);
        assert_eq!(tx, call.tx);
        let response = call.response?;
        rx[..response.len()].copy_from_slice(&response);
        Ok(response.len())
    }
}

fn call(command: u8, tx: &[u8], response: &[u8]) -> Call {
    Call { command, tx: tx.into(), response: Ok(response.into()) }
}

fn open_calls(version: u32) -> Vec<Call> {
    let mut attributes = [0u8; 16];
    attributes[..2].copy_from_slice(&8u16.to_le_bytes());
    alloc::vec![call(0, &[], &version.to_le_bytes()), call(1, &[], &attributes)]
}

fn domain_attributes(flags: u32, rate_limit: u32, sustained_khz: u32, sustained_level: u32) -> Vec<u8> {
    let mut response = [0u8; 32];
    response[..4].copy_from_slice(&flags.to_le_bytes());
    response[4..8].copy_from_slice(&rate_limit.to_le_bytes());
    response[8..12].copy_from_slice(&sustained_khz.to_le_bytes());
    response[12..16].copy_from_slice(&sustained_level.to_le_bytes());
    response.into()
}

fn v3_levels(levels: &[(u32, u16)]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&(levels.len() as u16).to_le_bytes());
    response.extend_from_slice(&0u16.to_le_bytes());
    for (performance, latency) in levels {
        response.extend_from_slice(&performance.to_le_bytes());
        response.extend_from_slice(&0u32.to_le_bytes());
        response.extend_from_slice(&latency.to_le_bytes());
        response.extend_from_slice(&0u16.to_le_bytes());
    }
    response
}

#[test]
fn v3_domain_translates_performance_levels_to_hertz_and_programs_its_index() {
    let mut calls = open_calls(0x0003_0000);
    calls.push(call(3, &7u32.to_le_bytes(), &domain_attributes(1 << 30, 12, 1_500_000, 1_500)));
    calls.push(call(4, &[7, 0, 0, 0, 0, 0, 0, 0], &v3_levels(&[(1_000, 4), (2_000, 7)])));
    calls.push(call(8, &7u32.to_le_bytes(), &2_000u32.to_le_bytes()));
    calls.push(call(7, &[7, 0, 0, 0, 232, 3, 0, 0], &[]));
    let performance = Performance::open(Mock::new(calls)).expect("open");
    let domain = performance.domain(7).expect("domain");
    assert_eq!(domain.rate_limit_us, 12);
    assert_eq!(domain.transition_latency_ns, 7_000);
    assert_eq!(domain.opps[0].frequency_hz, 1_000_000_000);
    assert!(domain.opps[1].turbo);
    assert_eq!(performance.frequency_hz(&domain), Ok(2_000_000_000));
    assert_eq!(performance.set_index(&domain, 0), Ok(()));
}

#[test]
fn v4_indexed_levels_use_indicative_frequency_and_opaque_wire_indices() {
    let mut calls = open_calls(0x0004_0000);
    calls.push(call(3, &0u32.to_le_bytes(), &domain_attributes((1 << 30) | (1 << 25), 0, 1_500_000, 0)));
    let mut response = Vec::new();
    response.extend_from_slice(&2u16.to_le_bytes());
    response.extend_from_slice(&0u16.to_le_bytes());
    for (performance, frequency, wire) in [(3u32, 1_200_000u32, 41u32), (5, 1_800_000, 99)] {
        response.extend_from_slice(&performance.to_le_bytes());
        response.extend_from_slice(&0u32.to_le_bytes());
        response.extend_from_slice(&2u16.to_le_bytes());
        response.extend_from_slice(&0u16.to_le_bytes());
        response.extend_from_slice(&frequency.to_le_bytes());
        response.extend_from_slice(&wire.to_le_bytes());
    }
    calls.push(call(4, &[0; 8], &response));
    calls.push(call(8, &0u32.to_le_bytes(), &99u32.to_le_bytes()));
    calls.push(call(7, &[0, 0, 0, 0, 99, 0, 0, 0], &[]));
    let performance = Performance::open(Mock::new(calls)).expect("open");
    let domain = performance.domain(0).expect("domain");
    assert_eq!(domain.opps[0].frequency_hz, 1_200_000_000);
    assert_eq!(domain.opps[1].wire_level, 99);
    assert_eq!(performance.frequency_hz(&domain), Ok(1_800_000_000));
    assert_eq!(performance.set_index(&domain, 1), Ok(()));
}

#[test]
fn a_newer_protocol_is_negotiated_down_to_the_supported_v4_layout() {
    let mut attributes = [0u8; 16];
    attributes[..2].copy_from_slice(&1u16.to_le_bytes());
    let transport = Mock::new(alloc::vec![
        call(0, &[], &0x0005_0000u32.to_le_bytes()),
        call(0x10, &0x0004_0000u32.to_le_bytes(), &[]),
        call(1, &[], &attributes),
    ]);
    let performance = Performance::open(transport).expect("open");
    assert_eq!(performance.version(), 0x0004_0000);
}
