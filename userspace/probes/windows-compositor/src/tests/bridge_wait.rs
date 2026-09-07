//! The real bridge blocks on the real descriptors, against a private Xvfb.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use syscall::nt_compositor::{self as wire, Opcode, Record};

use crate::{Backend, StreamTransport};

struct Xvfb { child: Child, display: String }
impl Drop for Xvfb { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }

fn xvfb() -> Xvfb {
    let mut child = Command::new("Xvfb").args(["-displayfd", "1", "-screen", "0", "320x240x24", "-nolisten", "tcp"])
        .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb is required for the bridge wait test");
    let mut line = String::new(); BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    Xvfb { child, display: format!(":{}", line.trim()) }
}

fn create(hwnd: u64, sequence: u64) -> Vec<u8> {
    let mut payload = wire::Rect { x: 0, y: 0, width: 32, height: 32 }.encode().unwrap().to_vec();
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    Record::new(Opcode::Create, sequence, hwnd, payload).unwrap().encode().unwrap()
}

/// Both descriptors are the ones the loop must wait on: a burst written
/// before the loop starts and a record written after it has gone idle both
/// have to come back acknowledged. A wrong descriptor does not fail an
/// assertion, it never wakes, so the test would hang rather than pass.
#[test]
fn the_bridge_drains_a_burst_and_wakes_for_a_record_that_arrives_while_idle() {
    const BURST: u64 = 32;
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    backend.seed_test_ewmh();
    let (peer, bridge) = UnixStream::pair().unwrap();
    let mut transport = StreamTransport::from_stream(bridge).unwrap();
    let writer = std::thread::spawn(move || {
        let mut peer = peer;
        let mut burst = Vec::new();
        for index in 0..BURST { burst.extend_from_slice(&create(0x100 + index, index + 1)); }
        peer.write_all(&burst).unwrap();
        // Long enough that the loop is certainly idle and blocked when this
        // last record arrives.
        std::thread::sleep(Duration::from_millis(50));
        peer.write_all(&create(0x200, BURST + 1)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        peer.shutdown(Shutdown::Write).unwrap();
        peer
    });
    let error = crate::bridge::run(&mut backend, &mut transport);
    let mut peer = writer.join().unwrap();
    assert!(matches!(error, crate::BackendError::Transport(crate::TransportError::Disconnected)), "{error:?}");
    peer.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut acked = Vec::new();
    loop {
        let mut header = [0u8; wire::HEADER_LEN];
        if peer.read_exact(&mut header).is_err() { break; }
        let header = wire::Header::decode(&header).unwrap();
        let mut payload = vec![0u8; header.length as usize];
        peer.read_exact(&mut payload).unwrap();
        if header.opcode == Opcode::Ack { assert_eq!(wire::u32_at(&payload, 0).unwrap(), 0); acked.push(header.sequence); }
    }
    assert_eq!(acked, (1..=BURST + 1).collect::<Vec<u64>>());
}
