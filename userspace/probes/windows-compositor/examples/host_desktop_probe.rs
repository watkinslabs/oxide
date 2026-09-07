//! Host-side driver: speaks the kernel's exact frames to a real bridge process
//! on the host X display, so a desktop mapping defect reproduces without a boot.
//!
//! Sends what the acceptance run sends -- monitor handshake, a top-level
//! Notepad window, its title, a frame, a show, then the child edit control --
//! and prints every event the bridge returns. Needs a display; run it as
//! `DISPLAY=:N cargo run --release --example host_desktop_probe -- <bridge> [seconds]`,
//! against any X server (a bare Xvfb answers the coordinate-space questions;
//! a window manager on it answers the reparenting ones).

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use syscall::nt_compositor::{self as wire, Opcode, Record};

fn send(s: &mut UnixStream, opcode: Opcode, seq: u64, hwnd: u64, payload: Vec<u8>) {
    s.write_all(&Record::new(opcode, seq, hwnd, payload).unwrap().encode().unwrap()).unwrap();
}

fn main() {
    let bin = std::env::args().nth(1).expect("usage: host_desktop_probe <bridge-binary> [seconds]");
    let secs: u64 = std::env::args().nth(2).map_or(6, |v| v.parse().unwrap());
    let (mut peer, bridge) = UnixStream::pair().unwrap();
    let bridge_fd = bridge.as_raw_fd();
    let mut child = unsafe {
        Command::new(&bin).args(["--fd", "0"]).stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
            .pre_exec(move || { if libc::dup2(bridge_fd, 0) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) })
            .spawn().unwrap()
    };
    drop(bridge);
    peer.set_read_timeout(Some(Duration::from_millis(200))).unwrap();

    const W: u32 = 0x2d9; const H: u32 = 0x222;
    let mut create = wire::Rect { x: 0, y: 0, width: W, height: H }.encode_window().unwrap().to_vec();
    create.extend_from_slice(&0u64.to_le_bytes());
    create.extend_from_slice(&0x14cf_0000u32.to_le_bytes()); // WS_OVERLAPPEDWINDOW | WS_VISIBLE
    create.extend_from_slice(&0u32.to_le_bytes());
    send(&mut peer, Opcode::Create, 1, 1, create);
    send(&mut peer, Opcode::Title, 2, 1, b"Untitled - Notepad".to_vec());
    let mut frame = Vec::new();
    frame.extend_from_slice(&W.to_le_bytes()); frame.extend_from_slice(&H.to_le_bytes());
    frame.extend_from_slice(&(W * 4).to_le_bytes()); frame.extend_from_slice(&wire::PIXEL_BGRA8888.to_le_bytes());
    for _ in 0..(W * H) { frame.extend_from_slice(&0x00ff_ffffu32.to_le_bytes()); }
    send(&mut peer, Opcode::Frame, 3, 1, frame);
    send(&mut peer, Opcode::Visibility, 4, 1, 1u32.to_le_bytes().to_vec());
    // The edit control: a WS_CHILD whose canonical rect is parent-relative.
    let mut kid = wire::Rect { x: 0, y: 0, width: W, height: H }.encode_window().unwrap().to_vec();
    kid.extend_from_slice(&1u64.to_le_bytes());
    kid.extend_from_slice(&0x5000_0000u32.to_le_bytes()); // WS_CHILD | WS_VISIBLE
    kid.extend_from_slice(&0u32.to_le_bytes());
    send(&mut peer, Opcode::Create, 5, 2, kid);
    send(&mut peer, Opcode::Visibility, 6, 2, 1u32.to_le_bytes().to_vec());
    // Move the top level away from the origin: a child's root position then
    // differs from the parent-relative one its ConfigureNotify reports.
    send(&mut peer, Opcode::Geometry, 7, 1, wire::Rect { x: 200, y: 150, width: W, height: H }.encode_window().unwrap().to_vec());
    send(&mut peer, Opcode::Geometry, 8, 2, wire::Rect { x: 0, y: 0, width: W - 8, height: H - 8 }.encode_window().unwrap().to_vec());

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut rx: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 65536];
    while Instant::now() < deadline {
        match peer.read(&mut scratch) { Ok(0) => { println!("PROBE: transport EOF"); break; } Ok(n) => rx.extend_from_slice(&scratch[..n]), Err(_) => {} }
        while rx.len() >= wire::HEADER_LEN {
            let Ok(header) = wire::Header::decode(&rx[..wire::HEADER_LEN]) else { println!("PROBE: undecodable header"); return; };
            let total = wire::HEADER_LEN + header.length as usize;
            if rx.len() < total { break; }
            let payload: Vec<u8> = rx.drain(..total).collect::<Vec<_>>()[wire::HEADER_LEN..].to_vec();
            match header.opcode {
                Opcode::Configure => { let r = wire::Rect::decode_window(&payload).unwrap(); println!("PROBE: Configure hwnd={} x={} y={} w={} h={}", header.hwnd, r.x, r.y, r.width, r.height); }
                other => println!("PROBE: {other:?} hwnd={} len={} {:x?}", header.hwnd, payload.len(), &payload[..payload.len().min(24)]),
            }
        }
    }
    println!("PROBE: done, killing bridge");
    let _ = child.kill(); let _ = child.wait();
}
