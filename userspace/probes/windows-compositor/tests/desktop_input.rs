//! Real desktop input: a window manager, a compositor and injected pointer and
//! key events, against the bridge that the guest runs.
//!
//! The bridge's own unit tests decode synthetic X event bytes, so every one of
//! them passes on a bridge that never receives an X event at all. Three
//! acceptance runs reported no input reaching the kernel with nothing able to
//! say which layer dropped it. This drives the whole path: a nested Wayland
//! compositor with its own XWayland (the guest's stack), the bridge binary as
//! its own process, and XTEST input from outside it. It skips, loudly, where the desktop
//! tools are absent.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use syscall::nt_compositor::{self as wire, Opcode, Record};
use windows_compositor::MK_LBUTTON;

const EDGE: u32 = 400;
const READY: Duration = Duration::from_secs(20);

struct Session { xvfb: Child, wm: Option<Child>, display: String, runtime: std::path::PathBuf }
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(wm) = self.wm.as_mut() { let _ = wm.kill(); let _ = wm.wait(); }
        let _ = self.xvfb.kill(); let _ = self.xvfb.wait();
        let _ = std::fs::remove_dir_all(&self.runtime);
    }
}

fn have(tool: &str) -> bool { Command::new("sh").arg("-c").arg(format!("command -v {tool}")).stdout(Stdio::null()).status().is_ok_and(|s| s.success()) }

/// A private X server with a reparenting window manager on it.
fn desktop() -> Option<Session> {
    for tool in ["Xvfb", "mutter", "xdotool"] { if !have(tool) { eprintln!("desktop-input: skipped, {tool} is not installed"); return None; } }
    let runtime = std::env::temp_dir().join(format!("oxide-bridge-input-{}", std::process::id()));
    std::fs::create_dir_all(&runtime).ok()?;
    let mut xvfb = Command::new("Xvfb").args(["-displayfd", "1", "-screen", "0", "1280x1024x24", "-nolisten", "tcp"])
        .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut line = String::new();
    BufReader::new(xvfb.stdout.take()?).read_line(&mut line).ok()?;
    let display = format!(":{}", line.trim());
    let wm = match Command::new("mutter").arg("--x11")
        .env("DISPLAY", &display).env("XDG_RUNTIME_DIR", &runtime).env_remove("WAYLAND_DISPLAY")
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Ok(child) => child,
        Err(_) => { eprintln!("desktop-input: skipped, no window manager starts here"); let _ = xvfb.kill(); return None; }
    };
    // A window manager that has not claimed the screen yet neither reparents
    // nor focuses, and input aimed at an unmanaged window proves nothing.
    let session = Session { xvfb, wm: Some(wm), display, runtime };
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if xdotool_output(&session, &["getdisplaygeometry"]).is_some_and(|v| v.starts_with("1280")) { return Some(session); }
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("desktop-input: skipped, the display never came up");
    None
}

/// Standard output of an xdotool command that succeeded, on this session's display.
fn xdotool_output(session: &Session, args: &[&str]) -> Option<String> {
    let out = Command::new("xdotool").args(args).env("DISPLAY", &session.display).env_remove("XAUTHORITY")
        .env("XDG_RUNTIME_DIR", &session.runtime).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn xdotool(session: &Session, args: &[&str]) {
    assert!(xdotool_output(session, args).is_some(), "xdotool {args:?} failed against the test desktop");
}

fn send(peer: &mut UnixStream, opcode: Opcode, seq: u64, hwnd: u64, payload: Vec<u8>) {
    peer.write_all(&Record::new(opcode, seq, hwnd, payload).unwrap().encode().unwrap()).unwrap();
}

fn window_payload(width: u32, height: u32, parent: u64, style: u32) -> Vec<u8> {
    let mut payload = wire::Rect { x: 0, y: 0, width, height }.encode_window().unwrap().to_vec();
    payload.extend_from_slice(&parent.to_le_bytes());
    payload.extend_from_slice(&style.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload
}

/// Every record the bridge has produced so far, drained without blocking.
fn drain(peer: &mut UnixStream, rx: &mut Vec<u8>, records: &mut Vec<(Opcode, u64, Vec<u8>)>) {
    let mut scratch = [0u8; 65536];
    while let Ok(n) = peer.read(&mut scratch) { if n == 0 { break; } rx.extend_from_slice(&scratch[..n]); }
    while rx.len() >= wire::HEADER_LEN {
        let Ok(header) = wire::Header::decode(&rx[..wire::HEADER_LEN]) else { rx.clear(); return; };
        let total = wire::HEADER_LEN + header.length as usize;
        if rx.len() < total { return; }
        let bytes: Vec<u8> = rx.drain(..total).collect();
        records.push((header.opcode, header.hwnd, bytes[wire::HEADER_LEN..].to_vec()));
    }
}

#[test]
fn injected_pointer_and_keys_reach_the_bridge_under_a_compositor() {
    const WS_OVERLAPPED_VISIBLE: u32 = 0x14cf_0000;
    const WS_CHILD_VISIBLE: u32 = 0x5000_0000;
    let Some(session) = desktop() else { return; };
    // The bridge runs as its own process, the way the guest runs it: libxcb
    // takes the display and the X authority from the environment, which a
    // child can be given without mutating this one, and the binary's own
    // event loop is then part of what this exercises.
    let (mut peer, bridge) = UnixStream::pair().unwrap();
    let bridge_fd = bridge.as_raw_fd();
    struct Reap(Child);
    impl Drop for Reap { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    // SAFETY: pre_exec only duplicates an inherited descriptor onto fd 0 in
    // the forked child; it allocates nothing and touches no shared state.
    let _bridge_process = Reap(unsafe {
        Command::new(env!("CARGO_BIN_EXE_windows-compositor")).args(["--fd", "0"])
            .env("DISPLAY", &session.display).env_remove("XAUTHORITY").env("XDG_RUNTIME_DIR", &session.runtime)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .pre_exec(move || { if libc::dup2(bridge_fd, 0) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) })
            .spawn().expect("the bridge binary starts")
    });
    drop(bridge);

    send(&mut peer, Opcode::Create, 1, 1, window_payload(EDGE, EDGE, 0, WS_OVERLAPPED_VISIBLE));
    send(&mut peer, Opcode::Title, 2, 1, b"oxide-bridge-input".to_vec());
    let mut frame = Vec::new();
    frame.extend_from_slice(&EDGE.to_le_bytes()); frame.extend_from_slice(&EDGE.to_le_bytes());
    frame.extend_from_slice(&(EDGE * 4).to_le_bytes()); frame.extend_from_slice(&wire::PIXEL_BGRA8888.to_le_bytes());
    frame.extend(core::iter::repeat_n(0x00ff_ffffu32.to_le_bytes(), (EDGE * EDGE) as usize).flatten());
    send(&mut peer, Opcode::Frame, 3, 1, frame);
    send(&mut peer, Opcode::Visibility, 4, 1, 1u32.to_le_bytes().to_vec());
    // The edit control: input lands on the child, which is what the guest's
    // click hits and what the retargeting has to name.
    send(&mut peer, Opcode::Create, 5, 2, window_payload(EDGE, EDGE, 1, WS_CHILD_VISIBLE));
    send(&mut peer, Opcode::Visibility, 6, 2, 1u32.to_le_bytes().to_vec());

    // The commands above are written blocking; the loop below polls.
    peer.set_nonblocking(true).unwrap();
    let mut rx = Vec::new();
    let mut records = Vec::new();
    let mut injected = false;
    let settle = Instant::now() + Duration::from_secs(3);
    let deadline = Instant::now() + READY;
    while Instant::now() < deadline {
        drain(&mut peer, &mut rx, &mut records);
        if !injected {
            // A top level's Configure states where the window manager put it
            // on the screen: input aimed anywhere else lands on the desktop.
            let placed = records.iter().rev().find(|(op, hwnd, _)| *op == Opcode::Configure && *hwnd == 1)
                .and_then(|(_, _, payload)| wire::Rect::decode_window(payload).ok());
            if let Some(rect) = placed.filter(|_| Instant::now() > settle) {
                // XTEST goes through the server's core devices, the same route
                // the guest's absolute-pointer and send-key injection takes.
                let x = (rect.x + rect.width as i32 / 2).to_string();
                let y = (rect.y + rect.height as i32 / 2).to_string();
                // Each event has to be delivered before the next is sent: a
                // button pressed in the same breath as the motion that put the
                // pointer over the window is aimed at wherever it used to be.
                xdotool(&session, &["mousemove", &x, &y]);
                std::thread::sleep(Duration::from_millis(400));
                xdotool(&session, &["click", "1"]);
                std::thread::sleep(Duration::from_millis(400));
                xdotool(&session, &["key", "a"]);
                injected = true;
            }
        }
        let pointer = records.iter().filter(|(op, _, _)| *op == Opcode::Pointer).count();
        let keys = records.iter().filter(|(op, _, _)| *op == Opcode::Key).count();
        if pointer >= 2 && keys >= 2 && records.iter().any(|(op, _, _)| *op == Opcode::Text) { break; }
        std::thread::sleep(Duration::from_millis(20));
    }

    let pointer: Vec<_> = records.iter().filter(|(op, _, _)| *op == Opcode::Pointer).collect();
    let keys: Vec<_> = records.iter().filter(|(op, _, _)| *op == Opcode::Key).collect();
    let text: Vec<_> = records.iter().filter(|(op, _, _)| *op == Opcode::Text).collect();
    let seen: Vec<Opcode> = records.iter().map(|(op, _, _)| *op).collect();
    assert!(pointer.len() >= 2, "no button press and release reached the bridge; records {seen:?}");
    assert!(keys.len() >= 2, "no key press and release reached the bridge; records {seen:?}");
    assert_eq!(text.len(), 1, "one press produces exactly one character; records {seen:?}");
    assert_eq!(text[0].2, b"a");
    // Input names the child the pointer is over, never the X window id.
    for (_, hwnd, _) in pointer.iter().chain(keys.iter()).chain(text.iter()) { assert_eq!(*hwnd, 2); }
    // The button mask is a Win32 one and states the button state after the
    // transition: an X modifier state read straight through reports the
    // opposite of the press that produced the event.
    let pressed = pointer.iter().position(|(_, _, p)| wire::u32_at(p, 8) == Ok(MK_LBUTTON))
        .expect("a press carries MK_LBUTTON");
    assert!(pointer[pressed + 1..].iter().any(|(_, _, p)| wire::u32_at(p, 8) == Ok(0)), "the release clears the mask");
    // 'a' is VK_A with the physical scan code, not the keysym or the keycode.
    assert_eq!(wire::u32_at(&keys[0].2, 0), Ok(0x41));
    assert_eq!(wire::u32_at(&keys[0].2, 4), Ok(0x1e));
    assert_eq!(wire::u32_at(&keys[0].2, 8), Ok(1));
    assert_eq!(wire::u32_at(&keys[1].2, 8), Ok(0));
}
