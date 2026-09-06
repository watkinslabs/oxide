//! Real daemon lock/socket lifetime boundary; no private registry implementation.
#![cfg(target_os = "linux")]

use std::{fs, io::{Read, Write}, os::unix::{fs::MetadataExt, net::UnixStream}, path::{Path, PathBuf},
    process::{Child, Command, Stdio}, thread, time::{Duration, Instant}};
use syscall::registry_wire;

const DEADLINE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);
const CURRENT_USER: u8 = 1;

struct Fixture { directory: PathBuf, children: Vec<Child> }
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir();
        fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let output = Command::new("mktemp").arg("-d").arg(base.join("registry-lifetime.XXXXXX")).output().unwrap();
        assert!(output.status.success());
        Self { directory: PathBuf::from(String::from_utf8(output.stdout).unwrap().trim()), children: Vec::new() }
    }
    fn spawn(&mut self) -> u32 {
        let child = Command::new(env!("CARGO_BIN_EXE_registryd"))
            .arg(self.directory.join("registry.sock")).arg(self.directory.join("registry.db"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
        let pid = child.id(); self.children.push(child); pid
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for child in &mut self.children { let _ = child.kill(); let _ = child.wait(); }
        // Only the unique directory allocated by this fixture is removed, after child reaping.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait_until(label: &str, mut ready: impl FnMut() -> bool) {
    let end = Instant::now() + DEADLINE;
    while !ready() { assert!(Instant::now() < end, "timed out: {label}"); thread::sleep(POLL); }
}

fn blocked_on_owner(owner: u32, waiter: u32) -> bool {
    let locks = fs::read_to_string("/proc/locks").expect("hosted Linux test requires /proc/locks");
    let mut owner_lock = None;
    for line in locks.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let blocked = fields.get(1) == Some(&"->");
        let start = if blocked { 2 } else { 1 };
        if fields.get(start) != Some(&"FLOCK") { continue; }
        let pid = fields.get(start + 3).and_then(|pid| pid.parse::<u32>().ok());
        if !blocked && pid == Some(owner) { owner_lock = fields.get(start + 4).copied(); }
        if blocked && pid == Some(waiter) && owner_lock.is_some()
            && fields.get(start + 4).copied() == owner_lock { return true; }
    }
    false
}

fn socket_identity(socket: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(socket).expect("live owner's socket must remain linked");
    (metadata.dev(), metadata.ino())
}

fn query_root(socket: &Path) {
    let mut stream = UnixStream::connect(socket).expect("fresh client must reach the original owner");
    request_handle(&mut stream, registry_wire::OPEN, "");
}

fn request_handle(stream: &mut UnixStream, operation: u8, name: &str) -> u64 {
    stream.set_read_timeout(Some(DEADLINE)).unwrap(); stream.set_write_timeout(Some(DEADLINE)).unwrap();
    let mut request = vec![operation, CURRENT_USER];
    request.extend_from_slice(&(name.len() as u32).to_le_bytes()); request.extend_from_slice(name.as_bytes());
    stream.write_all(&(request.len() as u32).to_le_bytes()).unwrap(); stream.write_all(&request).unwrap();
    let mut length = [0; 4]; stream.read_exact(&mut length).unwrap();
    assert_eq!(u32::from_le_bytes(length), 9, "root open must return a typed handle");
    let mut response = [0; 9]; stream.read_exact(&mut response).unwrap();
    assert_eq!(response[0], registry_wire::RESPONSE_HANDLE);
    let handle = u64::from_le_bytes(response[1..].try_into().unwrap());
    assert_ne!(handle, 0); handle
}

fn send_frame(stream: &mut UnixStream, request: &[u8]) {
    stream.write_all(&(request.len() as u32).to_le_bytes()).unwrap(); stream.write_all(request).unwrap();
}
fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0; 4]; stream.read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!(length > 0 && length <= registry_wire::MAX_FRAME);
    let mut response = vec![0; length]; stream.read_exact(&mut response).unwrap(); response
}
fn value_request(operation: u8, key: u64, name: &str) -> Vec<u8> {
    let mut frame = vec![operation]; frame.extend_from_slice(&key.to_le_bytes());
    frame.extend_from_slice(&(name.len() as u32).to_le_bytes()); frame.extend_from_slice(name.as_bytes()); frame
}
fn set_dword(stream: &mut UnixStream, key: u64, name: &str, value: u32) {
    let mut frame = value_request(registry_wire::SET, key, name);
    frame.extend_from_slice(&(windows_registry::ValueType::Dword as u32).to_le_bytes());
    frame.extend_from_slice(&4u32.to_le_bytes()); frame.extend_from_slice(&value.to_le_bytes());
    send_frame(stream, &frame); assert_eq!(read_frame(stream), [registry_wire::RESPONSE_SUCCESS]);
}
fn expect_dword(stream: &mut UnixStream, value: u32) {
    let mut expected = vec![registry_wire::RESPONSE_VALUE];
    expected.extend_from_slice(&(windows_registry::ValueType::Dword as u32).to_le_bytes());
    expected.extend_from_slice(&4u32.to_le_bytes()); expected.extend_from_slice(&value.to_le_bytes());
    assert_eq!(read_frame(stream), expected);
}

#[test]
fn idle_persistent_client_does_not_block_another_client_or_split_store() {
    let mut fixture = Fixture::new(); let socket = fixture.directory.join("registry.sock");
    fixture.spawn();
    wait_until("daemon socket", || { assert!(fixture.children[0].try_wait().unwrap().is_none()); socket.exists() });
    let mut first = UnixStream::connect(&socket).unwrap();
    request_handle(&mut first, registry_wire::OPEN, "");
    // First has completed a real request and remains connected: accept order is established.
    let mut second = UnixStream::connect(&socket).unwrap();
    let created = request_handle(&mut second, registry_wire::CREATE, "Software\\ConcurrentClients");
    let opened = request_handle(&mut first, registry_wire::OPEN, "Software\\ConcurrentClients");
    assert_ne!(created, opened, "both connections allocate from one canonical handle sequence");
    set_dword(&mut second, created, "from-second", 41);
    set_dword(&mut first, opened, "from-first", 73);
    // Requests outstanding on both connections; distinct payloads expose response misrouting.
    send_frame(&mut first, &value_request(registry_wire::QUERY, opened, "from-second"));
    send_frame(&mut second, &value_request(registry_wire::QUERY, created, "from-first"));
    expect_dword(&mut second, 73); expect_dword(&mut first, 41);
    drop(second);
    request_handle(&mut first, registry_wire::OPEN, "Software\\ConcurrentClients");
}

#[test]
fn partial_frame_client_does_not_hold_registry_owner() {
    let mut fixture = Fixture::new(); let socket = fixture.directory.join("registry.sock");
    fixture.spawn();
    wait_until("daemon socket", || { assert!(fixture.children[0].try_wait().unwrap().is_none()); socket.exists() });
    let mut first = UnixStream::connect(&socket).unwrap();
    request_handle(&mut first, registry_wire::OPEN, "");
    first.write_all(&[6, 0]).unwrap();
    query_root(&socket);
    drop(first);
    query_root(&socket);
}

#[test]
fn second_daemon_cannot_orphan_first_socket() {
    let mut fixture = Fixture::new(); let socket = fixture.directory.join("registry.sock");
    let first = fixture.spawn();
    wait_until("first daemon socket", || { assert!(fixture.children[0].try_wait().unwrap().is_none()); socket.exists() });
    query_root(&socket); let original = socket_identity(&socket);
    let second = fixture.spawn();
    wait_until("second daemon blocked on first sidecar lock", || {
        assert!(fixture.children.iter_mut().all(|child| child.try_wait().unwrap().is_none()));
        blocked_on_owner(first, second)
    });
    // Isolated removal-control models a launcher unlink, never mutating production source.
    if std::env::var_os("OXIDE_REGISTRY_UNLINK_CONTROL").is_some() { fs::remove_file(&socket).unwrap(); }
    assert_eq!(socket_identity(&socket), original, "contender replaced the owner's socket");
    query_root(&socket);
    fixture.children[1].kill().unwrap(); fixture.children[1].wait().unwrap();
    assert!(fixture.children[0].try_wait().unwrap().is_none());
    assert_eq!(socket_identity(&socket), original);
    query_root(&socket);
}
