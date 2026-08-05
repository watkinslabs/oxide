// Target-side coredump socket connection and request/ack transport.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use super::pattern::{self, CoreContext, SocketProtocol};
use super::socket_protocol::{self, Owner};

/// Prepared destination, selected before any core image is generated.
pub enum Target {
    Kernel { sock: Arc<net::sock::InetSocket>, wait: bool },
    Userspace { sock: Arc<net::sock::InetSocket>, wait: bool },
    Reject,
}

/// Connect and, for `@@`, negotiate the dump owner. # C: O(path lookup + wait)
pub fn prepare(raw: &[u8], cx: &CoreContext) -> Option<Target> {
    let dest = pattern::socket_pattern(raw, cx)?;
    let ns = vfs::mntns::initial().id();
    let root = vfs::mount::root_path_for_ns(ns)?;
    let found = vfs::path_lookup_at_root_cred(root.dentry.clone(), root.mnt_id,
        root.dentry, root.mnt_id, &dest.path, vfs::LookupFlags::default(), vfs::Cred::root()).ok()?;
    if found.inode.file_type() != vfs::FileType::Socket { return None }
    let addr = net::UnixAddr::from_inode_bytes(dest.path.as_bytes().to_vec(), &found.inode);
    let sock = net::sock::connect_kernel_unix(addr).ok()?;
    if dest.protocol == SocketProtocol::Direct {
        return Some(Target::Kernel { sock,
            wait: socket_protocol::direct_wait(super::limits::core_pipe_limit()) });
    }
    let choice = socket_protocol::negotiate(|bytes| read_exact(&sock, bytes),
        |bytes| write_all(&sock, bytes))?;
    match choice.owner {
        Owner::Kernel => Some(Target::Kernel { sock, wait: choice.wait }),
        Owner::Userspace => Some(Target::Userspace { sock, wait: choice.wait }),
        Owner::Reject => Some(Target::Reject),
    }
}

/// Finish kernel-owned delivery and the optional collector wait. # C: O(body.len() + wait)
pub fn deliver(sock: &Arc<net::sock::InetSocket>, body: &[u8], wait: bool) {
    if !write_all(sock, body) { return }
    finish(sock, wait);
}

/// Finish userspace-owned handling without constructing or sending an image. # C: O(wait)
pub fn finish_userspace(sock: &Arc<net::sock::InetSocket>, wait: bool) { finish(sock, wait); }

fn write_all(sock: &Arc<net::sock::InetSocket>, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let Ok(n) = sock.write_kernel(bytes) else { return false };
        if n == 0 { return false }
        bytes = &bytes[n..];
    }
    true
}

fn read_exact(sock: &Arc<net::sock::InetSocket>, mut bytes: &mut [u8]) -> bool {
    while !bytes.is_empty() {
        let Ok(n) = sock.read_kernel(bytes) else { return false };
        if n == 0 { return false }
        bytes = &mut bytes[n..];
    }
    true
}

fn finish(sock: &Arc<net::sock::InetSocket>, wait: bool) {
    let _ = net::sock::shutdown(sock, net::uapi::ShutdownHow::Write);
    if wait { let _ = sock.read_kernel(&mut [0u8; 1]); }
}
