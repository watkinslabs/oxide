//! Native NT registry boundary backed by the userspace registry owner.

use alloc::{string::{String, ToString}, sync::Arc, vec::Vec};
use syscall::nt::{NtCall, NtService};
use syscall::registry_wire;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
const MAX_REGISTRY_TEXT: usize = 1 << 20;
const MAX_REGISTRY_VALUE: usize = 1 << 24;
const REGISTRY_SOCKET: &str = "/run/oxide/registry.sock";

#[derive(Debug)]
enum Reply { Success, Handle(u64), Value { kind: u32, data: Vec<u8> }, Failure(u8) }

/// Create the native key handle for the userspace-owned current-user root.
/// # C: O(1) plus one NT handle-table insertion
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlOpenCurrentUser { return Some(open_current_user(call)); }
    if matches!(call.service, NtService::OpenKey | NtService::NtOpenKeyEx) { return Some(open_key(call)); }
    if call.service == NtService::CreateKey { return Some(create_key(call)); }
    if call.service == NtService::QueryValueKey { return Some(query_value(call)); }
    if call.service == NtService::NtQueryValueKey { return Some(query_value_native(call)); }
    if call.service == NtService::SetValueKey { return Some(set_value(call)); }
    if call.service == NtService::NtSetValueKey { return Some(set_value_native(call)); }
    None
}

/// Release the userspace registry handle paired with a native NT key.
/// # C: one bounded registry request
pub fn close_remote(key: u64) {
    let mut frame = Vec::new();
    frame.push(registry_wire::CLOSE);
    frame.extend_from_slice(&key.to_le_bytes());
    let _ = transact(&frame);
}

fn open_current_user(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a1 == 0 || call.args.a0 > u32::MAX as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    let handles = current.thread_group.nt_handles();
    let object = sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, 0x8000_0001);
    let Some(handle) = handles.insert(object, call.args.a0 as u32) else {
        return STATUS_NO_MEMORY;
    };
    if uaccess::put_user_u32(call.args.a1, handle.raw()).is_err() {
        let _ = handles.close(handle);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn open_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    if call.service == NtService::NtOpenKeyEx && call.args.a3 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some((root, relative, name)) = key_name(call.args.a2, &current) else { return STATUS_INVALID_PARAMETER; };
    let request = if let Some(handle) = relative { frame_relative(registry_wire::OPEN_RELATIVE, handle, &name) } else { frame_root(registry_wire::OPEN, root, &name) };
    let Some(reply) = transact(&request) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Handle(remote) = reply else { return reply_status(reply); };
    let handles = current.thread_group.nt_handles();
    let Some(native) = handles.insert(sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, remote), call.args.a1 as u32) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u32(call.args.a0, native.raw()).is_err() { let _ = handles.close(native); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn create_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 || call.args.a5 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some((root, relative, name)) = key_name(call.args.a2, &current) else { return STATUS_INVALID_PARAMETER; };
    let request = if let Some(handle) = relative { frame_relative(registry_wire::CREATE_RELATIVE, handle, &name) } else { frame_root(registry_wire::CREATE, root, &name) };
    let Some(reply) = transact(&request) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Handle(remote) = reply else { return reply_status(reply); };
    let handles = current.thread_group.nt_handles();
    let Some(native) = handles.insert(sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, remote), call.args.a1 as u32) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u32(call.args.a0, native.raw()).is_err() { let _ = handles.close(native); return STATUS_INVALID_PARAMETER; }
    if let Some(disposition) = crate::nt_dispatch::stack_argument(6) { let _ = uaccess::put_user_u32(disposition, 1); }
    STATUS_SUCCESS
}

fn frame_root(operation: u8, root: u8, name: &str) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(operation); frame.push(root); put_text(&mut frame, name); frame
}

fn frame_relative(operation: u8, key: u64, name: &str) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(operation); frame.extend_from_slice(&key.to_le_bytes()); put_text(&mut frame, name); frame
}

fn frame_query(key: u64, name: &str) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(registry_wire::QUERY); frame.extend_from_slice(&key.to_le_bytes()); put_text(&mut frame, name); frame
}

fn frame_set(key: u64, name: &str, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(registry_wire::SET); frame.extend_from_slice(&key.to_le_bytes()); put_text(&mut frame, name); frame.extend_from_slice(&kind.to_le_bytes()); put_bytes(&mut frame, data); frame
}

fn put_text(frame: &mut Vec<u8>, text: &str) { put_bytes(frame, text.as_bytes()); }
fn put_bytes(frame: &mut Vec<u8>, bytes: &[u8]) { frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); frame.extend_from_slice(bytes); }

fn transact(frame: &[u8]) -> Option<Reply> {
    let root = vfs::mntns::initial().id(); let root = vfs::mount::root_path_for_ns(root)?;
    let found = vfs::path_lookup_at_root_cred(root.dentry.clone(), root.mnt_id, root.dentry.clone(), root.mnt_id,
        REGISTRY_SOCKET, vfs::LookupFlags::default(), vfs::Cred::root()).ok()?;
    if found.inode.file_type() != vfs::FileType::Socket { return None; }
    let address = net::UnixAddr::from_inode_bytes(REGISTRY_SOCKET.as_bytes().to_vec(), &found.inode);
    let socket = net::sock::connect_kernel_unix(address).ok()?;
    let frame_len = (frame.len() as u32).to_le_bytes(); write_all(&socket, &frame_len)?; write_all(&socket, frame)?;
    let mut length = [0u8; 4]; read_exact(&socket, &mut length)?; let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > registry_wire::MAX_FRAME { return None; }
    let mut response = Vec::new(); response.try_reserve_exact(length).ok()?; response.resize(length, 0); read_exact(&socket, &mut response)?;
    decode_reply(&response)
}

fn write_all(socket: &Arc<net::sock::InetSocket>, mut bytes: &[u8]) -> Option<()> {
    while !bytes.is_empty() { let count = socket.write_kernel(bytes).ok()?; if count == 0 { return None; } bytes = &bytes[count..]; } Some(())
}

fn read_exact(socket: &Arc<net::sock::InetSocket>, mut bytes: &mut [u8]) -> Option<()> {
    while !bytes.is_empty() { let count = socket.read_kernel(bytes).ok()?; if count == 0 { return None; } bytes = &mut bytes[count..]; } Some(())
}

fn decode_reply(frame: &[u8]) -> Option<Reply> {
    match *frame.first()? {
        registry_wire::RESPONSE_SUCCESS if frame.len() == 1 => Some(Reply::Success),
        registry_wire::RESPONSE_HANDLE if frame.len() == 9 => Some(Reply::Handle(u64::from_le_bytes(frame[1..9].try_into().ok()?))),
        registry_wire::RESPONSE_VALUE => { let kind = u32::from_le_bytes(frame.get(1..5)?.try_into().ok()?); let length = u32::from_le_bytes(frame.get(5..9)?.try_into().ok()?) as usize; if length > MAX_REGISTRY_VALUE || frame.len() != 9 + length { return None; } Some(Reply::Value { kind, data: frame[9..].to_vec() }) },
        registry_wire::RESPONSE_FAILURE if frame.len() == 2 => Some(Reply::Failure(frame[1])),
        _ => None,
    }
}

fn query_value(call: NtCall) -> u64 {
    query_value_parts(call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5)
}

fn query_value_native(call: NtCall) -> u64 {
    query_value_parts(call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5)
}

fn query_value_parts(key: u32, name_ptr: u64, class: u64, info: u64, length: u64, result: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || name_ptr == 0 || info == 0 || length > u32::MAX as u64 || result > u32::MAX as u64 || class != KEY_VALUE_PARTIAL_INFORMATION { return STATUS_INVALID_PARAMETER; }
    let Some(remote) = remote_key(&current, key) else { return STATUS_INVALID_PARAMETER; };
    let Some(name) = read_unicode(name_ptr) else { return STATUS_INVALID_PARAMETER; };
    let Some(reply) = transact(&frame_query(remote, &name)) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Value { kind, data } = reply else { return reply_status(reply); };
    let required = match data.len().checked_add(8) { Some(v) if v <= u32::MAX as usize => v as u32, _ => return STATUS_UNSUCCESSFUL };
    if result != 0 && uaccess::put_user_u32(result, required).is_err() { return STATUS_INVALID_PARAMETER; }
    if length < 8 { return STATUS_BUFFER_TOO_SMALL; }
    if length < required as u64 { return STATUS_BUFFER_OVERFLOW; }
    if uaccess::copy_to_user(info, &kind.to_le_bytes()).is_err() || uaccess::copy_to_user(info + 4, &(data.len() as u32).to_le_bytes()).is_err() || uaccess::copy_to_user(info + 8, &data).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn set_value(call: NtCall) -> u64 {
    set_value_parts(call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5)
}

fn set_value_native(call: NtCall) -> u64 {
    set_value_parts(call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5)
}

fn set_value_parts(key: u32, name_ptr: u64, title: u64, kind: u64, data: u64, size: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || name_ptr == 0 || title != 0 || kind > u32::MAX as u64 || size > MAX_REGISTRY_VALUE as u64 || size != 0 && data == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(remote) = remote_key(&current, key) else { return STATUS_INVALID_PARAMETER; };
    let Some(name) = read_unicode(name_ptr) else { return STATUS_INVALID_PARAMETER; };
    let mut bytes = Vec::new(); if bytes.try_reserve_exact(size as usize).is_err() { return STATUS_NO_MEMORY; } bytes.resize(size as usize, 0);
    if size != 0 && uaccess::copy_from_user(&mut bytes, data).is_err() { return STATUS_ACCESS_VIOLATION; }
    match transact(&frame_set(remote, &name, kind as u32, &bytes)) { Some(Reply::Success) => STATUS_SUCCESS, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
}

fn reply_status(reply: Reply) -> u64 {
    match reply {
        Reply::Failure(1 | 4) => STATUS_INVALID_PARAMETER,
        Reply::Failure(2 | 3) => STATUS_OBJECT_NAME_NOT_FOUND,
        Reply::Failure(_) => STATUS_UNSUCCESSFUL,
        _ => STATUS_UNSUCCESSFUL,
    }
}

fn remote_key(current: &sched::Task, raw: u32) -> Option<u64> {
    let object = current.thread_group.nt_handles().get(sched::nt_object::NtHandle::from_raw(raw), 0)?;
    (object.kind() == sched::nt_object::NtObjectType::Key).then_some(object.id())
}

fn key_name(attributes: u64, current: &sched::Task) -> Option<(u8, Option<u64>, String)> {
    let mut bytes = [0u8; 48]; uaccess::copy_from_user(&mut bytes, attributes).ok()?;
    if u32::from_le_bytes(bytes[0..4].try_into().ok()?) < 48 { return None; }
    let root = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let object_name = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    let name = read_unicode(object_name)?;
    if let Some(remote) = (root != 0).then(|| remote_key(current, root as u32)).flatten() { return Some((0, Some(remote), name)); }
    if root != 0 { return None; }
    let folded = name.to_ascii_lowercase();
    for (prefix, code) in [("\\registry\\machine\\software\\classes", 2u8), ("\\registry\\user\\current", 1u8), ("\\registry\\machine", 0u8), ("\\registry\\user", 1u8)] {
        if folded == prefix { return Some((code, None, String::new())); }
        if let Some(rest) = folded.strip_prefix(&(prefix.to_string() + "\\")) { return Some((code, None, rest.to_string())); }
    }
    None
}

fn read_unicode(address: u64) -> Option<String> {
    if address == 0 { return None; }
    let mut descriptor = [0u8; 16]; uaccess::copy_from_user(&mut descriptor, address).ok()?;
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let maximum = u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().ok()?);
    if length > maximum || length & 1 != 0 || length > MAX_REGISTRY_TEXT * 2 || length != 0 && buffer == 0 { return None; }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(length).ok()?; bytes.resize(length, 0);
    if length != 0 { uaccess::copy_from_user(&mut bytes, buffer).ok()?; }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16(&units).ok()
}
