//! Native NT registry boundary backed by the userspace registry owner.

use alloc::{string::{String, ToString}, sync::Arc, vec::Vec};
use sync::{Spinlock, TaskList as RegistryWatchLock};
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
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_0001;
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
const KEY_VALUE_BASIC_INFORMATION: u64 = 0;
const KEY_VALUE_FULL_INFORMATION: u64 = 1;
const KEY_BASIC_INFORMATION: u64 = 0;
const KEY_NODE_INFORMATION: u64 = 1;
const KEY_FULL_INFORMATION: u64 = 2;
const KEY_NAME_INFORMATION: u64 = 3;
const MAX_REGISTRY_TEXT: usize = 1 << 20;
const MAX_REGISTRY_VALUE: usize = 1 << 24;
const REGISTRY_SOCKET: &str = "/run/oxide/registry.sock";
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const KEY_NOTIFY: u32 = 0x0010;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

struct RegistryWatch { key: u64, filter: u64, event: Arc<sched::nt_object::NtEvent>, io_status: u64 }
static REGISTRY_WATCHES: Spinlock<Vec<RegistryWatch>, RegistryWatchLock> = Spinlock::new(Vec::new());

#[derive(Debug)]
enum Reply { Success, Handle(u64), Value { kind: u32, data: Vec<u8> }, Keys(Vec<String>), Values(Vec<(String, u32, Vec<u8>)>), KeyInfo { name: String, subkeys: u32, max_subkey: u32, values: u32, max_value_name: u32, max_value_data: u32 }, Failure(u8) }

/// Create the native key handle for the userspace-owned current-user root.
/// # C: O(1) plus one NT handle-table insertion
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlOpenCurrentUser { return Some(open_current_user(call)); }
    if matches!(call.service, NtService::OpenKey | NtService::NtOpenKeyEx) { return Some(open_key(call)); }
    if call.service == NtService::CreateKey { return Some(create_key(call)); }
    if call.service == NtService::QueryValueKey { return Some(query_value(call)); }
    if call.service == NtService::NtQueryValueKey { return Some(query_value_native(call)); }
    if call.service == NtService::NtEnumerateValueKey { return Some(enumerate_value_native(call)); }
    if call.service == NtService::NtEnumerateKey { return Some(enumerate_key_native(call)); }
    if call.service == NtService::SetValueKey { return Some(set_value(call)); }
    if call.service == NtService::NtSetValueKey { return Some(set_value_native(call)); }
    if call.service == NtService::NtQueryKey { return Some(query_key_native(call)); }
    if call.service == NtService::NtFlushKey { return Some(flush_key_native(call)); }
    if call.service == NtService::NtNotifyChangeKey { return Some(notify_change_key(call)); }
    None
}

fn notify_change_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let Some(subtree) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(buffer) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(length) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    let Some(asynchronous) = crate::nt_dispatch::stack_argument(9) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a2 != 0 || call.args.a3 != 0 || call.args.a4 == 0 || asynchronous == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // The current registry owner exposes value mutation notifications only.
    // Rejecting the other filters is important: a pending request must never
    // claim completion for a mutation it cannot observe.
    if !crate::nt_registry_policy::supported_request(
        call.args.a2, call.args.a3, call.args.a4, buffer, length,
        asynchronous, subtree, call.args.a5,
    ) {
        return STATUS_NOT_IMPLEMENTED;
    }
    let key = call.args.a0 as u32;
    let table = current.thread_group.nt_handles();
    let Some(key_object) = table.get(sched::nt_object::NtHandle::from_raw(key), KEY_NOTIFY) else { return STATUS_ACCESS_DENIED; };
    if key_object.kind() != sched::nt_object::NtObjectType::Key { return STATUS_INVALID_PARAMETER; }
    let Some(event_object) = table.get(sched::nt_object::NtHandle::from_raw(call.args.a1 as u32), SYNCHRONIZE_ACCESS) else {
        return if table.contains(sched::nt_object::NtHandle::from_raw(call.args.a1 as u32)) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_PARAMETER };
    };
    let Some(event) = event_object.event() else { return STATUS_INVALID_PARAMETER; };
    let mut watches = REGISTRY_WATCHES.lock();
    watches.retain(|watch| !(watch.key == key_object.id() && watch.io_status == call.args.a4));
    watches.push(RegistryWatch { key: key_object.id(), filter: call.args.a5, event, io_status: call.args.a4 });
    STATUS_PENDING
}

fn notify_registry_key(key: u64) {
    let mut watches = REGISTRY_WATCHES.lock();
    let mut index = 0;
    while index < watches.len() {
        if watches[index].key != key || watches[index].filter & crate::nt_registry_policy::REG_NOTIFY_CHANGE_LAST_SET == 0 { index += 1; continue; }
        let watch = watches.remove(index);
        let _ = uaccess::put_user_u64(watch.io_status, STATUS_SUCCESS);
        let _ = uaccess::put_user_u64(watch.io_status.saturating_add(8), 0);
        watch.event.set();
    }
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

fn frame_key(operation: u8, key: u64) -> Vec<u8> { let mut frame = Vec::new(); frame.push(operation); frame.extend_from_slice(&key.to_le_bytes()); frame }

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
        registry_wire::RESPONSE_KEYS => { let mut at = 5; let count = u32::from_le_bytes(frame.get(1..5)?.try_into().ok()?) as usize; if count > 1 << 20 { return None; } let mut keys = Vec::new(); keys.try_reserve_exact(count).ok()?; for _ in 0..count { let length = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?) as usize; at += 4; if length > MAX_REGISTRY_TEXT { return None; } let end = at.checked_add(length)?; keys.push(String::from_utf8(frame.get(at..end)?.to_vec()).ok()?); at = end; } if at != frame.len() { return None; } Some(Reply::Keys(keys)) },
        registry_wire::RESPONSE_VALUES => { let mut at = 5; let count = u32::from_le_bytes(frame.get(1..5)?.try_into().ok()?) as usize; if count > 1 << 20 { return None; } let mut values = Vec::new(); values.try_reserve_exact(count).ok()?; for _ in 0..count { let name_len = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?) as usize; at += 4; if name_len > MAX_REGISTRY_TEXT { return None; } let name_end = at.checked_add(name_len)?; let name = String::from_utf8(frame.get(at..name_end)?.to_vec()).ok()?; at = name_end; let kind = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; let data_len = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?) as usize; at += 4; if data_len > MAX_REGISTRY_VALUE { return None; } let data_end = at.checked_add(data_len)?; values.push((name, kind, frame.get(at..data_end)?.to_vec())); at = data_end; } if at != frame.len() { return None; } Some(Reply::Values(values)) },
        registry_wire::RESPONSE_KEY_INFO => { let mut at = 1; let length = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?) as usize; at += 4; if length > MAX_REGISTRY_TEXT { return None; } let end = at.checked_add(length)?; let name = String::from_utf8(frame.get(at..end)?.to_vec()).ok()?; at = end; let subkeys = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; let max_subkey = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; let values = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; let max_value_name = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; let max_value_data = u32::from_le_bytes(frame.get(at..at + 4)?.try_into().ok()?); at += 4; if at != frame.len() { return None; } Some(Reply::KeyInfo { name, subkeys, max_subkey, values, max_value_name, max_value_data }) },
        registry_wire::RESPONSE_FAILURE if frame.len() == 2 => Some(Reply::Failure(frame[1])),
        _ => None,
    }
}

fn flush_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(remote) = remote_key(&current, call.args.a0 as u32) else { return STATUS_INVALID_PARAMETER; };
    match transact(&frame_key(registry_wire::FLUSH, remote)) { Some(Reply::Success) => STATUS_SUCCESS, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
}

fn query_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let class = call.args.a1; let info = call.args.a2; let length = call.args.a3; let result = call.args.a4;
    if !current.is_nt_personality() || info == 0 || length > u32::MAX as u64 || result > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let Some(remote) = remote_key(&current, key) else { return STATUS_INVALID_PARAMETER; };
    let Some(Reply::KeyInfo { name, subkeys, max_subkey, values, max_value_name, max_value_data }) = transact(&frame_key(registry_wire::QUERY_KEY, remote)) else { return STATUS_UNSUCCESSFUL; };
    let name: Vec<u16> = name.encode_utf16().collect(); let name_bytes = name.len().checked_mul(2).unwrap_or(usize::MAX);
    let (fixed, record) = match class {
        KEY_BASIC_INFORMATION => { let mut out = Vec::with_capacity(16 + name_bytes); out.extend_from_slice(&[0; 8]); put_u32(&mut out, 0); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (16, out) },
        KEY_NODE_INFORMATION => { let mut out = Vec::with_capacity(24 + name_bytes); out.extend_from_slice(&[0; 8]); put_u32(&mut out, 0); put_u32(&mut out, u32::MAX); put_u32(&mut out, 0); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (24, out) },
        KEY_FULL_INFORMATION => { let mut out = Vec::with_capacity(44); out.extend_from_slice(&[0; 8]); put_u32(&mut out, 0); put_u32(&mut out, u32::MAX); put_u32(&mut out, 0); put_u32(&mut out, subkeys); put_u32(&mut out, max_subkey); put_u32(&mut out, 0); put_u32(&mut out, values); put_u32(&mut out, max_value_name); put_u32(&mut out, max_value_data); (44, out) },
        KEY_NAME_INFORMATION => { let mut out = Vec::with_capacity(4 + name_bytes); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (4, out) },
        _ => return STATUS_INVALID_PARAMETER,
    };
    let required = record.len() as u32; if result != 0 && uaccess::put_user_u32(result, required).is_err() { return STATUS_INVALID_PARAMETER; }
    if length < fixed as u64 { return STATUS_BUFFER_TOO_SMALL; }
    if length < required as u64 {
        let available = length as usize;
        if uaccess::copy_to_user(info, &record[..available]).is_err() { return STATUS_ACCESS_VIOLATION; }
        return STATUS_BUFFER_OVERFLOW;
    }
    if uaccess::copy_to_user(info, &record).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn enumerate_value_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let index = call.args.a1; let class = call.args.a2;
    let info = call.args.a3; let length = call.args.a4; let result = call.args.a5;
    if !current.is_nt_personality() || info == 0 || index > u32::MAX as u64 || length > u32::MAX as u64 || result > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let Some(remote) = remote_key(&current, key) else { return STATUS_INVALID_PARAMETER; };
    let mut frame = Vec::new(); frame.push(registry_wire::ENUM_VALUES); frame.extend_from_slice(&remote.to_le_bytes());
    let Some(Reply::Values(values)) = transact(&frame) else { return STATUS_UNSUCCESSFUL; };
    let Some((name, kind, data)) = values.get(index as usize) else { return STATUS_NO_MORE_ENTRIES; };
    let name: Vec<u16> = name.encode_utf16().collect(); let name_bytes = name.len().checked_mul(2).unwrap_or(usize::MAX);
    let (fixed, mut record) = match class {
        KEY_VALUE_BASIC_INFORMATION => { let required = 12usize.checked_add(name_bytes).unwrap_or(usize::MAX); let mut out = Vec::with_capacity(required); put_u32(&mut out, 0); put_u32(&mut out, *kind); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (12, out) },
        KEY_VALUE_FULL_INFORMATION => { let required = 20usize.checked_add(name_bytes).and_then(|v| v.checked_add(data.len())).unwrap_or(usize::MAX); let mut out = Vec::with_capacity(required); put_u32(&mut out, 0); put_u32(&mut out, *kind); put_u32(&mut out, (20 + name_bytes) as u32); put_u32(&mut out, data.len() as u32); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); out.extend_from_slice(data); (20, out) },
        KEY_VALUE_PARTIAL_INFORMATION => { let required = 12usize.checked_add(data.len()).unwrap_or(usize::MAX); let mut out = Vec::with_capacity(required); put_u32(&mut out, 0); put_u32(&mut out, *kind); put_u32(&mut out, data.len() as u32); out.extend_from_slice(data); (12, out) },
        _ => return STATUS_INVALID_PARAMETER,
    };
    let required = record.len() as u32; if result != 0 && uaccess::put_user_u32(result, required).is_err() { return STATUS_INVALID_PARAMETER; }
    if length < fixed as u64 { return STATUS_BUFFER_TOO_SMALL; }
    if length < required as u64 { record.truncate(length as usize); }
    if uaccess::copy_to_user(info, &record).is_err() { return STATUS_ACCESS_VIOLATION; }
    if length < required as u64 { STATUS_BUFFER_OVERFLOW } else { STATUS_SUCCESS }
}

fn enumerate_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let index = call.args.a1; let class = call.args.a2; let info = call.args.a3; let length = call.args.a4; let result = call.args.a5;
    if !current.is_nt_personality() || info == 0 || index > u32::MAX as u64 || length > u32::MAX as u64 || result > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    if index == u32::MAX as u64 { return STATUS_NO_MORE_ENTRIES; }
    let Some(remote) = remote_key(&current, key) else { return STATUS_INVALID_PARAMETER; };
    let mut frame = Vec::new(); frame.push(registry_wire::ENUM_KEYS); frame.extend_from_slice(&remote.to_le_bytes());
    let Some(Reply::Keys(keys)) = transact(&frame) else { return STATUS_UNSUCCESSFUL; };
    let Some(name) = keys.get(index as usize) else { return STATUS_NO_MORE_ENTRIES; };
    let name: Vec<u16> = name.encode_utf16().collect(); let name_bytes = name.len().checked_mul(2).unwrap_or(usize::MAX);
    let (fixed, mut record) = match class {
        KEY_BASIC_INFORMATION => { let mut out = Vec::with_capacity(16 + name_bytes); out.extend_from_slice(&[0; 8]); put_u32(&mut out, 0); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (16, out) },
        KEY_NODE_INFORMATION => { let mut out = Vec::with_capacity(24 + name_bytes); out.extend_from_slice(&[0; 8]); put_u32(&mut out, 0); put_u32(&mut out, u32::MAX); put_u32(&mut out, 0); put_u32(&mut out, name_bytes as u32); append_utf16(&mut out, &name); (24, out) },
        KEY_FULL_INFORMATION => {
            let mut value_frame = Vec::new(); value_frame.push(registry_wire::ENUM_VALUES); value_frame.extend_from_slice(&remote.to_le_bytes());
            let values = match transact(&value_frame) { Some(Reply::Values(values)) => values, _ => return STATUS_UNSUCCESSFUL };
            let max_name = values.iter().map(|(name, _, _)| name.encode_utf16().count() * 2).max().unwrap_or(0);
            let max_data = values.iter().map(|(_, _, data)| data.len()).max().unwrap_or(0);
            let max_key = keys.iter().map(|key| key.encode_utf16().count() * 2).max().unwrap_or(0);
            let mut out = Vec::with_capacity(44); out.extend_from_slice(&[0; 8]);
            put_u32(&mut out, u32::MAX); put_u32(&mut out, 0); put_u32(&mut out, keys.len() as u32);
            put_u32(&mut out, max_key as u32); put_u32(&mut out, 0); put_u32(&mut out, values.len() as u32);
            put_u32(&mut out, max_name as u32); put_u32(&mut out, max_data as u32); (44, out)
        },
        _ => return STATUS_INVALID_PARAMETER,
    };
    let required = record.len() as u32; if result != 0 && uaccess::put_user_u32(result, required).is_err() { return STATUS_INVALID_PARAMETER; }
    if length < fixed as u64 { return STATUS_BUFFER_TOO_SMALL; }
    if length < required as u64 { record.truncate(length as usize); }
    if uaccess::copy_to_user(info, &record).is_err() { return STATUS_ACCESS_VIOLATION; }
    if length < required as u64 { STATUS_BUFFER_OVERFLOW } else { STATUS_SUCCESS }
}

fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn append_utf16(out: &mut Vec<u8>, text: &[u16]) { for unit in text { out.extend_from_slice(&unit.to_le_bytes()); } }

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
    match transact(&frame_set(remote, &name, kind as u32, &bytes)) { Some(Reply::Success) => { notify_registry_key(remote); STATUS_SUCCESS }, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
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
