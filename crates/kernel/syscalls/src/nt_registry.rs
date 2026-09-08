//! Native NT registry boundary backed by the userspace registry owner.

use alloc::{string::String, sync::Arc, vec::Vec};
use syscall::nt::{NtCall, NtService};
use syscall::registry_wire;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_0001;
const MAX_REGISTRY_TEXT: usize = 1 << 20;
const MAX_REGISTRY_VALUE: usize = 1 << 24;
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_CANCELLED: u64 = 0xc000_0120;
const STATUS_HANDLES_CLOSED: u64 = 0xc000_0117;
const KEY_NOTIFY: u32 = 0x0010;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_WRITE_DATA: u32 = 0x0002;

struct RegistryWatch { key: u64, subscription: u64, owner_tid: u32, event: Arc<sched::nt_object::NtEvent>, io_status: u64 }
static REGISTRY_WATCHES: sync::Spinlock<Vec<RegistryWatch>, sync::TaskList> = sync::Spinlock::new(Vec::new());

#[derive(Debug)]
enum Reply { Success, Handle(u64), Value { kind: u32, data: Vec<u8> }, Keys(Vec<String>), Values(Vec<(String, u32, Vec<u8>)>), KeyInfo { name: String, subkeys: u32, max_subkey: u32, values: u32, max_value_name: u32, max_value_data: u32 }, Bytes(Vec<u8>), #[allow(dead_code)] Text(String), Subscription(u64), Notification, Failure(u8) }

/// Create the native key handle for the userspace-owned current-user root.
/// # C: O(1) plus one NT handle-table insertion
pub fn dispatch(call: NtCall) -> Option<u64> {
    // One list names the registry-owned services, so the endpoint guard below
    // can never claim a service this ladder would not have answered.
    let handler: fn(NtCall) -> u64 = match call.service {
        NtService::RtlOpenCurrentUser => open_current_user,
        NtService::OpenKey | NtService::NtOpenKeyEx => open_key,
        NtService::CreateKey => create_key,
        NtService::QueryValueKey => query_value,
        NtService::NtQueryValueKey => query_value_native,
        NtService::NtEnumerateValueKey => enumerate_value_native,
        NtService::NtEnumerateKey => enumerate_key_native,
        NtService::SetValueKey => set_value,
        NtService::NtSetValueKey => set_value_native,
        NtService::NtDeleteValueKey => delete_value_native,
        NtService::NtDeleteKey => delete_key_native,
        NtService::NtQueryKey => query_key_native,
        NtService::NtFlushKey => flush_key_native,
        NtService::NtSaveKey => save_key_native,
        NtService::NtLoadKey => load_key_native,
        NtService::NtNotifyChangeKey => notify_change_key,
        _ => return None,
    };
    // A process whose launch admitted no endpoint has no registry at all.
    // Refusing here, before any frame is built, keeps that refusal distinct
    // from a key that genuinely does not exist.
    if sched::live::current().is_none_or(|current| current.thread_group.nt_registry_endpoint().is_none()) {
        return Some(crate::nt_registry_endpoint::no_endpoint_status());
    }
    Some(handler(call))
}

fn notify_change_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
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
    let Some(Reply::Subscription(subscription)) = transact(&frame_subscribe(key_object.id(), call.args.a5, subtree != 0)) else { return STATUS_UNSUCCESSFUL; };
    let mut watches = REGISTRY_WATCHES.lock();
    watches.push(RegistryWatch { key: key_object.id(), subscription, owner_tid: current.tid, event, io_status: call.args.a4 });
    STATUS_PENDING
}

/// Cancel pending notifications for one native key object and issuing thread.
/// # C: O(N_watches)
pub fn cancel(key: u64, owner_tid: u32, target_io_status: Option<u64>) -> bool {
    finish_watches(key, Some(owner_tid), target_io_status, STATUS_CANCELLED)
}

/// Complete notifications before the final NT key object reference is closed.
/// # C: O(N_watches)
pub fn close_watches(key: u64) { let _ = finish_watches(key, None, None, STATUS_HANDLES_CLOSED); }

fn finish_watches(key: u64, owner_tid: Option<u32>, target_io_status: Option<u64>, status: u64) -> bool {
    let mut watches = REGISTRY_WATCHES.lock();
    let mut finished = false;
    let mut subscriptions = Vec::new();
    let mut index = 0;
    while index < watches.len() {
        let watch = &watches[index];
        if watch.key != key || owner_tid.is_some_and(|tid| watch.owner_tid != tid)
            || target_io_status.is_some_and(|target| watch.io_status != target) {
            index += 1;
            continue;
        }
        let watch = watches.remove(index);
        subscriptions.push(watch.subscription);
        let _ = uaccess::put_user_u64(watch.io_status, status);
        if let Some(status_information) = watch.io_status.checked_add(8) {
            let _ = uaccess::put_user_u64(status_information, 0);
        }
        watch.event.set();
        finished = true;
    }
    drop(watches);
    for subscription in subscriptions { unsubscribe(subscription); }
    finished
}

fn notify_registry_key(key: u64, _change: u64) {
    let mut index = 0;
    loop {
        let subscription = {
            let watches = REGISTRY_WATCHES.lock();
            watches.iter().skip(index).find(|watch| watch.key == key).map(|watch| watch.subscription)
        };
        let Some(subscription) = subscription else { break };
        let notified = matches!(transact(&frame_poll_subscription(subscription)), Some(Reply::Notification));
        if !notified { index += 1; continue; }
        let watch = {
            let mut watches = REGISTRY_WATCHES.lock();
            let Some(position) = watches.iter().position(|watch| watch.subscription == subscription) else { continue };
            watches.remove(position)
        };
        let _ = uaccess::put_user_u64(watch.io_status, STATUS_SUCCESS);
        if let Some(status_information) = watch.io_status.checked_add(8) {
            let _ = uaccess::put_user_u64(status_information, 0);
        }
        watch.event.set();
        unsubscribe(subscription);
    }
}

fn frame_subscribe(key: u64, filter: u64, subtree: bool) -> Vec<u8> {
    let mut frame = frame_key(registry_wire::SUBSCRIBE, key); frame.extend_from_slice(&filter.to_le_bytes()); frame.push(subtree as u8); frame
}

fn frame_poll_subscription(subscription: u64) -> Vec<u8> { frame_key(registry_wire::POLL_SUBSCRIPTION, subscription) }

fn unsubscribe(subscription: u64) {
    let frame = frame_key(registry_wire::UNSUBSCRIBE, subscription);
    let _ = transact(&frame);
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
    if !current.is_nt_personality() || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(access) = crate::nt_access::KEY.grant(crate::nt_ulong::ulong(call.args.a0) as u32) else { return STATUS_ACCESS_DENIED; };
    let handles = current.thread_group.nt_handles();
    let object = sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, 0x8000_0001);
    let Some(handle) = handles.insert(object, access) else {
        return STATUS_NO_MEMORY;
    };
    if uaccess::put_user_u64(call.args.a1, u64::from(handle.raw())).is_err() {
        let _ = handles.close(handle);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn open_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    if call.service == NtService::NtOpenKeyEx && crate::nt_ulong::ulong(call.args.a3) != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(access) = crate::nt_access::KEY.grant(crate::nt_ulong::ulong(call.args.a1) as u32) else { return STATUS_ACCESS_DENIED; };
    let (root, relative, name) = match key_name(call.args.a2, &current) { Ok(parts) => parts, Err(status) => return status };
    let request = if let Some(handle) = relative { frame_relative(registry_wire::OPEN_RELATIVE, handle, &name) } else { frame_root(registry_wire::OPEN, root, &name) };
    let Some(reply) = transact(&request) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Handle(remote) = reply else { return reply_status(reply); };
    let handles = current.thread_group.nt_handles();
    let Some(native) = handles.insert(sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, remote), access) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u64(call.args.a0, u64::from(native.raw())).is_err() { let _ = handles.close(native); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn create_key(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0 || crate::nt_ulong::ulong(call.args.a5) != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(access) = crate::nt_access::KEY.grant(crate::nt_ulong::ulong(call.args.a1) as u32) else { return STATUS_ACCESS_DENIED; };
    let (root, relative, name) = match key_name(call.args.a2, &current) { Ok(parts) => parts, Err(status) => return status };
    let request = if let Some(handle) = relative { frame_relative(registry_wire::CREATE_RELATIVE, handle, &name) } else { frame_root(registry_wire::CREATE, root, &name) };
    let Some(reply) = transact(&request) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Handle(remote) = reply else { return reply_status(reply); };
    let handles = current.thread_group.nt_handles();
    let Some(native) = handles.insert(sched::nt_object::NtObject::new(sched::nt_object::NtObjectType::Key, remote), access) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u64(call.args.a0, u64::from(native.raw())).is_err() { let _ = handles.close(native); return STATUS_INVALID_PARAMETER; }
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

/// Query one Image File Execution Options value through the canonical registry owner.
pub(crate) fn query_ifeo_option(image: &str, value: &str) -> Result<Option<(u32, Vec<u8>)>, u64> {
    let path = alloc::format!("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{image}");
    let reply = transact(&frame_root(registry_wire::OPEN, 0, &path)).ok_or(STATUS_UNSUCCESSFUL)?;
    let handle = match reply {
        Reply::Handle(handle) => handle,
        Reply::Failure(2 | 3) => return Ok(None),
        other => return Err(reply_status(other)),
    };
    let result = match transact(&frame_query(handle, value)) {
        Some(Reply::Value { kind, data }) => Ok(Some((kind, data))),
        Some(Reply::Failure(2 | 3)) => Ok(None),
        Some(other) => Err(reply_status(other)),
        None => Err(STATUS_UNSUCCESSFUL),
    };
    close_remote(handle);
    result
}

fn frame_set(key: u64, name: &str, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(registry_wire::SET); frame.extend_from_slice(&key.to_le_bytes()); put_text(&mut frame, name); frame.extend_from_slice(&kind.to_le_bytes()); put_bytes(&mut frame, data); frame
}

fn frame_delete_value(key: u64, name: &str) -> Vec<u8> {
    let mut frame = Vec::new(); frame.push(registry_wire::DELETE_VALUE); frame.extend_from_slice(&key.to_le_bytes()); put_text(&mut frame, name); frame
}

fn frame_delete_key(key: u64) -> Vec<u8> { frame_key(registry_wire::DELETE_KEY, key) }

fn frame_key(operation: u8, key: u64) -> Vec<u8> { let mut frame = Vec::new(); frame.push(operation); frame.extend_from_slice(&key.to_le_bytes()); frame }

fn frame_save_hive(key: u64) -> Vec<u8> { frame_key(registry_wire::SAVE_HIVE, key) }

fn frame_load_hive(root: u8, parent: Option<u64>, name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    match parent {
        Some(key) => { frame.push(registry_wire::LOAD_HIVE_RELATIVE); frame.extend_from_slice(&key.to_le_bytes()); }
        None => { frame.push(registry_wire::LOAD_HIVE_ROOT); frame.push(root); }
    }
    put_text(&mut frame, name); put_bytes(&mut frame, bytes); frame
}

fn put_text(frame: &mut Vec<u8>, text: &str) { put_bytes(frame, text.as_bytes()); }
fn put_bytes(frame: &mut Vec<u8>, bytes: &[u8]) { frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); frame.extend_from_slice(bytes); }

/// Exchange one framed request over the process-owned registry endpoint that
/// the launcher admitted at exec. The exchange holds the process registry
/// mutant so concurrent NT threads cannot interleave frames on the one shared
/// connection.
fn transact(frame: &[u8]) -> Option<Reply> {
    let current = sched::live::current()?;
    let file = current.thread_group.nt_registry_endpoint()?;
    let socket = crate::net_common::inode_as_inet_socket(file.inode())?;
    let _exchange = RegistryExchange::acquire(&current)?;
    let frame_len = (frame.len() as u32).to_le_bytes(); write_all(&socket, &frame_len)?; write_all(&socket, frame)?;
    let mut length = [0u8; 4]; read_exact(&socket, &mut length)?; let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > registry_wire::MAX_FRAME { return None; }
    let mut response = Vec::new(); response.try_reserve_exact(length).ok()?; response.resize(length, 0); read_exact(&socket, &mut response)?;
    decode_reply(&response)
}

/// Held ownership of the process registry connection for one exchange.
struct RegistryExchange { group: Arc<sched::thread_group::ThreadGroup>, tid: u64 }

impl RegistryExchange {
    /// Acquire the shared connection, waiting for a peer thread's exchange.
    fn acquire(current: &sched::Task) -> Option<Self> {
        let tid = current.tid as u64;
        let group = Arc::clone(&current.thread_group);
        loop {
            if group.nt_registry_lock.try_acquire(tid) { return Some(Self { group, tid }); }
            // SAFETY: process context, and the thread group holding this
            // mutant is kept alive by the cloned reference above.
            match unsafe { group.nt_registry_lock.wait(tid, u64::MAX, timekeeper::monotonic_ns) } {
                sched::WaitOutcome::Interrupted => return None,
                _ => continue,
            }
        }
    }
}

impl Drop for RegistryExchange {
    fn drop(&mut self) { let _ = self.group.nt_registry_lock.release(self.tid); }
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
        registry_wire::RESPONSE_BYTES => { let length = u32::from_le_bytes(frame.get(1..5)?.try_into().ok()?) as usize; if length > MAX_REGISTRY_VALUE || frame.len() != 5 + length { return None; } Some(Reply::Bytes(frame[5..].to_vec())) },
        registry_wire::RESPONSE_TEXT => { let length = u32::from_le_bytes(frame.get(1..5)?.try_into().ok()?) as usize; if length > MAX_REGISTRY_TEXT || frame.len() != 5 + length { return None; } Some(Reply::Text(String::from_utf8(frame[5..].to_vec()).ok()?)) },
        registry_wire::RESPONSE_SUBSCRIPTION if frame.len() == 9 => Some(Reply::Subscription(u64::from_le_bytes(frame[1..9].try_into().ok()?))),
        registry_wire::RESPONSE_NOTIFICATION if frame.len() == 1 => Some(Reply::Notification),
        registry_wire::RESPONSE_FAILURE if frame.len() == 2 => Some(Reply::Failure(frame[1])),
        _ => None,
    }
}

fn flush_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let key = match crate::nt_registry_policy::flush_handle(call.args.a0) { Ok(key) => key, Err(status) => return status };
    let Some(remote) = remote_key(&current, key, 0) else { return STATUS_INVALID_HANDLE; };
    match transact(&frame_key(registry_wire::FLUSH, remote)) { Some(Reply::Success) => STATUS_SUCCESS, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
}

fn save_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(key) = remote_key(&current, call.args.a0 as u32, KEY_QUERY_VALUE) else {
        return STATUS_INVALID_HANDLE;
    };
    let file_handle = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
    let table = current.thread_group.nt_handles();
    let Some(file_object) = table.get(file_handle, FILE_WRITE_DATA) else {
        return if table.contains(file_handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    if file_object.kind() != sched::nt_object::NtObjectType::File { return STATUS_INVALID_HANDLE; }
    let Some(file) = file_object.file() else { return STATUS_INVALID_HANDLE; };
    let Some(Reply::Bytes(bytes)) = transact(&frame_save_hive(key)) else { return STATUS_UNSUCCESSFUL; };
    crate::nt_file::write_registry_hive(&file, &bytes)
}

fn load_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let (root, relative, name) = match key_name(call.args.a0, &current) { Ok(parts) => parts, Err(status) => return status };
    let bytes = match crate::nt_file::read_registry_hive(&current, call.args.a1) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    match transact(&frame_load_hive(root, relative, &name, &bytes)) {
        Some(Reply::Success) => STATUS_SUCCESS,
        Some(reply) => reply_status(reply),
        None => STATUS_UNSUCCESSFUL,
    }
}

fn query_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let class = crate::nt_ulong::ulong(call.args.a1) as u64; let info = call.args.a2;
    let length = crate::nt_ulong::ulong(call.args.a3) as u64; let result = call.args.a4;
    if !current.is_nt_personality() || info == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(class) = crate::nt_registry_reply::KeyClass::from_raw(class) else { return STATUS_INVALID_PARAMETER; };
    let remote = match remote_key_checked(&current, key, 0) { Ok(key) => key, Err(status) => return status };
    let Some(Reply::KeyInfo { name, subkeys, max_subkey, values, max_value_name, max_value_data }) = transact(&frame_key(registry_wire::QUERY_KEY, remote)) else { return STATUS_UNSUCCESSFUL; };
    let units: Vec<u16> = name.encode_utf16().collect();
    let facts = crate::nt_registry_reply::KeyFacts { subkeys, max_subkey, values, max_value_name, max_value_data };
    let record = crate::nt_registry_reply::key_record(class, &units, facts);
    write_reply(&record, info, length, result, crate::nt_registry_reply::Ladder::HeaderIsMandatory)
}

fn enumerate_value_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let index = crate::nt_ulong::ulong(call.args.a1) as u64;
    let class = crate::nt_ulong::ulong(call.args.a2) as u64;
    let info = call.args.a3; let length = crate::nt_ulong::ulong(call.args.a4) as u64; let result = call.args.a5;
    if !current.is_nt_personality() || info == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(class) = crate::nt_registry_reply::ValueClass::from_raw(class) else { return STATUS_INVALID_PARAMETER; };
    let remote = match remote_key_checked(&current, key, KEY_QUERY_VALUE) { Ok(key) => key, Err(status) => return status };
    let mut frame = Vec::new(); frame.push(registry_wire::ENUM_VALUES); frame.extend_from_slice(&remote.to_le_bytes());
    let Some(Reply::Values(values)) = transact(&frame) else { return STATUS_UNSUCCESSFUL; };
    let Some((name, kind, data)) = values.get(index as usize) else { return STATUS_NO_MORE_ENTRIES; };
    let units: Vec<u16> = name.encode_utf16().collect();
    let Some(record) = crate::nt_registry_reply::value_enum_record(class, &units, *kind, data) else { return STATUS_INVALID_PARAMETER; };
    write_reply(&record, info, length, result, crate::nt_registry_reply::Ladder::OverflowOnly)
}

fn enumerate_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let key = call.args.a0 as u32; let index = crate::nt_ulong::ulong(call.args.a1) as u64;
    let class = crate::nt_ulong::ulong(call.args.a2) as u64; let info = call.args.a3;
    let length = crate::nt_ulong::ulong(call.args.a4) as u64; let result = call.args.a5;
    if !current.is_nt_personality() || info == 0 { return STATUS_INVALID_PARAMETER; }
    // The service that queries a key by handle reaches the same enumeration
    // with this index; as an enumeration index it is past every subkey.
    if index == u32::MAX as u64 { return STATUS_NO_MORE_ENTRIES; }
    let Some(class) = crate::nt_registry_reply::KeyClass::from_raw(class) else { return STATUS_INVALID_PARAMETER; };
    let remote = match remote_key_checked(&current, key, KEY_ENUMERATE_SUB_KEYS) { Ok(key) => key, Err(status) => return status };
    let mut frame = Vec::new(); frame.push(registry_wire::ENUM_KEYS); frame.extend_from_slice(&remote.to_le_bytes());
    let Some(Reply::Keys(keys)) = transact(&frame) else { return STATUS_UNSUCCESSFUL; };
    let Some(child_name) = keys.get(index as usize) else { return STATUS_NO_MORE_ENTRIES; };
    let units: Vec<u16> = child_name.encode_utf16().collect();
    // Only the counting classes need the subkey's own contents; the classes
    // that just name it are answered from the enumeration reply alone.
    let facts = if class.carries_name() { crate::nt_registry_reply::KeyFacts::default() } else {
        match child_facts(remote, child_name) { Ok(facts) => facts, Err(status) => return status }
    };
    let record = crate::nt_registry_reply::key_record(class, &units, facts);
    write_reply(&record, info, length, result, crate::nt_registry_reply::Ladder::HeaderIsMandatory)
}

/// Counts of one subkey, opened for the duration of the enumeration reply.
fn child_facts(parent: u64, name: &str) -> Result<crate::nt_registry_reply::KeyFacts, u64> {
    let child = match transact(&frame_relative(registry_wire::OPEN_RELATIVE, parent, name)) {
        Some(Reply::Handle(child)) => child,
        Some(reply) => return Err(reply_status(reply)),
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    let reply = transact(&frame_key(registry_wire::QUERY_KEY, child));
    let _ = transact(&frame_key(registry_wire::CLOSE, child));
    let Some(Reply::KeyInfo { subkeys, max_subkey, values, max_value_name, max_value_data, .. }) = reply else {
        return Err(STATUS_UNSUCCESSFUL);
    };
    Ok(crate::nt_registry_reply::KeyFacts { subkeys, max_subkey, values, max_value_name, max_value_data })
}


fn query_value(call: NtCall) -> u64 { query_value_native(call) }

fn query_value_native(call: NtCall) -> u64 {
    query_value_parts(call.args.a0 as u32, call.args.a1, crate::nt_ulong::ulong(call.args.a2) as u64,
        call.args.a3, crate::nt_ulong::ulong(call.args.a4) as u64, call.args.a5)
}

fn query_value_parts(key: u32, name_ptr: u64, class: u64, info: u64, length: u64, result: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || name_ptr == 0 || info == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(units) = read_unicode_units(name_ptr) else { return STATUS_INVALID_PARAMETER; };
    // The name length is judged before the information class, so an
    // over-long name is reported as an absent value whatever was asked for.
    if units.len() * 2 > crate::nt_registry_reply::MAX_VALUE_NAME_BYTES { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let Some(class) = crate::nt_registry_reply::ValueClass::from_raw(class) else { return STATUS_INVALID_PARAMETER; };
    let Ok(name) = String::from_utf16(&units) else { return STATUS_INVALID_PARAMETER; };
    let remote = match remote_key_checked(&current, key, KEY_QUERY_VALUE) { Ok(key) => key, Err(status) => return status };
    let Some(reply) = transact(&frame_query(remote, &name)) else { return STATUS_UNSUCCESSFUL; };
    let Reply::Value { kind, data } = reply else { return reply_status(reply); };
    let record = crate::nt_registry_reply::value_query_record(class, &units, kind, &data);
    write_reply(&record, info, length, result, crate::nt_registry_reply::Ladder::HeaderIsMandatory)
}

fn set_value(call: NtCall) -> u64 { set_value_native(call) }

fn set_value_native(call: NtCall) -> u64 {
    set_value_parts(call.args.a0 as u32, call.args.a1, crate::nt_ulong::ulong(call.args.a2) as u64,
        crate::nt_ulong::ulong(call.args.a3) as u64, call.args.a4, crate::nt_ulong::ulong(call.args.a5) as u64)
}

fn delete_value_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(units) = read_unicode_units(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    // An over-long name cannot name a value that exists.
    if units.len() * 2 > crate::nt_registry_reply::MAX_VALUE_NAME_BYTES { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let remote = match remote_key_checked(&current, call.args.a0 as u32, KEY_SET_VALUE) { Ok(key) => key, Err(status) => return status };
    let Ok(name) = String::from_utf16(&units) else { return STATUS_INVALID_PARAMETER; };
    match transact(&frame_delete_value(remote, &name)) {
        Some(Reply::Success) => { notify_registry_key(remote, crate::nt_registry_policy::REG_NOTIFY_CHANGE_LAST_SET); STATUS_SUCCESS }
        Some(reply) => reply_status(reply),
        None => STATUS_UNSUCCESSFUL,
    }
}

fn delete_key_native(call: NtCall) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let remote = match remote_key_checked(&current, call.args.a0 as u32, DELETE_ACCESS) { Ok(key) => key, Err(status) => return status };
    match transact(&frame_delete_key(remote)) { Some(Reply::Success) => STATUS_SUCCESS, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
}

fn set_value_parts(key: u32, name_ptr: u64, title: u64, kind: u64, data: u64, size: u64) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || name_ptr == 0 || title != 0 || size > MAX_REGISTRY_VALUE as u64 || size != 0 && data == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(units) = read_unicode_units(name_ptr) else { return STATUS_INVALID_PARAMETER; };
    // A name this service cannot store is a caller error, not a missing value.
    if units.len() * 2 > crate::nt_registry_reply::MAX_VALUE_NAME_BYTES { return STATUS_INVALID_PARAMETER; }
    let remote = match remote_key_checked(&current, key, KEY_SET_VALUE) { Ok(key) => key, Err(status) => return status };
    let Ok(name) = String::from_utf16(&units) else { return STATUS_INVALID_PARAMETER; };
    let mut bytes = Vec::new(); if bytes.try_reserve_exact(size as usize).is_err() { return STATUS_NO_MEMORY; } bytes.resize(size as usize, 0);
    if size != 0 && uaccess::copy_from_user(&mut bytes, data).is_err() { return STATUS_ACCESS_VIOLATION; }
    match transact(&frame_set(remote, &name, kind as u32, &bytes)) { Some(Reply::Success) => { notify_registry_key(remote, crate::nt_registry_policy::REG_NOTIFY_CHANGE_LAST_SET); STATUS_SUCCESS }, Some(reply) => reply_status(reply), None => STATUS_UNSUCCESSFUL }
}

fn reply_status(reply: Reply) -> u64 {
    match reply {
        Reply::Failure(1 | 4) => STATUS_INVALID_PARAMETER,
        Reply::Failure(2 | 3) => STATUS_OBJECT_NAME_NOT_FOUND,
        Reply::Failure(6) => 0xc000_017b,
        Reply::Failure(_) => STATUS_UNSUCCESSFUL,
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// Resolve one key handle, distinguishing the three ways it can fail: no such
/// handle, a handle to something that is not a key, and a key the caller did
/// not open for the right this request needs.
fn remote_key_checked(current: &sched::Task, raw: u32, access: u32) -> Result<u64, u64> {
    let table = current.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(handle, 0) else { return Err(STATUS_INVALID_HANDLE); };
    if object.kind() != sched::nt_object::NtObjectType::Key { return Err(STATUS_OBJECT_TYPE_MISMATCH); }
    if table.get(handle, access).is_none() { return Err(STATUS_ACCESS_DENIED); }
    Ok(object.id())
}

fn remote_key(current: &sched::Task, raw: u32, access: u32) -> Option<u64> {
    remote_key_checked(current, raw, access).ok()
}

fn key_name(attributes: u64, current: &sched::Task) -> Result<(u8, Option<u64>, String), u64> {
    let mut bytes = [0u8; 48];
    if uaccess::copy_from_user(&mut bytes, attributes).is_err() { return Err(STATUS_ACCESS_VIOLATION); }
    let Ok(length) = bytes[0..4].try_into().map(u32::from_le_bytes) else { return Err(STATUS_INVALID_PARAMETER); };
    if (length as usize) < bytes.len() { return Err(STATUS_INVALID_PARAMETER); }
    let Ok(root) = bytes[8..16].try_into().map(u64::from_le_bytes) else { return Err(STATUS_INVALID_PARAMETER); };
    let Ok(object_name) = bytes[16..24].try_into().map(u64::from_le_bytes) else { return Err(STATUS_INVALID_PARAMETER); };
    let Some(name) = read_unicode(object_name) else { return Err(STATUS_INVALID_PARAMETER); };
    if root == 0 {
        let (hive, within) = crate::nt_registry_path::classify_absolute(&name)?;
        return Ok((hive, None, within));
    }
    let Some(remote) = remote_key(current, root as u32, 0) else { return Err(STATUS_INVALID_HANDLE); };
    Ok((crate::nt_registry_path::ROOT_MACHINE, Some(remote), crate::nt_registry_path::classify_relative(&name)?))
}

fn read_unicode(address: u64) -> Option<String> { String::from_utf16(&read_unicode_units(address)?).ok() }

/// Read one counted Unicode string as the code units the caller supplied, so
/// a reply that echoes the name back reproduces it exactly.
fn read_unicode_units(address: u64) -> Option<Vec<u16>> {
    if address == 0 { return None; }
    let mut descriptor = [0u8; 16]; uaccess::copy_from_user(&mut descriptor, address).ok()?;
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let maximum = u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().ok()?);
    if length > maximum || length & 1 != 0 || length > MAX_REGISTRY_TEXT * 2 || length != 0 && buffer == 0 { return None; }
    let mut bytes = Vec::new(); bytes.try_reserve_exact(length).ok()?; bytes.resize(length, 0);
    if length != 0 { uaccess::copy_from_user(&mut bytes, buffer).ok()?; }
    Some(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

/// Report one completed reply record to the caller: the length it needed, the
/// prefix that fits, and the status its buffer earned.
fn write_reply(record: &crate::nt_registry_reply::Record, info: u64, length: u64, result: u64,
    ladder: crate::nt_registry_reply::Ladder) -> u64 {
    let Ok(required) = u32::try_from(record.result_len()) else { return STATUS_UNSUCCESSFUL; };
    if result != 0 && uaccess::put_user_u32(result, required).is_err() { return STATUS_INVALID_PARAMETER; }
    let delivery = crate::nt_registry_reply::deliver(record, length as usize, ladder);
    if delivery.prefix != 0 && uaccess::copy_to_user(info, &record.bytes()[..delivery.prefix]).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    delivery.status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_request_targets_the_canonical_registry_owner() {
        assert_eq!(frame_save_hive(0x1122_3344_5566_7788), [registry_wire::SAVE_HIVE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn exported_hive_reply_is_bounded_and_decoded_without_copying_a_claimed_tail() {
        let payload = b"OXHIVE\0\x01payload";
        let mut reply = vec![registry_wire::RESPONSE_BYTES];
        reply.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        reply.extend_from_slice(payload);
        assert!(matches!(decode_reply(&reply), Some(Reply::Bytes(bytes)) if bytes == payload));

        let mut malformed = reply.clone();
        malformed[1..5].copy_from_slice(&((payload.len() as u32) - 1).to_le_bytes());
        assert!(decode_reply(&malformed).is_none());
    }

    #[test]
    fn reply_decoder_rejects_truncation_and_trailing_bytes() {
        let mut value = vec![registry_wire::RESPONSE_VALUE];
        value.extend_from_slice(&4u32.to_le_bytes());
        value.extend_from_slice(&8u32.to_le_bytes());
        value.extend_from_slice(b"data");
        assert!(decode_reply(&value).is_none());

        let mut success = vec![registry_wire::RESPONSE_SUCCESS, 0];
        assert!(decode_reply(&success).is_none());
        success.clear();
        success.push(registry_wire::RESPONSE_SUCCESS);
        success.push(0);
        assert!(decode_reply(&success).is_none());
    }

    #[test]
    fn reply_decoder_rejects_oversized_and_invalid_key_lists() {
        let mut keys = vec![registry_wire::RESPONSE_KEYS];
        keys.extend_from_slice(&(1u32 << 20 + 1).to_le_bytes());
        assert!(decode_reply(&keys).is_none());

        let mut keys = vec![registry_wire::RESPONSE_KEYS];
        keys.extend_from_slice(&1u32.to_le_bytes());
        keys.extend_from_slice(&2u32.to_le_bytes());
        keys.extend_from_slice(&[b'x']);
        assert!(decode_reply(&keys).is_none());
    }

    #[test]
    fn registry_frames_encode_lengths_and_handles_little_endian() {
        assert_eq!(frame_key(registry_wire::FLUSH, 0x0102_0304_0506_0708),
            [registry_wire::FLUSH, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(frame_set(9, "Name", 4, &[1, 2]),
            [registry_wire::SET, 9, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
                4, 0, 0, 0, b'N', b'a', b'm', b'e', 2, 0, 0, 0, 1, 2]);
    }
}
