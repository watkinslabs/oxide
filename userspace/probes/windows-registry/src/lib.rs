//! One userspace owner for the Windows registry namespace.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use syscall::registry_wire;

mod client;
mod advapi;
pub use client::Client;
pub use advapi::Advapi;

const MAGIC: &[u8; 8] = b"OXREG\0\x01\0";
const SUBTREE_MAGIC: &[u8; 8] = b"OXHIVE\0\x01";
const MAX_RECORDS: u32 = 1 << 20;
const MAX_BYTES: u32 = 1 << 24;
const MAX_FRAME: usize = registry_wire::MAX_FRAME;

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Root { LocalMachine, CurrentUser, Classes }

pub const HKEY_LOCAL_MACHINE: u64 = 0x8000_0000;
pub const HKEY_CURRENT_USER: u64 = 0x8000_0001;
pub const HKEY_CLASSES_ROOT: u64 = 0x8000_0002;

impl Root {
    fn name(self) -> &'static str {
        match self { Self::LocalMachine => "HKLM", Self::CurrentUser => "HKCU", Self::Classes => "HKCR" }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ValueType { None = 0, String = 1, ExpandString = 2, Binary = 3, Dword = 4, MultiString = 7, Qword = 11 }

impl ValueType {
    fn decode(raw: u32) -> Option<Self> {
        Some(match raw { 0 => Self::None, 1 => Self::String, 2 => Self::ExpandString, 3 => Self::Binary, 4 => Self::Dword, 7 => Self::MultiString, 11 => Self::Qword, _ => return None })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Value { pub kind: ValueType, pub data: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyInfo { pub name: String, pub subkeys: u32, pub max_subkey: u32, pub values: u32, pub max_value_name: u32, pub max_value_data: u32 }

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyHandle(u64);

impl KeyHandle {
    pub const fn raw(self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key { pub path: String, values: BTreeMap<String, (String, Value)> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error { InvalidPath, MissingKey, MissingValue, InvalidFile, Io(String), Deleted }

impl From<io::Error> for Error { fn from(error: io::Error) -> Self { Self::Io(error.to_string()) } }

/// Canonical userspace registry database. Key identity is case-insensitive;
/// display spelling is retained for enumeration and persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registry { keys: BTreeMap<String, Key>, handles: BTreeMap<KeyHandle, String>, deleted: BTreeSet<KeyHandle>, next_handle: u64 }

/// One runtime/user registry session backed by one Linux file.
pub struct RegistryStore { registry: Registry, path: PathBuf, _lock: File, dirty: bool, subscriptions: BTreeMap<u64, Subscription>, next_subscription: u64 }

#[derive(Clone, Debug, Eq, PartialEq)]
struct Subscription { key: KeyHandle, filter: u64, subtree: bool, pending: bool }

#[derive(Debug)]
pub enum Request {
    Open { root: Root, subkey: String },
    Create { root: Root, subkey: String },
    OpenRelative { key: KeyHandle, subkey: String },
    CreateRelative { key: KeyHandle, subkey: String },
    Rename { key: KeyHandle, name: String },
    Set { key: KeyHandle, name: String, value: Value },
    DeleteValue { key: KeyHandle, name: String },
    DeleteKey { key: KeyHandle },
    Query { key: KeyHandle, name: String },
    EnumKeys { key: KeyHandle },
    EnumValues { key: KeyHandle },
    QueryKey { key: KeyHandle },
    Close { key: KeyHandle },
    Flush { key: KeyHandle },
    Export { key: KeyHandle },
    Import { key: KeyHandle, bytes: Vec<u8> },
    QueryPath { key: KeyHandle },
    Subscribe { key: KeyHandle, filter: u64, subtree: bool },
    PollSubscription { subscription: u64 },
    Unsubscribe { subscription: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response { Handle(KeyHandle), Value(Value), Keys(Vec<String>), Values(Vec<(String, Value)>), KeyInfo(KeyInfo), Bytes(Vec<u8>), Text(String), Subscription(u64), Notification, Success, Failure(Error) }

impl RegistryStore {
    /// Load an existing per-user database or create a new one when absent. # C: O(file bytes)
    pub fn open(path: &Path) -> Result<Self, Error> {
        let lock_path = path.with_extension("oxide-registry.lock");
        let lock = OpenOptions::new().read(true).write(true).create(true).open(lock_path)?;
        let fd = lock.as_raw_fd();
        // SAFETY: the descriptor belongs to the live sidecar File and remains open for the session.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 { return Err(io::Error::last_os_error().into()); }
        let registry = if path.exists() { Registry::load(path)? } else { Registry::new() };
        Ok(Self { registry, path: path.to_path_buf(), _lock: lock, dirty: false, subscriptions: BTreeMap::new(), next_subscription: 1 })
    }

    /// Borrow the live canonical registry session. # C: O(1)
    pub fn registry(&self) -> &Registry { &self.registry }

    /// Borrow the live registry and mark the session dirty. # C: O(1)
    pub fn registry_mut(&mut self) -> &mut Registry { self.dirty = true; &mut self.registry }

    /// Persist changes atomically; unchanged sessions do no I/O. # C: O(N_values)
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.dirty { self.registry.save(&self.path)?; self.dirty = false; } Ok(())
    }

    /// Return whether the session has unflushed mutations. # C: O(1)
    pub fn is_dirty(&self) -> bool { self.dirty }

    /// Execute one typed registry operation against this session. # C: O(depth log N)
    pub fn execute(&mut self, request: Request) -> Response {
        match request {
            Request::Open { root, subkey } => self.registry.open_handle(root, &subkey).map_or_else(Response::Failure, Response::Handle),
            Request::Create { root, subkey } => self.registry.create_handle(root, &subkey).map_or_else(Response::Failure, |handle| { self.dirty = true; Response::Handle(handle) }),
            Request::OpenRelative { key, subkey } => self.registry.open_relative_handle(key, &subkey).map_or_else(Response::Failure, Response::Handle),
            Request::CreateRelative { key, subkey } => self.registry.create_relative_handle(key, &subkey).map_or_else(Response::Failure, |handle| { self.dirty = true; Response::Handle(handle) }),
            Request::Rename { key, name } => self.registry.rename_key_handle(key, &name).map_or_else(Response::Failure, |_| { self.dirty = true; Response::Success }),
            Request::Set { key, name, value } => self.registry.set_value_handle(key, &name, value).map_or_else(Response::Failure, |_| { self.dirty = true; self.mark_changed(key); Response::Success }),
            Request::DeleteValue { key, name } => self.registry.delete_value_handle(key, &name).map_or_else(Response::Failure, |_| { self.dirty = true; self.mark_changed(key); Response::Success }),
            Request::DeleteKey { key } => self.registry.delete_key_handle(key).map_or_else(Response::Failure, |_| { self.dirty = true; Response::Success }),
            Request::Query { key, name } => self.registry.query_value_handle(key, &name).map_or_else(Response::Failure, Response::Value),
            Request::EnumKeys { key } => self.registry.subkeys_handle(key).map_or_else(Response::Failure, Response::Keys),
            Request::EnumValues { key } => self.registry.values_handle(key).map_or_else(Response::Failure, Response::Values),
            Request::QueryKey { key } => self.registry.query_key_handle(key).map_or_else(Response::Failure, Response::KeyInfo),
            Request::Close { key } => self.registry.close_handle(key).map_or_else(Response::Failure, |_| { self.subscriptions.retain(|_, state| state.key != key); Response::Success }),
            Request::Flush { key } => {
                if !self.registry.handles.contains_key(&key) { return Response::Failure(Error::MissingKey); }
                self.flush().map_or_else(|error| Response::Failure(error), |_| Response::Success)
            }
            Request::Export { key } => self.registry.export_handle(key).map_or_else(Response::Failure, Response::Bytes),
            Request::Import { key, bytes } => {
                let mut candidate = self.registry.clone();
                candidate.import_handle(key, &bytes).map_or_else(Response::Failure, |_| {
                    self.registry = candidate;
                    self.dirty = true;
                    Response::Success
                })
            }
            Request::QueryPath { key } => self.registry.path_for_handle(key).map_or_else(Response::Failure, Response::Text),
            Request::Subscribe { key, filter, subtree } => {
                if filter != crate::REG_NOTIFY_CHANGE_LAST_SET || self.registry.path_for_handle(key).is_err() { return Response::Failure(Error::InvalidPath); }
                let id = self.next_subscription; self.next_subscription = self.next_subscription.saturating_add(1);
                self.subscriptions.insert(id, Subscription { key, filter, subtree, pending: false }); Response::Subscription(id)
            }
            Request::PollSubscription { subscription } => match self.subscriptions.get(&subscription).map(|state| state.pending) {
                Some(true) => { self.subscriptions.remove(&subscription); Response::Notification }
                Some(false) => Response::Success,
                None => Response::Failure(Error::MissingKey),
            },
            Request::Unsubscribe { subscription } => if self.subscriptions.remove(&subscription).is_some() { Response::Success } else { Response::Failure(Error::MissingKey) },
        }
    }

    fn mark_changed(&mut self, key: KeyHandle) {
        let Some(changed) = self.registry.path_for_handle(key).ok().map(|path| canonical(&path)) else { return };
        for state in self.subscriptions.values_mut() {
            let Some(watched) = self.registry.path_for_handle(state.key).ok().map(|path| canonical(&path)) else { continue };
            let matches = state.key == key || state.subtree && changed.starts_with(&format!("{}\\", watched));
            if matches && state.filter & REG_NOTIFY_CHANGE_LAST_SET != 0 { state.pending = true; }
        }
    }
}

pub const REG_NOTIFY_CHANGE_LAST_SET: u64 = 0x0000_0004;

/// Serve framed registry requests over one native Linux stream. The caller
/// owns listener lifetime and chooses the per-user store.
pub fn serve_connection<S: Read + Write>(stream: &mut S, store: &mut RegistryStore) -> io::Result<()> {
    loop {
        let mut length = [0u8; 4];
        match stream.read_exact(&mut length) { Ok(()) => {}, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()), Err(error) => return Err(error) }
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME { return Err(io::Error::new(io::ErrorKind::InvalidData, "registry frame exceeds bound")); }
        let mut frame = vec![0u8; length]; stream.read_exact(&mut frame)?;
        let response = decode_request(&frame).map_or_else(Response::Failure, |request| store.execute(request));
        if store.is_dirty() {
            store.flush().map_err(|error| io::Error::new(io::ErrorKind::Other, format!("registry commit failed: {error:?}")))?;
        }
        let encoded = encode_response(&response).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "registry response exceeds bound"))?;
        if encoded.len() > u32::MAX as usize { return Err(io::Error::new(io::ErrorKind::InvalidData, "registry response too large")); }
        stream.write_all(&(encoded.len() as u32).to_le_bytes())?; stream.write_all(&encoded)?; stream.flush()?;
    }
}

fn decode_request(frame: &[u8]) -> Result<Request, Error> {
    let mut at = 0; let operation = take_u8(frame, &mut at).ok_or(Error::InvalidFile)?;
    let request = match operation {
        registry_wire::OPEN => Request::Open { root: take_root(frame, &mut at)?, subkey: take_text(frame, &mut at)? },
        registry_wire::CREATE => Request::Create { root: take_root(frame, &mut at)?, subkey: take_text(frame, &mut at)? },
        registry_wire::OPEN_RELATIVE => Request::OpenRelative { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), subkey: take_text(frame, &mut at)? },
        registry_wire::CREATE_RELATIVE => Request::CreateRelative { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), subkey: take_text(frame, &mut at)? },
        registry_wire::RENAME => Request::Rename { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), name: take_text(frame, &mut at)? },
        registry_wire::SET => Request::Set { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), name: take_text(frame, &mut at)?, value: take_value(frame, &mut at)? },
        registry_wire::DELETE_VALUE => Request::DeleteValue { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), name: take_text(frame, &mut at)? },
        registry_wire::DELETE_KEY => Request::DeleteKey { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::QUERY => Request::Query { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), name: take_text(frame, &mut at)? },
        registry_wire::CLOSE => Request::Close { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::ENUM_KEYS => Request::EnumKeys { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::ENUM_VALUES => Request::EnumValues { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::QUERY_KEY => Request::QueryKey { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::FLUSH => Request::Flush { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::EXPORT => Request::Export { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::IMPORT => Request::Import { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), bytes: take_bytes(frame, &mut at)?.to_vec() },
        registry_wire::QUERY_PATH => Request::QueryPath { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::SUBSCRIBE => Request::Subscribe { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), filter: take_u64(frame, &mut at).ok_or(Error::InvalidFile)?, subtree: take_u8(frame, &mut at).ok_or(Error::InvalidFile)? != 0 },
        registry_wire::POLL_SUBSCRIPTION => Request::PollSubscription { subscription: take_u64(frame, &mut at).ok_or(Error::InvalidFile)? },
        registry_wire::UNSUBSCRIBE => Request::Unsubscribe { subscription: take_u64(frame, &mut at).ok_or(Error::InvalidFile)? },
        _ => return Err(Error::InvalidFile),
    };
    if at == frame.len() { Ok(request) } else { Err(Error::InvalidFile) }
}

fn encode_response(response: &Response) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match response {
        Response::Success => out.push(registry_wire::RESPONSE_SUCCESS),
        Response::Handle(handle) => { out.push(registry_wire::RESPONSE_HANDLE); put_u64(&mut out, handle.raw()); },
        Response::Value(value) => { out.push(registry_wire::RESPONSE_VALUE); put_u32(&mut out, value.kind as u32); put_bytes(&mut out, &value.data)?; },
        Response::Keys(keys) => { out.push(registry_wire::RESPONSE_KEYS); put_u32(&mut out, keys.len().try_into().map_err(|_| Error::InvalidFile)?); for key in keys { put_text(&mut out, key)?; } },
        Response::Values(values) => { out.push(registry_wire::RESPONSE_VALUES); put_u32(&mut out, values.len().try_into().map_err(|_| Error::InvalidFile)?); for (name, value) in values { put_text(&mut out, name)?; put_u32(&mut out, value.kind as u32); put_bytes(&mut out, &value.data)?; } },
        Response::KeyInfo(info) => { out.push(registry_wire::RESPONSE_KEY_INFO); put_text(&mut out, &info.name)?; put_u32(&mut out, info.subkeys); put_u32(&mut out, info.max_subkey); put_u32(&mut out, info.values); put_u32(&mut out, info.max_value_name); put_u32(&mut out, info.max_value_data); },
        Response::Bytes(bytes) => { out.push(registry_wire::RESPONSE_BYTES); put_bytes(&mut out, bytes)?; },
        Response::Text(text) => { out.push(registry_wire::RESPONSE_TEXT); put_text(&mut out, text)?; },
        Response::Subscription(id) => { out.push(registry_wire::RESPONSE_SUBSCRIPTION); put_u64(&mut out, *id); },
        Response::Notification => out.push(registry_wire::RESPONSE_NOTIFICATION),
        Response::Failure(error) => { out.push(registry_wire::RESPONSE_FAILURE); out.push(error_code(error)); },
    }
    Ok(out)
}

fn take_root(bytes: &[u8], at: &mut usize) -> Result<Root, Error> {
    match take_u8(bytes, at).ok_or(Error::InvalidFile)? { 0 => Ok(Root::LocalMachine), 1 => Ok(Root::CurrentUser), 2 => Ok(Root::Classes), _ => Err(Error::InvalidFile) }
}
fn take_value(bytes: &[u8], at: &mut usize) -> Result<Value, Error> {
    let kind = ValueType::decode(take_u32(bytes, at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?;
    Ok(Value { kind, data: take_bytes(bytes, at)?.to_vec() })
}
fn take_text(bytes: &[u8], at: &mut usize) -> Result<String, Error> { String::from_utf8(take_bytes(bytes, at)?.to_vec()).map_err(|_| Error::InvalidFile) }
fn take_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], Error> { let length = take_u32(bytes, at).ok_or(Error::InvalidFile)? as usize; if length > MAX_BYTES as usize { return Err(Error::InvalidFile); } let end = at.checked_add(length).ok_or(Error::InvalidFile)?; let value = bytes.get(*at..end).ok_or(Error::InvalidFile)?; *at = end; Ok(value) }
fn take_u8(bytes: &[u8], at: &mut usize) -> Option<u8> { let value = *bytes.get(*at)?; *at += 1; Some(value) }
fn take_u32(bytes: &[u8], at: &mut usize) -> Option<u32> { let end = at.checked_add(4)?; let value = u32::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
fn take_u64(bytes: &[u8], at: &mut usize) -> Option<u64> { let end = at.checked_add(8)?; let value = u64::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn error_code(error: &Error) -> u8 { match error { Error::InvalidPath => 1, Error::MissingKey => 2, Error::MissingValue => 3, Error::InvalidFile => 4, Error::Io(_) => 5, Error::Deleted => registry_wire::ERROR_DELETED } }

impl Registry {
    /// Construct the three predefined roots. # C: O(1)
    pub fn new() -> Self {
        let mut keys = BTreeMap::new(); let mut handles = BTreeMap::new();
        for root in [Root::LocalMachine, Root::CurrentUser, Root::Classes] {
            let path = root.name().to_string();
            let identity = canonical(&path); keys.insert(identity.clone(), Key { path, values: BTreeMap::new() });
            handles.insert(KeyHandle(root_handle(root)), identity);
        }
        Self { keys, handles, deleted: BTreeSet::new(), next_handle: 0x1000 }
    }

    /// Open an existing key relative to a predefined root. # C: O(log N)
    pub fn open_key(&self, root: Root, subkey: &str) -> Result<String, Error> {
        let path = join_path(root.name(), subkey)?;
        let identity = canonical(&path);
        if root == Root::Classes { if self.classes_view_exists(&identity) { Ok(identity) } else { Err(Error::MissingKey) } }
        else if self.keys.contains_key(&identity) { Ok(identity) } else { Err(Error::MissingKey) }
    }

    /// Create all missing path components and return the canonical key handle. # C: O(depth log N)
    pub fn create_key(&mut self, root: Root, subkey: &str) -> Result<String, Error> {
        if root == Root::Classes {
            let path = join_path(root.name(), subkey)?;
            let relative = path.split_once('\\').map_or("", |(_, rest)| rest);
            let backing = classes_backing_path("HKCU", relative);
            self.create_backing_key(&backing)?;
            return Ok(canonical(&path));
        }
        let path = join_path(root.name(), subkey)?;
        let mut current = root.name().to_string();
        for component in path.split('\\').skip(1) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component);
            let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(canonical(&path))
    }

    /// Open an existing key and allocate a process-local 64-bit handle. # C: O(log N)
    pub fn open_handle(&mut self, root: Root, subkey: &str) -> Result<KeyHandle, Error> {
        let key = self.open_key(root, subkey)?; self.allocate_handle(key)
    }

    /// Create a key and allocate a process-local 64-bit handle. # C: O(depth log N)
    pub fn create_handle(&mut self, root: Root, subkey: &str) -> Result<KeyHandle, Error> {
        let key = self.create_key(root, subkey)?; self.allocate_handle(key)
    }

    /// Open a key relative to an existing opaque handle. # C: O(depth log N)
    pub fn open_relative_handle(&mut self, parent: KeyHandle, subkey: &str) -> Result<KeyHandle, Error> {
        let path = self.live_handle_path(parent)?;
        let child = canonical(&join_path(&path, subkey)?);
        if child.starts_with("HKCR\\") && self.classes_view_exists(&child) || self.keys.contains_key(&child) { self.allocate_handle(child) } else { Err(Error::MissingKey) }
    }

    /// Create a key relative to an existing opaque handle. # C: O(depth log N)
    pub fn create_relative_handle(&mut self, parent: KeyHandle, subkey: &str) -> Result<KeyHandle, Error> {
        let path = self.live_handle_path(parent)?;
        if path == "HKCR" || path.starts_with("HKCR\\") {
            let child = join_path(&path, subkey)?;
            let relative = child.split_once('\\').map_or("", |(_, rest)| rest);
            return self.create_handle(Root::Classes, relative);
        }
        let child = self.create_relative_path(&path, subkey)?; self.allocate_handle(child)
    }

    /// Rename one key and every descendant while preserving open-handle identity. # C: O(N_subtree log N)
    pub fn rename_key_handle(&mut self, key: KeyHandle, name: &str) -> Result<(), Error> {
        if name.is_empty() || name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let old = self.live_handle_path(key)?;
        if is_root(&old) { return Err(Error::InvalidPath); }
        let (parent, _) = old.rsplit_once('\\').ok_or(Error::InvalidPath)?;
        let new_path = format!("{}\\{}", parent, name); let new_identity = canonical(&new_path);
        let prefix = format!("{}\\", old);
        if self.keys.keys().any(|path| (*path == new_identity || path.starts_with(&format!("{}\\", new_identity))) && *path != old && !path.starts_with(&prefix)) { return Err(Error::InvalidPath); }
        let affected = self.keys.keys().filter(|path| **path == old || path.starts_with(&prefix)).cloned().collect::<Vec<_>>();
        for path in &affected {
            let mut key_record = self.keys.remove(path).ok_or(Error::MissingKey)?;
            let suffix = &key_record.path[old.len()..]; key_record.path = format!("{}{}", new_path, suffix);
            self.keys.insert(canonical(&key_record.path), key_record);
        }
        for handle_path in self.handles.values_mut() {
            if *handle_path == old || handle_path.starts_with(&prefix) { let suffix = &handle_path[old.len()..]; *handle_path = canonical(&format!("{}{}", new_path, suffix)); }
        }
        Ok(())
    }

    /// Return one predefined root handle without allocating a duplicate. # C: O(1)
    pub fn root_handle(root: Root) -> KeyHandle { KeyHandle(root_handle(root)) }

    /// Set a value through an opaque key handle. # C: O(log N)
    pub fn set_value_handle(&mut self, key: KeyHandle, name: &str, value: Value) -> Result<(), Error> {
        let path = self.live_handle_path(key)?; self.set_value(&path, name, value)
    }

    /// Delete one value through an opaque key handle. # C: O(log N)
    pub fn delete_value_handle(&mut self, key: KeyHandle, name: &str) -> Result<(), Error> {
        let path = self.live_handle_path(key)?; self.delete_value(&path, name)
    }

    /// Delete one leaf key through an opaque handle. # C: O(N_subkeys)
    pub fn delete_key_handle(&mut self, key: KeyHandle) -> Result<(), Error> {
        if self.deleted.contains(&key) { return Ok(()); }
        let path = self.handles.get(&key).cloned().ok_or(Error::MissingKey)?;
        if is_root(&path) || !self.subkeys(&path)?.is_empty() { return Err(Error::InvalidPath); }
        let backing = if path.starts_with("HKCR\\") { classes_backing_path("HKCU", path.strip_prefix("HKCR\\").unwrap_or("")) } else { path.clone() };
        self.keys.remove(&canonical(&backing)).ok_or(Error::MissingKey)?;
        self.deleted.insert(key);
        Ok(())
    }

    /// Query a value through an opaque key handle. # C: O(log N)
    pub fn query_value_handle(&self, key: KeyHandle, name: &str) -> Result<Value, Error> {
        let path = self.live_handle_path(key)?; self.query_value(&path, name)
    }

    /// Enumerate child keys through an opaque key handle. # C: O(N_keys)
    pub fn subkeys_handle(&self, key: KeyHandle) -> Result<Vec<String>, Error> {
        let path = self.live_handle_path(key)?; self.subkeys(&path)
    }

    /// Enumerate values through an opaque key handle in stable display order. # C: O(N_values)
    pub fn values_handle(&self, key: KeyHandle) -> Result<Vec<(String, Value)>, Error> {
        let path = self.handles.get(&key).ok_or(Error::MissingKey)?;
        if path == "HKCR" || path.starts_with("HKCR\\") { return self.classes_values(path); }
        let values = &self.keys.get(path).ok_or(Error::MissingKey)?.values;
        let mut out = values.values().map(|(name, value)| (name.clone(), value.clone())).collect::<Vec<_>>();
        out.sort_by_key(|(name, _)| canonical(name)); Ok(out)
    }

    /// Return key metadata from the canonical registry tree. # C: O(N_values)
    pub fn query_key_handle(&self, key: KeyHandle) -> Result<KeyInfo, Error> {
        let path = self.live_handle_path(key)?;
        let subkeys = self.subkeys(&path)?; let values = self.values_handle(key)?;
        let max_subkey = subkeys.iter().map(|name| name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_value_name = values.iter().map(|(name, _)| name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_value_data = values.iter().map(|(_, value)| value.data.len()).max().unwrap_or(0);
        Ok(KeyInfo { name: path.clone(), subkeys: subkeys.len() as u32, max_subkey: max_subkey as u32, values: values.len() as u32, max_value_name: max_value_name as u32, max_value_data: max_value_data as u32 })
    }

    /// Return the canonical display path retained by the registry owner. # C: O(log N)
    pub fn path_for_handle(&self, key: KeyHandle) -> Result<String, Error> {
        let path = self.live_handle_path(key)?;
        if path == "HKCR" || path.starts_with("HKCR\\") { if self.classes_view_exists(&path) { return Ok(path); } return Err(Error::Deleted); }
        Ok(self.keys.get(&path).ok_or(Error::Deleted)?.path.clone())
    }

    /// Close one allocated handle; predefined roots remain valid. # C: O(log N)
    pub fn close_handle(&mut self, key: KeyHandle) -> Result<(), Error> {
        if matches!(key.0, HKEY_LOCAL_MACHINE | HKEY_CURRENT_USER | HKEY_CLASSES_ROOT) { return Err(Error::InvalidPath); }
        if self.deleted.remove(&key) { self.handles.remove(&key); return Ok(()); }
        if self.handles.remove(&key).is_some() { Ok(()) } else { Err(Error::MissingKey) }
    }

    fn live_handle_path(&self, key: KeyHandle) -> Result<String, Error> {
        if self.deleted.contains(&key) { return Err(Error::Deleted); }
        self.handles.get(&key).cloned().ok_or(Error::MissingKey)
    }

    fn allocate_handle(&mut self, path: String) -> Result<KeyHandle, Error> {
        let handle = KeyHandle(self.next_handle); self.next_handle = self.next_handle.checked_add(1).ok_or(Error::InvalidFile)?;
        self.handles.insert(handle, path); Ok(handle)
    }

    fn create_relative_path(&mut self, parent: &str, subkey: &str) -> Result<String, Error> {
        let display_parent = self.keys.get(parent).ok_or(Error::MissingKey)?.path.clone();
        let path = join_path(&display_parent, subkey)?; let mut current = display_parent;
        for component in path.split('\\').skip(parent.split('\\').count()) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component); let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(canonical(&path))
    }

    fn create_backing_key(&mut self, path: &str) -> Result<(), Error> {
        let root = path.split_once('\\').map_or(path, |(root, _)| root);
        let mut current = root.to_string();
        for component in path.split('\\').skip(1) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component); let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(())
    }

    fn classes_view_exists(&self, path: &str) -> bool {
        if path == "HKCR" { return true; }
        let relative = path.strip_prefix("HKCR\\").unwrap_or("");
        ["HKCU", "HKLM"].iter().any(|root| self.keys.contains_key(&canonical(&classes_backing_path(root, relative))))
    }

    fn classes_subkeys(&self, key: &str) -> Result<Vec<String>, Error> {
        if !self.classes_view_exists(key) { return Err(Error::MissingKey); }
        let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
        let mut names = BTreeMap::new();
        for root in ["HKCU", "HKLM"] {
            let backing = classes_backing_path(root, relative);
            if let Ok(children) = self.subkeys(&canonical(&backing)) { for child in children { names.insert(canonical(&child), child); } }
        }
        Ok(names.into_values().collect())
    }

    fn classes_values(&self, key: &str) -> Result<Vec<(String, Value)>, Error> {
        if !self.classes_view_exists(key) { return Err(Error::MissingKey); }
        let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
        let mut values = BTreeMap::new();
        for root in ["HKCU", "HKLM"] {
            let backing = classes_backing_path(root, relative);
            if let Some(key) = self.keys.get(&canonical(&backing)) { for (name, value) in key.values.values() { values.entry(canonical(name)).or_insert_with(|| (name.clone(), value.clone())); } }
        }
        Ok(values.into_values().collect())
    }

    /// Set or replace one typed value. # C: O(log N)
    pub fn set_value(&mut self, key: &str, name: &str, value: Value) -> Result<(), Error> {
        if name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let backing = if key == "HKCR" || key.starts_with("HKCR\\") { classes_backing_path("HKCU", key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\')) } else { key.to_string() };
        let entry = self.keys.get_mut(&canonical(&backing)).ok_or(Error::MissingKey)?;
        entry.values.insert(canonical(name), (name.to_string(), value));
        Ok(())
    }

    /// Query one typed value by case-insensitive name. # C: O(log N)
    pub fn query_value(&self, key: &str, name: &str) -> Result<Value, Error> {
        if key == "HKCR" || key.starts_with("HKCR\\") {
            let relative = key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\');
            let user = classes_backing_path("HKCU", relative); let machine = classes_backing_path("HKLM", relative);
            return self.keys.get(&canonical(&user)).and_then(|key| key.values.get(&canonical(name))).or_else(|| self.keys.get(&canonical(&machine)).and_then(|key| key.values.get(&canonical(name)))).map(|(_, value)| value.clone()).ok_or(Error::MissingValue);
        }
        self.keys.get(key).ok_or(Error::MissingKey)?.values.get(&canonical(name)).map(|(_, value)| value.clone()).ok_or(Error::MissingValue)
    }

    /// Delete one value by its case-insensitive canonical name. # C: O(log N)
    pub fn delete_value(&mut self, key: &str, name: &str) -> Result<(), Error> {
        if name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let backing = if key == "HKCR" || key.starts_with("HKCR\\") { classes_backing_path("HKCU", key.strip_prefix("HKCR").unwrap_or("").trim_start_matches('\\')) } else { key.to_string() };
        let entry = self.keys.get_mut(&canonical(&backing)).ok_or(Error::MissingKey)?;
        if entry.values.remove(&canonical(name)).is_some() { Ok(()) } else { Err(Error::MissingValue) }
    }

    /// Enumerate child keys in stable display order. # C: O(N_keys)
    pub fn subkeys(&self, key: &str) -> Result<Vec<String>, Error> {
        if key == "HKCR" || key.starts_with("HKCR\\") { return self.classes_subkeys(key); }
        let parent = self.keys.get(key).ok_or(Error::MissingKey)?.path.clone();
        let prefix = format!("{}\\", parent);
        let mut out = Vec::new();
        for child in self.keys.values() {
            if child.path.starts_with(&prefix) && !child.path[prefix.len()..].contains('\\') { out.push(child.path[prefix.len()..].to_string()); }
        }
        out.sort_by_key(|name| canonical(name));
        Ok(out)
    }

    /// Persist one registry database using a bounded, versioned binary format. # C: O(N_values)
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let bytes = self.encode()?;
        let mut selected = None;
        for attempt in 0..1024u32 {
            let temp = path.with_extension(format!("oxide-registry.tmp.{}.{}", std::process::id(), attempt));
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => { selected = Some((temp, file)); break; }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let (temp, mut file) = selected.ok_or_else(|| Error::Io("registry temporary-file namespace exhausted".into()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Encode the canonical owner state for a typed hive transaction. # C: O(N_values)
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new(); bytes.extend_from_slice(MAGIC);
        let records = self.keys.values().filter(|key| !is_root(&key.path)).count() as u32;
        put_u32(&mut bytes, records);
        for key in self.keys.values().filter(|key| !is_root(&key.path)) {
            put_bytes(&mut bytes, key.path.as_bytes())?; put_u32(&mut bytes, key.values.len() as u32);
            for (display, value) in key.values.values() { put_bytes(&mut bytes, display.as_bytes())?; put_u32(&mut bytes, value.kind as u32); put_bytes(&mut bytes, &value.data)?; }
        }
        Ok(bytes)
    }

    /// Load a database, retaining predefined roots and rejecting malformed input. # C: O(file bytes)
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::decode(&fs::read(path)?)
    }

    /// Decode a complete owner snapshot before it is committed. # C: O(file bytes)
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut at = 0;
        if bytes.len() > MAX_BYTES as usize { return Err(Error::InvalidFile); }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) { return Err(Error::InvalidFile); } at += MAGIC.len();
        let records = get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?; if records > MAX_RECORDS { return Err(Error::InvalidFile); }
        let mut registry = Self::new();
        for _ in 0..records {
            let path = text(get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?)?;
            let root = persisted_root(&path).ok_or(Error::InvalidFile)?;
            let key = registry.create_key(root, path.split_once('\\').map_or("", |(_, rest)| rest))?;
            let values = get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?; if values > MAX_RECORDS { return Err(Error::InvalidFile); }
            for _ in 0..values {
                let name = text(get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?)?;
                let kind = ValueType::decode(get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?;
                let data = get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?.to_vec(); registry.set_value(&key, &name, Value { kind, data })?;
            }
        }
        if at != bytes.len() { return Err(Error::InvalidFile); } Ok(registry)
    }

    fn export_handle(&self, handle: KeyHandle) -> Result<Vec<u8>, Error> {
        let path = self.handles.get(&handle).ok_or(Error::MissingKey)?;
        let mut subset = Self::new();
        for key in self.keys.values().filter(|key| canonical(&key.path) == *path || canonical(&key.path).starts_with(&format!("{}\\", path))) {
            let root = if key.path.starts_with("HKLM") { Root::LocalMachine } else if key.path.starts_with("HKCU") { Root::CurrentUser } else { Root::Classes };
            let relative = key.path.split_once('\\').map_or("", |(_, rest)| rest);
            let target = subset.create_key(root, relative)?;
            for (display, value) in key.values.values() { subset.set_value(&target, display, value.clone())?; }
        }
        subset.keys.retain(|_, key| is_root(&key.path) || canonical(&key.path) == *path || canonical(&key.path).starts_with(&format!("{}\\", path)));
        let payload = subset.encode()?;
        let mut out = Vec::new(); out.extend_from_slice(SUBTREE_MAGIC); put_bytes(&mut out, path.as_bytes())?; out.extend_from_slice(&payload); Ok(out)
    }

    fn import_handle(&mut self, handle: KeyHandle, bytes: &[u8]) -> Result<(), Error> {
        let target = self.handles.get(&handle).cloned().ok_or(Error::MissingKey)?;
        if bytes.get(..SUBTREE_MAGIC.len()) != Some(SUBTREE_MAGIC.as_slice()) { return Err(Error::InvalidFile); }
        let mut at = SUBTREE_MAGIC.len(); let source = text(get_bytes(bytes, &mut at).ok_or(Error::InvalidFile)?)?;
        let incoming = Self::decode(bytes.get(at..).ok_or(Error::InvalidFile)?)?;
        let source_root = source.split_once('\\').map_or(source.as_str(), |(_, rest)| rest.split_once('\\').map_or(rest, |(head, _)| head));
        let target_root = target.split_once('\\').map_or(target.as_str(), |(_, rest)| rest.split_once('\\').map_or(rest, |(head, _)| head));
        if !source_root.eq_ignore_ascii_case(target_root) { return Err(Error::InvalidPath); }
        for key in incoming.keys.values() {
            let identity = canonical(&key.path);
            if is_root(&key.path) || (identity != canonical(&source) && !identity.starts_with(&format!("{}\\", canonical(&source)))) { continue; }
            let root = if target.starts_with("HKLM") { Root::LocalMachine } else if target.starts_with("HKCU") { Root::CurrentUser } else { Root::Classes };
            let source_identity = canonical(&source);
            let relative = if identity == source_identity { String::new() } else { identity.strip_prefix(&(source_identity + "\\")).ok_or(Error::InvalidPath)?.to_string() };
            let destination = relative_for_target(&target, &relative);
            let created = self.create_key(root, &destination)?;
            for (display, value) in key.values.values() { self.set_value(&created, display, value.clone())?; }
        }
        Ok(())
    }
}

fn relative_for_target(target: &str, relative: &str) -> String {
    let target = target.split_once('\\').map_or("", |(_, rest)| rest);
    if target.is_empty() { relative.to_string() } else if relative.is_empty() { target.to_string() } else { format!("{}\\{}", target, relative) }
}

fn classes_backing_path(root: &str, relative: &str) -> String {
    if relative.is_empty() { format!("{}\\Software\\Classes", root) } else { format!("{}\\Software\\Classes\\{}", root, relative) }
}

fn canonical(text: &str) -> String { text.to_ascii_uppercase() }
fn is_root(path: &str) -> bool { matches!(path, "HKLM" | "HKCU" | "HKCR") }
fn persisted_root(path: &str) -> Option<Root> {
    let (root, suffix) = path.split_once('\\').map_or((path, ""), |(root, suffix)| (root, suffix));
    if suffix.is_empty() && !is_root(root) { return None; }
    match root { "HKLM" => Some(Root::LocalMachine), "HKCU" => Some(Root::CurrentUser), "HKCR" => Some(Root::Classes), _ => None }
}
fn root_handle(root: Root) -> u64 { match root { Root::LocalMachine => HKEY_LOCAL_MACHINE, Root::CurrentUser => HKEY_CURRENT_USER, Root::Classes => HKEY_CLASSES_ROOT } }
fn join_path(root: &str, subkey: &str) -> Result<String, Error> {
    if subkey.contains('\0') || subkey.split('\\').any(str::is_empty) { return if subkey.is_empty() { Ok(root.to_string()) } else { Err(Error::InvalidPath) }; }
    if subkey.is_empty() { Ok(root.to_string()) } else { Ok(format!("{}\\{}", root, subkey)) }
}
fn text(bytes: &[u8]) -> Result<String, Error> { String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidFile) }
fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> { if bytes.len() > u32::MAX as usize { return Err(Error::InvalidFile); } put_u32(out, bytes.len() as u32); out.extend_from_slice(bytes); Ok(()) }
fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), Error> { put_bytes(out, text.as_bytes()) }
fn get_u32(bytes: &[u8], at: &mut usize) -> Option<u32> { let end = at.checked_add(4)?; let value = u32::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
fn get_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> { let len = get_u32(bytes, at)? as usize; let end = at.checked_add(len)?; let value = bytes.get(*at..end)?; *at = end; Some(value) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_store_persists_case_insensitive_keys_and_values() {
        let path = std::env::temp_dir().join(format!("oxide-registry-store-{}.db", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let key = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Oxide".into() }) { Response::Handle(key) => key, other => panic!("unexpected response: {other:?}") };
        assert_eq!(store.execute(Request::Set { key, name: "InstallPath".into(), value: Value { kind: ValueType::String, data: b"C:\\Oxide".to_vec() } }), Response::Success);
        assert_eq!(store.execute(Request::Flush { key }), Response::Success);
        drop(store);
        let mut reopened = RegistryStore::open(&path).unwrap();
        let opened = match reopened.execute(Request::Open { root: Root::CurrentUser, subkey: "software\\oxide".into() }) { Response::Handle(key) => key, other => panic!("unexpected response: {other:?}") };
        assert_eq!(reopened.execute(Request::Query { key: opened, name: "installpath".into() }), Response::Value(Value { kind: ValueType::String, data: b"C:\\Oxide".to_vec() }));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn keys_and_values_are_case_insensitive_but_preserve_display_names() {
        let mut registry = Registry::new();
        let key = registry.create_key(Root::CurrentUser, "Software\\Oxide").unwrap();
        registry.set_value(&key, "InstallPath", Value { kind: ValueType::String, data: b"C:\\Oxide".to_vec() }).unwrap();
        assert_eq!(registry.open_key(Root::CurrentUser, "software\\oxide"), Ok(key.clone()));
        assert_eq!(registry.query_value(&key, "installpath").unwrap().data, b"C:\\Oxide");
        assert_eq!(registry.subkeys(&canonical("HKCU")).unwrap(), vec!["Software"]);
    }

    #[test]
    fn rename_rebases_subtree_and_existing_handles() {
        let mut registry = Registry::new();
        let parent = registry.create_handle(Root::CurrentUser, "Software\\Old").unwrap();
        let child = registry.create_relative_handle(parent, "Child").unwrap();
        registry.set_value_handle(child, "Value", Value { kind: ValueType::Dword, data: vec![9, 0, 0, 0] }).unwrap();
        registry.rename_key_handle(parent, "New").unwrap();
        assert_eq!(registry.handles.get(&child), Some(&"HKCU\\SOFTWARE\\NEW\\CHILD".to_string()));
        assert_eq!(registry.query_value_handle(child, "value").unwrap().data, vec![9, 0, 0, 0]);
        assert_eq!(registry.open_relative_handle(parent, "Child"), Ok(KeyHandle(child.raw() + 1)));
        assert_eq!(registry.rename_key_handle(parent, "bad\\name"), Err(Error::InvalidPath));
    }

    #[test]
    fn persistence_round_trip_retains_all_typed_bytes() {
        let path = std::env::temp_dir().join(format!("oxide-registry-{}", std::process::id()));
        let mut registry = Registry::new(); let key = registry.create_key(Root::LocalMachine, "Software\\Oxide").unwrap();
        registry.set_value(&key, "Flags", Value { kind: ValueType::Dword, data: vec![1, 2, 3, 4] }).unwrap(); registry.save(&path).unwrap();
        assert_eq!(Registry::load(&path).unwrap(), registry); std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn save_skips_an_existing_process_scoped_temporary_file() {
        let path = std::env::temp_dir().join(format!("oxide-registry-temp-collision-{}", std::process::id()));
        let occupied = path.with_extension(format!("oxide-registry.tmp.{}.0", std::process::id()));
        let _ = fs::remove_file(&path); let _ = fs::remove_file(&occupied);
        File::create(&occupied).unwrap();
        let mut registry = Registry::new();
        let key = registry.create_key(Root::CurrentUser, "Software\\Oxide").unwrap();
        registry.set_value(&key, "Ready", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        registry.save(&path).unwrap();
        assert_eq!(Registry::load(&path).unwrap(), registry);
        fs::remove_file(path).unwrap(); fs::remove_file(occupied).unwrap();
    }

    #[test]
    fn persistence_retains_empty_keys_in_the_tree() {
        let path = std::env::temp_dir().join(format!("oxide-registry-empty-{}", std::process::id()));
        let mut registry = Registry::new(); let key = registry.create_key(Root::CurrentUser, "Software\\Oxide\\Empty").unwrap();
        registry.save(&path).unwrap(); let restored = Registry::load(&path).unwrap();
        assert_eq!(restored.open_key(Root::CurrentUser, "software\\oxide\\empty"), Ok(key)); std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_or_unknown_value_data_is_rejected() {
        let path = std::env::temp_dir().join(format!("oxide-registry-bad-{}", std::process::id()));
        std::fs::write(&path, b"not-a-registry").unwrap(); assert_eq!(Registry::load(&path), Err(Error::InvalidFile)); std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn handles_are_64_bit_process_local_and_predefined_roots_cannot_close() {
        let mut registry = Registry::new();
        assert_eq!(Registry::root_handle(Root::CurrentUser).raw(), HKEY_CURRENT_USER);
        let handle = registry.create_handle(Root::CurrentUser, "Software\\Oxide").unwrap();
        registry.set_value_handle(handle, "Version", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        assert_eq!(registry.query_value_handle(handle, "version").unwrap().data, vec![1, 0, 0, 0]);
        assert_eq!(registry.close_handle(handle), Ok(()));
        assert_eq!(registry.query_value_handle(handle, "version"), Err(Error::MissingKey));
        assert_eq!(registry.close_handle(Registry::root_handle(Root::CurrentUser)), Err(Error::InvalidPath));
    }

    #[test]
    fn deleting_an_open_leaf_is_idempotent_until_its_handle_closes() {
        let mut registry = Registry::new();
        let key = registry.create_handle(Root::CurrentUser, "Software\\Oxide\\DeleteMe").unwrap();
        assert_eq!(registry.delete_key_handle(key), Ok(()));
        assert_eq!(registry.delete_key_handle(key), Ok(()));
        assert_eq!(registry.open_key(Root::CurrentUser, "Software\\Oxide\\DeleteMe"), Err(Error::MissingKey));
        assert_eq!(registry.query_value_handle(key, "missing"), Err(Error::Deleted));
        assert_eq!(registry.close_handle(key), Ok(()));
        assert_eq!(registry.close_handle(key), Err(Error::MissingKey));
    }

    #[test]
    fn subtree_notification_wakes_for_descendant_value_mutation() {
        let path = std::env::temp_dir().join(format!("oxide-registry-subtree-{}.db", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let parent = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Oxide".into() }) { Response::Handle(key) => key, other => panic!("unexpected response: {other:?}") };
        let child = match store.execute(Request::CreateRelative { key: parent, subkey: "Settings".into() }) { Response::Handle(key) => key, other => panic!("unexpected response: {other:?}") };
        let subscription = match store.execute(Request::Subscribe { key: parent, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: true }) { Response::Subscription(id) => id, other => panic!("unexpected response: {other:?}") };
        assert_eq!(store.execute(Request::PollSubscription { subscription }), Response::Success);
        assert_eq!(store.execute(Request::Set { key: child, name: "Ready".into(), value: Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] } }), Response::Success);
        assert_eq!(store.execute(Request::PollSubscription { subscription }), Response::Notification);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(std::env::temp_dir().join(format!("oxide-registry-subtree-{}.oxide-registry.lock", std::process::id())));
    }

    #[test]
    fn store_loads_missing_user_state_and_flushes_one_canonical_database() {
        let path = std::env::temp_dir().join(format!("oxide-registry-missing-user-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap(); assert!(!store.is_dirty());
        let key = store.registry_mut().create_handle(Root::CurrentUser, "Software\\Oxide").unwrap();
        store.registry_mut().set_value_handle(key, "Ready", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        assert!(store.is_dirty()); store.flush().unwrap(); assert!(!store.is_dirty());
        drop(store);
        let restored = RegistryStore::open(&path).unwrap();
        let key = restored.registry().open_key(Root::CurrentUser, "software\\oxide").unwrap();
        assert_eq!(restored.registry().query_value(&key, "ready").unwrap().data, vec![1, 0, 0, 0]); std::fs::remove_file(&path).unwrap(); std::fs::remove_file(path.with_extension("oxide-registry.lock")).unwrap();
    }

    #[test]
    fn registry_session_lock_serializes_open_and_releases_on_drop() {
        use std::sync::{mpsc, Arc};
        let path = std::env::temp_dir().join(format!("oxide-registry-lock-{}", std::process::id()));
        let _ = fs::remove_file(&path); let _ = fs::remove_file(path.with_extension("oxide-registry.lock"));
        let first = RegistryStore::open(&path).unwrap();
        let lock_path = path.with_extension("oxide-registry.lock");
        let probe = OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
        // SAFETY: the probe descriptor is open for this test and remains valid for the call.
        let result = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EWOULDBLOCK));
        drop(probe);
        let (started_tx, started_rx) = mpsc::channel(); let (acquired_tx, acquired_rx) = mpsc::channel(); let shared = Arc::new(path.clone());
        let second_path = Arc::clone(&shared);
        let waiter = std::thread::spawn(move || { started_tx.send(()).unwrap(); let store = RegistryStore::open(&second_path).unwrap(); acquired_tx.send(()).unwrap(); drop(store); });
        started_rx.recv().unwrap(); assert!(acquired_rx.recv_timeout(std::time::Duration::from_millis(50)).is_err());
        drop(first); assert!(acquired_rx.recv_timeout(std::time::Duration::from_secs(1)).is_ok());
        waiter.join().unwrap(); let _ = fs::remove_file(path); let _ = fs::remove_file(shared.with_extension("oxide-registry.lock"));
    }

    #[test]
    fn registry_session_lock_preserves_committed_writes_between_contending_sessions() {
        use std::sync::{mpsc, Arc};
        let path = std::env::temp_dir().join(format!("oxide-registry-contention-{}", std::process::id()));
        let lock_path = path.with_extension("oxide-registry.lock");
        let _ = fs::remove_file(&path); let _ = fs::remove_file(&lock_path);
        let mut first = RegistryStore::open(&path).unwrap();
        let first_key = first.registry_mut().create_handle(Root::CurrentUser, r"Software\First").unwrap();
        first.registry_mut().set_value_handle(first_key, "Committed", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        first.flush().unwrap();
        let (started_tx, started_rx) = mpsc::channel(); let (done_tx, done_rx) = mpsc::channel(); let shared = Arc::new(path.clone());
        let second_path = Arc::clone(&shared);
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let mut second = RegistryStore::open(&second_path).unwrap();
            let second_key = second.registry_mut().create_handle(Root::CurrentUser, r"Software\Second").unwrap();
            second.registry_mut().set_value_handle(second_key, "Committed", Value { kind: ValueType::Dword, data: vec![2, 0, 0, 0] }).unwrap();
            second.flush().unwrap(); done_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap(); assert!(done_rx.recv_timeout(std::time::Duration::from_millis(50)).is_err());
        drop(first); done_rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(); writer.join().unwrap();
        let restored = RegistryStore::open(&path).unwrap();
        let first_key = restored.registry().open_key(Root::CurrentUser, r"software\first").unwrap();
        let second_key = restored.registry().open_key(Root::CurrentUser, r"software\second").unwrap();
        assert_eq!(restored.registry().query_value(&first_key, "committed").unwrap().data, vec![1, 0, 0, 0]);
        assert_eq!(restored.registry().query_value(&second_key, "committed").unwrap().data, vec![2, 0, 0, 0]);
        drop(restored); let _ = fs::remove_file(path); let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn failed_registry_load_releases_the_session_lock() {
        let path = std::env::temp_dir().join(format!("oxide-registry-load-failure-{}", std::process::id()));
        let lock_path = path.with_extension("oxide-registry.lock");
        let _ = fs::remove_file(&path); let _ = fs::remove_file(&lock_path);
        fs::write(&path, b"not-a-registry").unwrap();
        assert!(matches!(RegistryStore::open(&path), Err(Error::InvalidFile)));
        fs::remove_file(&path).unwrap();
        let store = RegistryStore::open(&path).unwrap();
        drop(store); let _ = fs::remove_file(path); let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn failed_commit_keeps_dirty_state_and_can_be_retried() {
        let path = std::env::temp_dir().join(format!("oxide-registry-commit-failure-{}", std::process::id()));
        let lock_path = path.with_extension("oxide-registry.lock");
        let _ = fs::remove_file(&path); let _ = fs::remove_dir(&path); let _ = fs::remove_file(&lock_path);
        let mut store = RegistryStore::open(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let key = store.registry_mut().create_handle(Root::CurrentUser, "Software\\Failure").unwrap();
        store.registry_mut().set_value_handle(key, "State", Value { kind: ValueType::Dword, data: vec![7, 0, 0, 0] }).unwrap();
        assert!(store.flush().is_err());
        assert!(store.is_dirty(), "a failed atomic replacement must not report a commit");
        fs::remove_dir(&path).unwrap(); store.flush().unwrap(); assert!(!store.is_dirty());
        drop(store);
        let restored = RegistryStore::open(&path).unwrap();
        let restored_key = restored.registry().open_key(Root::CurrentUser, "software\\failure").unwrap();
        assert_eq!(restored.registry().query_value(&restored_key, "state").unwrap().data, vec![7, 0, 0, 0]);
        drop(restored); let _ = fs::remove_file(path); let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn one_commit_durable_before_connection_loss_and_both_roots_survive_restart() {
        let path = std::env::temp_dir().join(format!("oxide-registry-connection-loss-{}", std::process::id()));
        let lock_path = path.with_extension("oxide-registry.lock");
        let _ = fs::remove_file(&path); let _ = fs::remove_file(&lock_path);
        let mut store = RegistryStore::open(&path).unwrap();
        let mut request = Vec::new(); request.push(registry_wire::CREATE); request.push(1); put_bytes(&mut request, b"Software\\UserState").unwrap();
        let framed = (request.len() as u32).to_le_bytes();
        let mut input = framed.to_vec(); input.extend_from_slice(&request);
        let mut stream = std::io::Cursor::new(input);
        serve_connection(&mut stream, &mut store).unwrap();
        drop(store);
        let mut restored = RegistryStore::open(&path).unwrap();
        let user = restored.registry().open_key(Root::CurrentUser, "software\\userstate").unwrap();
        assert!(restored.registry().open_key(Root::LocalMachine, "software\\userstate").is_err());
        let machine = restored.registry_mut().create_handle(Root::LocalMachine, "Software\\MachineState").unwrap();
        restored.registry_mut().set_value_handle(machine, "Ready", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        restored.flush().unwrap(); drop(restored);
        let final_store = RegistryStore::open(&path).unwrap();
        assert!(final_store.registry().open_key(Root::CurrentUser, "software\\userstate").is_ok());
        assert!(final_store.registry().open_key(Root::LocalMachine, "software\\machinestate").is_ok());
        drop(final_store); let _ = fs::remove_file(path); let _ = fs::remove_file(lock_path);
        let _ = user;
    }

    #[test]
    fn persisted_root_names_require_a_real_root_boundary() {
        let mut bytes = Vec::new(); bytes.extend_from_slice(MAGIC); put_u32(&mut bytes, 1);
        put_bytes(&mut bytes, b"HKLMX\\Software").unwrap(); put_u32(&mut bytes, 0);
        assert_eq!(Registry::decode(&bytes), Err(Error::InvalidFile));
    }

    #[test]
    fn classes_root_merges_user_over_machine_and_writes_user_classes() {
        let mut registry = Registry::new();
        let machine = registry.create_key(Root::LocalMachine, r"Software\Classes\Oxide").unwrap();
        registry.set_value(&machine, "Owner", Value { kind: ValueType::String, data: b"machine".to_vec() }).unwrap();
        let machine_only = registry.create_key(Root::LocalMachine, r"Software\Classes\MachineOnly").unwrap();
        registry.set_value(&machine_only, "Present", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        let user = registry.create_key(Root::CurrentUser, r"Software\Classes\Oxide").unwrap();
        registry.set_value(&user, "Owner", Value { kind: ValueType::String, data: b"user".to_vec() }).unwrap();
        let view = registry.open_handle(Root::Classes, "Oxide").unwrap();
        assert_eq!(registry.query_value_handle(view, "owner").unwrap().data, b"user");
        assert_eq!(registry.values_handle(view).unwrap(), vec![("Owner".into(), Value { kind: ValueType::String, data: b"user".to_vec() })]);
        assert_eq!(registry.subkeys(&canonical("HKCR")).unwrap(), vec!["MachineOnly", "Oxide"]);
        let value = Value { kind: ValueType::Binary, data: vec![7, 8] };
        registry.set_value_handle(view, "WrittenThroughHkcr", value.clone()).unwrap();
        assert_eq!(registry.query_value(&user, "writtenthroughhkcr"), Ok(value));
        assert_eq!(registry.query_value(&machine, "writtenthroughhkcr"), Err(Error::MissingValue));
    }

    #[test]
    fn typed_service_operations_share_one_handle_owner_and_dirty_lifecycle() {
        let path = std::env::temp_dir().join(format!("oxide-registry-service-{}", std::process::id())); let _ = std::fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let handle = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Oxide".into() }) { Response::Handle(handle) => handle, response => panic!("unexpected response: {response:?}") };
        assert!(store.is_dirty());
        assert_eq!(store.execute(Request::Set { key: handle, name: "Mode".into(), value: Value { kind: ValueType::String, data: b"test".to_vec() } }), Response::Success);
        assert_eq!(store.execute(Request::Query { key: handle, name: "mode".into() }), Response::Value(Value { kind: ValueType::String, data: b"test".to_vec() }));
        let child = match store.execute(Request::CreateRelative { key: handle, subkey: "Child".into() }) { Response::Handle(child) => child, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::EnumKeys { key: handle }), Response::Keys(vec!["Child".into()]));
        assert_eq!(store.execute(Request::DeleteKey { key: handle }), Response::Failure(Error::InvalidPath));
        assert_eq!(store.execute(Request::DeleteKey { key: child }), Response::Success);
        assert_eq!(store.execute(Request::Query { key: child, name: "mode".into() }), Response::Failure(Error::Deleted));
        assert_eq!(store.execute(Request::Close { key: child }), Response::Success);
        assert_eq!(store.execute(Request::OpenRelative { key: handle, subkey: "Child".into() }), Response::Failure(Error::MissingKey));
        assert_eq!(store.execute(Request::DeleteValue { key: handle, name: "MODE".into() }), Response::Success);
        assert_eq!(store.execute(Request::Query { key: handle, name: "mode".into() }), Response::Failure(Error::MissingValue));
        assert_eq!(store.execute(Request::DeleteValue { key: handle, name: "mode".into() }), Response::Failure(Error::MissingValue));
        assert_eq!(store.execute(Request::Close { key: handle }), Response::Success);
        assert_eq!(store.execute(Request::Query { key: handle, name: "mode".into() }), Response::Failure(Error::MissingKey));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn typed_service_enumerates_keys_and_values_in_stable_display_order() {
        let mut store = RegistryStore::open(&std::env::temp_dir().join(format!("oxide-registry-enum-{}", std::process::id()))).unwrap();
        let key = match store.execute(Request::Create { root: Root::CurrentUser, subkey: r"Software\Oxide".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        let _ = store.execute(Request::Create { root: Root::CurrentUser, subkey: r"Software\Oxide\z-child".into() });
        let _ = store.execute(Request::Create { root: Root::CurrentUser, subkey: r"Software\Oxide\A-child".into() });
        let _ = store.execute(Request::Set { key, name: "z-value".into(), value: Value { kind: ValueType::Binary, data: vec![9] } });
        let _ = store.execute(Request::Set { key, name: "A-value".into(), value: Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] } });
        assert_eq!(store.execute(Request::EnumKeys { key }), Response::Keys(vec!["A-child".into(), "z-child".into()]));
        assert_eq!(store.execute(Request::EnumValues { key }), Response::Values(vec![("A-value".into(), Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }), ("z-value".into(), Value { kind: ValueType::Binary, data: vec![9] })]));
        assert_eq!(store.execute(Request::QueryKey { key }), Response::KeyInfo(KeyInfo {
            name: "HKCU\\SOFTWARE\\OXIDE".into(), subkeys: 2, max_subkey: 14,
            values: 2, max_value_name: 14, max_value_data: 4,
        }));
    }

    #[test]
    fn framed_service_routes_binary_values_and_rejects_trailing_bytes() {
        let path = std::env::temp_dir().join(format!("oxide-registry-wire-{}", std::process::id())); let _ = std::fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let mut input = Vec::new(); input.push(2); input.push(1); put_bytes(&mut input, b"Software\\Oxide").unwrap();
        let mut bytes = (input.len() as u32).to_le_bytes().to_vec(); bytes.extend_from_slice(&input);
        let mut stream = std::io::Cursor::new(bytes); serve_connection(&mut stream, &mut store).unwrap();
        assert!(stream.get_ref().len() > input.len() + 4);
        let mut bad = input; bad.push(0); let mut bytes = (bad.len() as u32).to_le_bytes().to_vec(); bytes.extend_from_slice(&bad);
        let response_start = bytes.len(); let mut stream = std::io::Cursor::new(bytes); serve_connection(&mut stream, &mut store).unwrap();
        assert_eq!(&stream.get_ref()[response_start..], &[2, 0, 0, 0, 3, 4]);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn framed_service_rejects_bounded_length_errors_before_dispatch() {
        let path = std::env::temp_dir().join(format!("oxide-registry-frame-bound-{}", std::process::id())); let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let mut zero = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert_eq!(serve_connection(&mut zero, &mut store).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        let mut oversized = std::io::Cursor::new((MAX_FRAME as u32 + 1).to_le_bytes().to_vec());
        assert_eq!(serve_connection(&mut oversized, &mut store).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(!store.is_dirty());
        fs::remove_file(path).ok();
    }

    #[test]
    fn canonical_owner_queues_exact_or_subtree_last_set_notifications() {
        let path = std::env::temp_dir().join(format!("oxide-registry-notify-{}", std::process::id())); let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let key = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Notify".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        let child = match store.execute(Request::CreateRelative { key, subkey: "Child".into() }) { Response::Handle(child) => child, response => panic!("unexpected response: {response:?}") };
        let subscription = match store.execute(Request::Subscribe { key, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: false }) { Response::Subscription(id) => id, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::PollSubscription { subscription }), Response::Success);
        assert_eq!(store.execute(Request::Set { key: child, name: "ignored".into(), value: Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] } }), Response::Success);
        assert_eq!(store.execute(Request::PollSubscription { subscription }), Response::Success);
        assert_eq!(store.execute(Request::Set { key, name: "changed".into(), value: Value { kind: ValueType::Dword, data: vec![2, 0, 0, 0] } }), Response::Success);
        assert_eq!(store.execute(Request::PollSubscription { subscription }), Response::Notification);
        assert!(matches!(store.execute(Request::Subscribe { key, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: true }), Response::Subscription(_)));
        fs::remove_file(path).ok();
    }

    #[test]
    fn notifications_are_one_shot_and_multiple_watchers_share_a_key() {
        let path = std::env::temp_dir().join(format!("oxide-registry-notify-lifetime-{}", std::process::id())); let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let key = match store.execute(Request::Create { root: Root::CurrentUser, subkey: r"Software\Lifetime".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        let first = match store.execute(Request::Subscribe { key, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: false }) { Response::Subscription(id) => id, response => panic!("unexpected response: {response:?}") };
        let second = match store.execute(Request::Subscribe { key, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: false }) { Response::Subscription(id) => id, response => panic!("unexpected response: {response:?}") };
        assert_ne!(first, second);
        assert_eq!(store.execute(Request::Set { key, name: "Changed".into(), value: Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] } }), Response::Success);
        assert_eq!(store.execute(Request::PollSubscription { subscription: first }), Response::Notification);
        assert_eq!(store.execute(Request::PollSubscription { subscription: second }), Response::Notification);
        assert_eq!(store.execute(Request::PollSubscription { subscription: first }), Response::Failure(Error::MissingKey));
        assert_eq!(store.execute(Request::PollSubscription { subscription: second }), Response::Failure(Error::MissingKey));
        fs::remove_file(path).ok();
    }

    #[test]
    fn explicit_unsubscribe_releases_a_pending_notification() {
        let path = std::env::temp_dir().join(format!("oxide-registry-unsubscribe-{}", std::process::id())); let _ = fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let key = match store.execute(Request::Create { root: Root::CurrentUser, subkey: r"Software\Unsubscribe".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        let subscription = match store.execute(Request::Subscribe { key, filter: REG_NOTIFY_CHANGE_LAST_SET, subtree: false }) { Response::Subscription(id) => id, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::Unsubscribe { subscription }), Response::Success);
        assert_eq!(store.execute(Request::Unsubscribe { subscription }), Response::Failure(Error::MissingKey));
        fs::remove_file(path).ok();
    }

    #[test]
    fn shared_wire_contract_keeps_relative_operations_distinct() {
        assert_eq!(registry_wire::OPEN, 1);
        assert_eq!(registry_wire::CREATE, 2);
        assert_eq!(registry_wire::OPEN_RELATIVE, 8);
        assert_eq!(registry_wire::CREATE_RELATIVE, 9);
        assert_ne!(registry_wire::OPEN, registry_wire::OPEN_RELATIVE);
        assert_ne!(registry_wire::CREATE, registry_wire::CREATE_RELATIVE);
        assert_eq!(registry_wire::MAX_FRAME, 1 << 24);
    }

    #[test]
    fn hive_export_import_is_subtree_scoped_and_atomic() {
        let mut store = RegistryStore::open(&std::env::temp_dir().join(format!("oxide-registry-hive-{}", std::process::id()))).unwrap();
        let source = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Source".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        let child = match store.execute(Request::CreateRelative { key: source, subkey: "Child".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::Set { key: child, name: "Value".into(), value: Value { kind: ValueType::Binary, data: vec![1, 2, 3] } }), Response::Success);
        let bytes = match store.execute(Request::Export { key: source }) { Response::Bytes(bytes) => bytes, response => panic!("unexpected response: {response:?}") };
        let target = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Target".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::Import { key: target, bytes: bytes.clone() }), Response::Success);
        let imported = match store.execute(Request::OpenRelative { key: target, subkey: "Child".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        assert_eq!(store.execute(Request::Query { key: imported, name: "value".into() }), Response::Value(Value { kind: ValueType::Binary, data: vec![1, 2, 3] }));
        assert_eq!(store.execute(Request::Import { key: target, bytes: b"invalid".to_vec() }), Response::Failure(Error::InvalidFile));
        assert_eq!(store.execute(Request::Query { key: imported, name: "value".into() }), Response::Value(Value { kind: ValueType::Binary, data: vec![1, 2, 3] }));
    }
}
