//! One userspace owner for the Windows registry namespace.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use syscall::registry_wire;

mod client;
mod advapi;
pub use client::Client;
pub use advapi::Advapi;

const MAGIC: &[u8; 8] = b"OXREG\0\x01\0";
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

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyHandle(u64);

impl KeyHandle {
    pub const fn raw(self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key { pub path: String, values: BTreeMap<String, (String, Value)> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error { InvalidPath, MissingKey, MissingValue, InvalidFile, Io(String) }

impl From<io::Error> for Error { fn from(error: io::Error) -> Self { Self::Io(error.to_string()) } }

/// Canonical userspace registry database. Key identity is case-insensitive;
/// display spelling is retained for enumeration and persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registry { keys: BTreeMap<String, Key>, handles: BTreeMap<KeyHandle, String>, next_handle: u64 }

/// One runtime/user registry session backed by one Linux file.
pub struct RegistryStore { registry: Registry, path: PathBuf, dirty: bool }

#[derive(Debug)]
pub enum Request {
    Open { root: Root, subkey: String },
    Create { root: Root, subkey: String },
    OpenRelative { key: KeyHandle, subkey: String },
    CreateRelative { key: KeyHandle, subkey: String },
    Rename { key: KeyHandle, name: String },
    Set { key: KeyHandle, name: String, value: Value },
    Query { key: KeyHandle, name: String },
    EnumKeys { key: KeyHandle },
    EnumValues { key: KeyHandle },
    Close { key: KeyHandle },
    Flush { key: KeyHandle },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response { Handle(KeyHandle), Value(Value), Keys(Vec<String>), Values(Vec<(String, Value)>), Success, Failure(Error) }

impl RegistryStore {
    /// Load an existing per-user database or create a new one when absent. # C: O(file bytes)
    pub fn open(path: &Path) -> Result<Self, Error> {
        let registry = if path.exists() { Registry::load(path)? } else { Registry::new() };
        Ok(Self { registry, path: path.to_path_buf(), dirty: false })
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
            Request::Set { key, name, value } => self.registry.set_value_handle(key, &name, value).map_or_else(Response::Failure, |_| { self.dirty = true; Response::Success }),
            Request::Query { key, name } => self.registry.query_value_handle(key, &name).map_or_else(Response::Failure, Response::Value),
            Request::EnumKeys { key } => self.registry.subkeys_handle(key).map_or_else(Response::Failure, Response::Keys),
            Request::EnumValues { key } => self.registry.values_handle(key).map_or_else(Response::Failure, Response::Values),
            Request::Close { key } => self.registry.close_handle(key).map_or_else(Response::Failure, |_| Response::Success),
            Request::Flush { key } => {
                if !self.registry.handles.contains_key(&key) { return Response::Failure(Error::MissingKey); }
                self.flush().map_or_else(|error| Response::Failure(error), |_| Response::Success)
            }
        }
    }
}

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
        registry_wire::QUERY => Request::Query { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), name: take_text(frame, &mut at)? },
        registry_wire::CLOSE => Request::Close { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::ENUM_KEYS => Request::EnumKeys { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::ENUM_VALUES => Request::EnumValues { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::FLUSH => Request::Flush { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
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
        Response::Keys(keys) => { out.push(4); put_u32(&mut out, keys.len().try_into().map_err(|_| Error::InvalidFile)?); for key in keys { put_text(&mut out, key)?; } },
        Response::Values(values) => { out.push(5); put_u32(&mut out, values.len().try_into().map_err(|_| Error::InvalidFile)?); for (name, value) in values { put_text(&mut out, name)?; put_u32(&mut out, value.kind as u32); put_bytes(&mut out, &value.data)?; } },
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
fn error_code(error: &Error) -> u8 { match error { Error::InvalidPath => 1, Error::MissingKey => 2, Error::MissingValue => 3, Error::InvalidFile => 4, Error::Io(_) => 5 } }

impl Registry {
    /// Construct the three predefined roots. # C: O(1)
    pub fn new() -> Self {
        let mut keys = BTreeMap::new(); let mut handles = BTreeMap::new();
        for root in [Root::LocalMachine, Root::CurrentUser, Root::Classes] {
            let path = root.name().to_string();
            let identity = canonical(&path); keys.insert(identity.clone(), Key { path, values: BTreeMap::new() });
            handles.insert(KeyHandle(root_handle(root)), identity);
        }
        Self { keys, handles, next_handle: 0x1000 }
    }

    /// Open an existing key relative to a predefined root. # C: O(log N)
    pub fn open_key(&self, root: Root, subkey: &str) -> Result<String, Error> {
        let path = join_path(root.name(), subkey)?;
        let identity = canonical(&path);
        if self.keys.contains_key(&identity) { Ok(identity) } else { Err(Error::MissingKey) }
    }

    /// Create all missing path components and return the canonical key handle. # C: O(depth log N)
    pub fn create_key(&mut self, root: Root, subkey: &str) -> Result<String, Error> {
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
        let path = self.handles.get(&parent).cloned().ok_or(Error::MissingKey)?;
        let child = join_path(&path, subkey)?; if self.keys.contains_key(&canonical(&child)) { self.allocate_handle(canonical(&child)) } else { Err(Error::MissingKey) }
    }

    /// Create a key relative to an existing opaque handle. # C: O(depth log N)
    pub fn create_relative_handle(&mut self, parent: KeyHandle, subkey: &str) -> Result<KeyHandle, Error> {
        let path = self.handles.get(&parent).cloned().ok_or(Error::MissingKey)?;
        let child = self.create_relative_path(&path, subkey)?; self.allocate_handle(child)
    }

    /// Rename one key and every descendant while preserving open-handle identity. # C: O(N_subtree log N)
    pub fn rename_key_handle(&mut self, key: KeyHandle, name: &str) -> Result<(), Error> {
        if name.is_empty() || name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let old = self.handles.get(&key).cloned().ok_or(Error::MissingKey)?;
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
        let path = self.handles.get(&key).cloned().ok_or(Error::MissingKey)?; self.set_value(&path, name, value)
    }

    /// Query a value through an opaque key handle. # C: O(log N)
    pub fn query_value_handle(&self, key: KeyHandle, name: &str) -> Result<Value, Error> {
        let path = self.handles.get(&key).ok_or(Error::MissingKey)?; self.query_value(path, name)
    }

    /// Enumerate child keys through an opaque key handle. # C: O(N_keys)
    pub fn subkeys_handle(&self, key: KeyHandle) -> Result<Vec<String>, Error> {
        let path = self.handles.get(&key).ok_or(Error::MissingKey)?; self.subkeys(path)
    }

    /// Enumerate values through an opaque key handle in stable display order. # C: O(N_values)
    pub fn values_handle(&self, key: KeyHandle) -> Result<Vec<(String, Value)>, Error> {
        let path = self.handles.get(&key).ok_or(Error::MissingKey)?;
        let values = &self.keys.get(path).ok_or(Error::MissingKey)?.values;
        let mut out = values.values().map(|(name, value)| (name.clone(), value.clone())).collect::<Vec<_>>();
        out.sort_by_key(|(name, _)| canonical(name)); Ok(out)
    }

    /// Close one allocated handle; predefined roots remain valid. # C: O(log N)
    pub fn close_handle(&mut self, key: KeyHandle) -> Result<(), Error> {
        if matches!(key.0, HKEY_LOCAL_MACHINE | HKEY_CURRENT_USER | HKEY_CLASSES_ROOT) { return Err(Error::InvalidPath); }
        if self.handles.remove(&key).is_some() { Ok(()) } else { Err(Error::MissingKey) }
    }

    fn allocate_handle(&mut self, path: String) -> Result<KeyHandle, Error> {
        let handle = KeyHandle(self.next_handle); self.next_handle = self.next_handle.checked_add(1).ok_or(Error::InvalidFile)?;
        self.handles.insert(handle, path); Ok(handle)
    }

    fn create_relative_path(&mut self, parent: &str, subkey: &str) -> Result<String, Error> {
        let path = join_path(parent, subkey)?; let mut current = parent.to_string();
        for component in path.split('\\').skip(parent.split('\\').count()) {
            if component.is_empty() { return Err(Error::InvalidPath); }
            current.push('\\'); current.push_str(component); let identity = canonical(&current);
            self.keys.entry(identity).or_insert_with(|| Key { path: current.clone(), values: BTreeMap::new() });
        }
        Ok(canonical(&path))
    }

    /// Set or replace one typed value. # C: O(log N)
    pub fn set_value(&mut self, key: &str, name: &str, value: Value) -> Result<(), Error> {
        if name.contains('\\') || name.contains('\0') { return Err(Error::InvalidPath); }
        let entry = self.keys.get_mut(key).ok_or(Error::MissingKey)?;
        entry.values.insert(canonical(name), (name.to_string(), value));
        Ok(())
    }

    /// Query one typed value by case-insensitive name. # C: O(log N)
    pub fn query_value(&self, key: &str, name: &str) -> Result<Value, Error> {
        self.keys.get(key).ok_or(Error::MissingKey)?.values.get(&canonical(name)).map(|(_, value)| value.clone()).ok_or(Error::MissingValue)
    }

    /// Enumerate child keys in stable display order. # C: O(N_keys)
    pub fn subkeys(&self, key: &str) -> Result<Vec<String>, Error> {
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
        let mut bytes = Vec::new(); bytes.extend_from_slice(MAGIC);
        let records = self.keys.values().filter(|key| !is_root(&key.path)).count() as u32;
        put_u32(&mut bytes, records);
        for key in self.keys.values().filter(|key| !is_root(&key.path)) {
            put_bytes(&mut bytes, key.path.as_bytes())?; put_u32(&mut bytes, key.values.len() as u32);
            for (display, value) in key.values.values() { put_bytes(&mut bytes, display.as_bytes())?; put_u32(&mut bytes, value.kind as u32); put_bytes(&mut bytes, &value.data)?; }
        }
        let temp = path.with_extension("oxide-registry.tmp"); fs::write(&temp, bytes)?; fs::rename(temp, path)?; Ok(())
    }

    /// Load a database, retaining predefined roots and rejecting malformed input. # C: O(file bytes)
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read(path)?; let mut at = 0;
        if bytes.len() > MAX_BYTES as usize { return Err(Error::InvalidFile); }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) { return Err(Error::InvalidFile); } at += MAGIC.len();
        let records = get_u32(&bytes, &mut at).ok_or(Error::InvalidFile)?; if records > MAX_RECORDS { return Err(Error::InvalidFile); }
        let mut registry = Self::new();
        for _ in 0..records {
            let path = text(get_bytes(&bytes, &mut at).ok_or(Error::InvalidFile)?)?;
            let root = if path.starts_with("HKLM") { Root::LocalMachine } else if path.starts_with("HKCU") { Root::CurrentUser } else if path.starts_with("HKCR") { Root::Classes } else { return Err(Error::InvalidFile) };
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
}

fn canonical(text: &str) -> String { text.to_ascii_uppercase() }
fn is_root(path: &str) -> bool { matches!(path, "HKLM" | "HKCU" | "HKCR") }
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
    fn store_loads_missing_user_state_and_flushes_one_canonical_database() {
        let path = std::env::temp_dir().join(format!("oxide-registry-store-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap(); assert!(!store.is_dirty());
        let key = store.registry_mut().create_handle(Root::CurrentUser, "Software\\Oxide").unwrap();
        store.registry_mut().set_value_handle(key, "Ready", Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] }).unwrap();
        assert!(store.is_dirty()); store.flush().unwrap(); assert!(!store.is_dirty());
        let restored = RegistryStore::open(&path).unwrap();
        let key = restored.registry().open_key(Root::CurrentUser, "software\\oxide").unwrap();
        assert_eq!(restored.registry().query_value(&key, "ready").unwrap().data, vec![1, 0, 0, 0]); std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn typed_service_operations_share_one_handle_owner_and_dirty_lifecycle() {
        let path = std::env::temp_dir().join(format!("oxide-registry-service-{}", std::process::id())); let _ = std::fs::remove_file(&path);
        let mut store = RegistryStore::open(&path).unwrap();
        let handle = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Oxide".into() }) { Response::Handle(handle) => handle, response => panic!("unexpected response: {response:?}") };
        assert!(store.is_dirty());
        assert_eq!(store.execute(Request::Set { key: handle, name: "Mode".into(), value: Value { kind: ValueType::String, data: b"test".to_vec() } }), Response::Success);
        assert_eq!(store.execute(Request::Query { key: handle, name: "mode".into() }), Response::Value(Value { kind: ValueType::String, data: b"test".to_vec() }));
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
    fn shared_wire_contract_keeps_relative_operations_distinct() {
        assert_eq!(registry_wire::OPEN, 1);
        assert_eq!(registry_wire::CREATE, 2);
        assert_eq!(registry_wire::OPEN_RELATIVE, 8);
        assert_eq!(registry_wire::CREATE_RELATIVE, 9);
        assert_ne!(registry_wire::OPEN, registry_wire::OPEN_RELATIVE);
        assert_ne!(registry_wire::CREATE, registry_wire::CREATE_RELATIVE);
        assert_eq!(registry_wire::MAX_FRAME, 1 << 24);
    }
}
