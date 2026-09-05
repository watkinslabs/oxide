//! Win32 registry operations backed by the canonical native service.

use crate::{Client, Error, KeyHandle, Response, Root, Value, ValueType, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_GEN_FAILURE: u32 = 31;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_KEY_DELETED: u32 = 1018;
pub const ERROR_DATATYPE_MISMATCH: u32 = 1629;
pub const ERROR_UNSUPPORTED_TYPE: u32 = 1630;

pub const RRF_RT_REG_NONE: u32 = 1 << 0;
pub const RRF_RT_REG_SZ: u32 = 1 << 1;
pub const RRF_RT_REG_EXPAND_SZ: u32 = 1 << 2;
pub const RRF_RT_REG_BINARY: u32 = 1 << 3;
pub const RRF_RT_REG_DWORD: u32 = 1 << 4;
pub const RRF_RT_REG_MULTI_SZ: u32 = 1 << 5;
pub const RRF_RT_REG_QWORD: u32 = 1 << 6;
pub const RRF_RT_DWORD: u32 = RRF_RT_REG_BINARY | RRF_RT_REG_DWORD;
pub const RRF_RT_QWORD: u32 = RRF_RT_REG_BINARY | RRF_RT_REG_QWORD;
pub const RRF_RT_ANY: u32 = 0xffff;
pub const RRF_SUBKEY_WOW6464KEY: u32 = 1 << 16;
pub const RRF_SUBKEY_WOW6432KEY: u32 = 1 << 17;
pub const RRF_WOW64_MASK: u32 = RRF_SUBKEY_WOW6432KEY | RRF_SUBKEY_WOW6464KEY;
pub const RRF_NOEXPAND: u32 = 1 << 28;
pub const RRF_ZEROONFAILURE: u32 = 1 << 29;

/// One Win32 `advapi32` registry view over a native Linux service session.
pub struct Advapi { client: Client }

impl Advapi {
    /// Attach the Win32 adapter to one registryd Unix endpoint. # C: O(1)
    pub fn connect(path: &std::path::Path) -> std::io::Result<Self> { Ok(Self { client: Client::connect(path)? }) }

    /// Implement the legacy `RegOpenKeyW` entry point through the same
    /// canonical operation as `RegOpenKeyExW`. # C: O(name length)
    pub fn reg_open_key_w(&mut self, parent: u64, name: Option<&[u16]>) -> (u32, Option<u64>) {
        self.reg_open_key_ex_w(parent, name, 0, 0)
    }

    /// Implement legacy `RegCreateKeyW` through the canonical extended create operation. # C: O(name length)
    pub fn reg_create_key_w(&mut self, parent: u64, name: Option<&[u16]>) -> (u32, Option<u64>) {
        self.reg_create_key_ex_w(parent, name, 0, 0, 0)
    }

    /// Implement the observable `RegOpenKeyExW` contract for safe Rust callers. # C: O(name length)
    pub fn reg_open_key_ex_w(&mut self, parent: u64, name: Option<&[u16]>, options: u32, _access: u32) -> (u32, Option<u64>) {
        if options != 0 { return (ERROR_INVALID_PARAMETER, None); }
        if name.is_none() || name.unwrap_or(&[]).is_empty() || name == Some(&[0]) {
            if root(parent).is_some() { return (ERROR_SUCCESS, Some(parent)); }
        }
        self.open(parent, name.unwrap_or(&[]))
    }

    /// Implement the observable `RegCreateKeyExW` contract for safe Rust callers. # C: O(name length)
    pub fn reg_create_key_ex_w(&mut self, parent: u64, name: Option<&[u16]>, reserved: u32, options: u32, _access: u32) -> (u32, Option<u64>) {
        if reserved != 0 || options != 0 { return (ERROR_INVALID_PARAMETER, None); }
        let name = name.unwrap_or(&[]);
        if name.is_empty() || name == [0] {
            if root(parent).is_some() { return (ERROR_SUCCESS, Some(parent)); }
        }
        match self.create(parent, name) { Ok(handle) => (ERROR_SUCCESS, Some(handle.raw())), Err(status) => (status, None) }
    }

    /// Implement `RegQueryValueExW`, including size-only and short-buffer calls. # C: O(value bytes)
    pub fn reg_query_value_ex_w(&mut self, key: u64, name: Option<&[u16]>, reserved: u32, value_type: &mut Option<u32>, data: Option<&mut [u8]>, count: &mut u32) -> u32 {
        if reserved != 0 || data.is_some() && (*count as usize) > data.as_ref().map_or(0, |buf| buf.len()) { return ERROR_INVALID_PARAMETER; }
        let name = name.unwrap_or(&[]);
        let value = match self.client.query_utf16(KeyHandle(key), name) { Ok(Response::Value(value)) => value, Ok(Response::Failure(error)) => return status_handle(error), Ok(_) => return ERROR_GEN_FAILURE, Err(_) => return ERROR_GEN_FAILURE };
        *value_type = Some(value.kind as u32);
        let needed = value.data.len();
        if needed > u32::MAX as usize { return ERROR_MORE_DATA; }
        if let Some(buffer) = data {
            if (*count as usize) < needed { *count = needed as u32; return ERROR_MORE_DATA; }
            buffer[..needed].copy_from_slice(&value.data); *count = needed as u32;
        } else { *count = needed as u32; }
        ERROR_SUCCESS
    }

    /// Implement Wine's `RegGetValueW` contract over the canonical service. # C: O(value bytes + environment)
    pub fn reg_get_value_w(&mut self, key: u64, subkey: Option<&[u16]>, name: Option<&[u16]>, flags: u32,
        value_type: Option<&mut u32>, mut data: Option<&mut [u8]>, count: Option<&mut u32>) -> u32 {
        if data.is_some() && count.is_none() { return ERROR_INVALID_PARAMETER; }
        if flags & RRF_WOW64_MASK == RRF_WOW64_MASK { return ERROR_INVALID_PARAMETER; }
        if flags & RRF_RT_REG_EXPAND_SZ != 0 && flags & RRF_NOEXPAND == 0 && flags & RRF_RT_ANY != RRF_RT_ANY {
            return ERROR_INVALID_PARAMETER;
        }
        let subkey = match subkey {
            Some(value) if !value.is_empty() && value != [0] => match terminated_utf16(value) { Ok(value) => Some(value), Err(error) => return error },
            _ => None,
        };
        let name = match name {
            None => &[][..],
            Some(value) => match terminated_utf16(value) { Ok(value) => value, Err(error) => return error },
        };
        let opened = if let Some(subkey) = subkey {
            let (status, handle) = self.open(key, subkey);
            if status != ERROR_SUCCESS { return status; }
            handle.map(KeyHandle)
        } else { None };
        let query_key = opened.unwrap_or(KeyHandle(key));
        let result = match self.client.query_utf16(query_key, name) {
            Ok(Response::Value(value)) => value,
            Ok(Response::Failure(error)) => { if let Some(handle) = opened { let _ = self.client.execute(crate::Request::Close { key: handle }); } return get_failure(status_handle(error), flags, data, count); }
            Ok(_) | Err(_) => { if let Some(handle) = opened { let _ = self.client.execute(crate::Request::Close { key: handle }); } return get_failure(ERROR_GEN_FAILURE, flags, data, count); }
        };
        if let Some(handle) = opened { let _ = self.client.execute(crate::Request::Close { key: handle }); }
        let mut kind = result.kind;
        let mut bytes = result.data;
        if kind == ValueType::ExpandString && flags & RRF_NOEXPAND == 0 {
            let Some(text) = String::from_utf16(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>().as_slice()).ok() else {
                return get_failure(ERROR_INVALID_PARAMETER, flags, data, count);
            };
            bytes = expand_environment(&text).encode_utf16().flat_map(u16::to_le_bytes).collect();
            kind = ValueType::String;
        }
        if is_string(kind) && (bytes.len() < 2 || bytes[bytes.len() - 2..] != [0, 0]) { bytes.extend_from_slice(&[0, 0]); }
        let restriction = flags & RRF_RT_ANY;
        let type_mask = value_type_mask(kind);
        let mut status = if restriction & type_mask == 0 { ERROR_UNSUPPORTED_TYPE } else { ERROR_SUCCESS };
        if status == ERROR_SUCCESS && kind == ValueType::Binary && (restriction == RRF_RT_DWORD && bytes.len() != 4 || restriction == RRF_RT_QWORD && bytes.len() != 8) { status = ERROR_DATATYPE_MISMATCH; }
        if let Some(output) = value_type { *output = kind as u32; }
        let needed = bytes.len();
        if let Some(output) = count { *output = needed as u32; }
        if status == ERROR_SUCCESS {
            if let Some(buffer) = data.as_deref_mut() {
                if buffer.len() < needed { status = ERROR_MORE_DATA; } else { buffer[..needed].copy_from_slice(&bytes); }
            }
        }
        if status != ERROR_SUCCESS && flags & RRF_ZEROONFAILURE != 0 { if let Some(buffer) = data { buffer.fill(0); } }
        status
    }

    /// Implement `RegSetValueExW` for bounded safe buffers. # C: O(value bytes)
    pub fn reg_set_value_ex_w(&mut self, key: u64, name: Option<&[u16]>, reserved: u32, value_type: u32, data: Option<&[u8]>, count: u32) -> u32 {
        if reserved != 0 { return ERROR_INVALID_PARAMETER; }
        let Some(kind) = ValueType::decode_for_adapter(value_type) else { return ERROR_INVALID_PARAMETER; };
        let data = match data { Some(data) => data, None => { if count != 0 { return ERROR_INVALID_PARAMETER; } &[] } };
        if count as usize > data.len() { return ERROR_INVALID_PARAMETER; }
        let name = name.unwrap_or(&[]);
        match self.client.set_utf16(KeyHandle(key), name, Value { kind, data: data[..count as usize].to_vec() }) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
    }

    /// Implement `RegDeleteValueW`, including the unnamed default value. # C: O(name length)
    pub fn reg_delete_value_w(&mut self, key: u64, name: Option<&[u16]>) -> u32 {
        let name = match name {
            None => &[][..],
            Some(name) => match terminated_utf16(name) { Ok(name) => name, Err(error) => return error },
        };
        match self.client.delete_utf16(KeyHandle(key), name) {
            Ok(Response::Success) => ERROR_SUCCESS,
            Ok(Response::Failure(error)) => status_handle(error),
            Ok(_) | Err(_) => ERROR_GEN_FAILURE,
        }
    }

    /// Implement `RegCloseKey`; predefined root handles remain open. # C: O(log N)
    pub fn reg_close_key(&mut self, key: u64) -> u32 {
        match self.client.execute(crate::Request::Close { key: KeyHandle(key) }) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
    }

    /// Implement `RegFlushKey` through the canonical registry service. # C: O(1)
    pub fn reg_flush_key(&mut self, key: u64) -> u32 {
        match self.client.flush(KeyHandle(key)) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
    }

    /// Implement `RegQueryInfoKeyW` from the service's canonical key metadata. # C: O(N_subkeys + N_values)
    pub fn reg_query_info_key_w(&mut self, key: u64, class: Option<&mut [u16]>, class_len: Option<&mut u32>, reserved: u32,
        subkeys: Option<&mut u32>, max_subkey_len: Option<&mut u32>, max_class_len: Option<&mut u32>, values: Option<&mut u32>,
        max_value_name_len: Option<&mut u32>, max_value_len: Option<&mut u32>, security_len: Option<&mut u32>, last_write_time: Option<&mut u64>) -> u32 {
        if reserved != 0 || class.is_some() && class_len.is_none() { return ERROR_INVALID_PARAMETER; }
        let info = match self.client.query_key(KeyHandle(key)) {
            Ok(Response::KeyInfo(info)) => info,
            Ok(Response::Failure(error)) => return status_handle(error),
            Ok(_) | Err(_) => return ERROR_GEN_FAILURE,
        };
        if let Some(output) = subkeys { *output = info.subkeys; }
        if let Some(output) = max_subkey_len { *output = info.max_subkey / 2; }
        if let Some(output) = values { *output = info.values; }
        if let Some(output) = max_value_name_len { *output = info.max_value_name / 2; }
        if let Some(output) = max_value_len { *output = info.max_value_data; }
        if let Some(output) = max_class_len { *output = 0; }
        if let Some(output) = security_len { *output = 0; }
        if let Some(output) = last_write_time { *output = 0; }
        if let Some(output) = class_len { *output = 0; }
        if let Some(buffer) = class { if let Some(first) = buffer.first_mut() { *first = 0; } }
        ERROR_SUCCESS
    }

    /// Implement `RegRenameKey` while retaining handles to renamed descendants. # C: O(subtree)
    pub fn reg_rename_key(&mut self, key: u64, name: &[u16]) -> u32 {
        match self.client.rename_utf16(KeyHandle(key), name) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
    }

    /// Implement `RegEnumKeyExW` for a caller-owned UTF-16 buffer. # C: O(response bytes)
    pub fn reg_enum_key_ex_w(&mut self, key: u64, index: u32, name: &mut [u16], name_len: &mut u32, reserved: u32) -> u32 {
        if reserved != 0 || *name_len as usize > name.len() { return ERROR_INVALID_PARAMETER; }
        let keys = match self.client.enum_keys(KeyHandle(key)) { Ok(Response::Keys(keys)) => keys, Ok(Response::Failure(error)) => return status_handle(error), Ok(_) | Err(_) => return ERROR_GEN_FAILURE };
        let Some(value) = keys.get(index as usize) else { return ERROR_NO_MORE_ITEMS; };
        copy_name(value, name, name_len)
    }

    /// Implement `RegEnumValueW` with Wine-compatible name/data size reporting. # C: O(response bytes)
    pub fn reg_enum_value_w(&mut self, key: u64, index: u32, name: &mut [u16], name_len: &mut u32, reserved: u32, value_type: &mut Option<u32>, data: Option<&mut [u8]>, count: &mut u32) -> u32 {
        if reserved != 0 || *name_len as usize > name.len() || data.is_some() && (*count as usize) > data.as_ref().map_or(0, |buf| buf.len()) { return ERROR_INVALID_PARAMETER; }
        let values = match self.client.enum_values(KeyHandle(key)) { Ok(Response::Values(values)) => values, Ok(Response::Failure(error)) => return status_handle(error), Ok(_) | Err(_) => return ERROR_GEN_FAILURE };
        let Some((value_name, value)) = values.get(index as usize) else { return ERROR_NO_MORE_ITEMS; };
        let name_status = copy_name(value_name, name, name_len); if name_status != ERROR_SUCCESS { return name_status; }
        *value_type = Some(value.kind as u32); let needed = value.data.len();
        if needed > u32::MAX as usize { return ERROR_MORE_DATA; }
        if let Some(buffer) = data { if (*count as usize) < needed { *count = needed as u32; return ERROR_MORE_DATA; } buffer[..needed].copy_from_slice(&value.data); }
        *count = needed as u32; ERROR_SUCCESS
    }

    fn open(&mut self, parent: u64, name: &[u16]) -> (u32, Option<u64>) {
        let result = if let Some(root) = root(parent) { self.client.open_utf16(root, name) } else { self.client.open_relative_utf16(KeyHandle(parent), name) };
        match result { Ok(Response::Handle(handle)) => (ERROR_SUCCESS, Some(handle.raw())), Ok(Response::Failure(error)) => (status_handle(error), None), Ok(_) | Err(_) => (ERROR_GEN_FAILURE, None) }
    }

    fn create(&mut self, parent: u64, name: &[u16]) -> Result<KeyHandle, u32> {
        let result = if let Some(root) = root(parent) { self.client.create_utf16(root, name) } else { self.client.create_relative_utf16(KeyHandle(parent), name) };
        match result { Ok(Response::Handle(handle)) => Ok(handle), Ok(Response::Failure(error)) => Err(status_handle(error)), Ok(_) | Err(_) => Err(ERROR_GEN_FAILURE) }
    }
}

fn root(raw: u64) -> Option<Root> { match raw { HKEY_LOCAL_MACHINE => Some(Root::LocalMachine), HKEY_CURRENT_USER => Some(Root::CurrentUser), HKEY_CLASSES_ROOT => Some(Root::Classes), _ => None } }
fn status(error: Error) -> u32 { match error { Error::MissingKey | Error::MissingValue => ERROR_FILE_NOT_FOUND, Error::Deleted => ERROR_KEY_DELETED, Error::InvalidPath => ERROR_INVALID_PARAMETER, Error::Io(_) | Error::InvalidFile => ERROR_GEN_FAILURE } }
fn status_handle(error: Error) -> u32 { match error { Error::MissingKey => ERROR_INVALID_HANDLE, other => status(other) } }
fn copy_name(value: &str, buffer: &mut [u16], length: &mut u32) -> u32 {
    let encoded: Vec<u16> = value.encode_utf16().collect();
    if *length as usize <= encoded.len() { return ERROR_MORE_DATA; }
    if encoded.len() + 1 > buffer.len() { return ERROR_INVALID_PARAMETER; }
    buffer[..encoded.len()].copy_from_slice(&encoded); buffer[encoded.len()] = 0; *length = encoded.len() as u32; ERROR_SUCCESS
}

fn terminated_utf16(value: &[u16]) -> Result<&[u16], u32> {
    if value.last() == Some(&0) && !value[..value.len() - 1].contains(&0) { Ok(&value[..value.len() - 1]) } else { Err(ERROR_INVALID_PARAMETER) }
}

fn is_string(kind: ValueType) -> bool { matches!(kind, ValueType::String | ValueType::ExpandString | ValueType::MultiString) }
fn value_type_mask(kind: ValueType) -> u32 { match kind { ValueType::None => RRF_RT_REG_NONE, ValueType::String => RRF_RT_REG_SZ, ValueType::ExpandString => RRF_RT_REG_EXPAND_SZ, ValueType::Binary => RRF_RT_REG_BINARY, ValueType::Dword => RRF_RT_REG_DWORD, ValueType::MultiString => RRF_RT_REG_MULTI_SZ, ValueType::Qword => RRF_RT_REG_QWORD } }
fn get_failure(status: u32, flags: u32, data: Option<&mut [u8]>, count: Option<&mut u32>) -> u32 {
    if flags & RRF_ZEROONFAILURE != 0 { if let Some(buffer) = data { buffer.fill(0); } }
    let _ = count;
    status
}
fn expand_environment(text: &str) -> String {
    let mut output = String::with_capacity(text.len()); let mut rest = text;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]); let tail = &rest[start + 1..];
        let Some(end) = tail.find('%') else { output.push_str(&rest[start..]); break; };
        let name = &tail[..end];
        if name.is_empty() { output.push('%'); rest = &tail[1..]; continue; }
        match std::env::var(name) { Ok(value) => output.push_str(&value), Err(_) => { output.push('%'); output.push_str(name); output.push('%'); } }
        rest = &tail[end + 1..];
    }
    if !rest.is_empty() && !rest.contains('%') { output.push_str(rest); }
    output
}

trait AdapterValueType { fn decode_for_adapter(raw: u32) -> Option<ValueType>; }
impl AdapterValueType for ValueType { fn decode_for_adapter(raw: u32) -> Option<ValueType> { match raw { 0 => Some(ValueType::None), 1 => Some(ValueType::String), 2 => Some(ValueType::ExpandString), 3 => Some(ValueType::Binary), 4 => Some(ValueType::Dword), 7 => Some(ValueType::MultiString), 11 => Some(ValueType::Qword), _ => None } } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_maps_registry_failures_to_win32_statuses() {
        assert_eq!(status(Error::MissingKey), ERROR_FILE_NOT_FOUND);
        assert_eq!(status(Error::MissingValue), ERROR_FILE_NOT_FOUND);
        assert_eq!(status(Error::InvalidPath), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn adapter_type_decoder_accepts_only_supported_value_types() {
        assert_eq!(ValueType::decode_for_adapter(4), Some(ValueType::Dword));
        assert_eq!(ValueType::decode_for_adapter(6), None);
    }

    #[test]
    fn create_key_wrapper_matches_predefined_root_and_invalid_handle_contract() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let base = std::env::temp_dir(); let id = std::process::id();
        let socket = base.join(format!("oxide-advapi-create-{id}.sock")); let database = base.join(format!("oxide-advapi-create-{id}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap(); let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = crate::RegistryStore::open(&server_database).unwrap(); crate::serve_connection(&mut stream, &mut store).unwrap(); });
        let mut api = Advapi::connect(&socket).unwrap();
        let name: Vec<u16> = "Software\\Oxide".encode_utf16().chain([0]).collect();
        let (status, key) = api.reg_create_key_w(HKEY_LOCAL_MACHINE, Some(&name));
        assert_eq!(status, ERROR_SUCCESS); let key = key.unwrap();
        let (status, reopened) = api.reg_open_key_w(HKEY_LOCAL_MACHINE, Some(&name));
        assert_eq!(status, ERROR_SUCCESS); assert!(reopened.is_some());
        assert_eq!(api.reg_create_key_w(0xdead, Some(&name)), (ERROR_INVALID_HANDLE, None));
        let bad_name: Vec<u16> = "bad\\".encode_utf16().chain([0]).collect();
        assert_eq!(api.reg_create_key_w(HKEY_CLASSES_ROOT, Some(&bad_name)), (ERROR_INVALID_PARAMETER, None));
        assert_eq!(api.reg_close_key(key), ERROR_SUCCESS); drop(api); server.join().unwrap();
        let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }

    #[test]
    fn delete_value_matches_win32_default_and_missing_value_contract() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let base = std::env::temp_dir(); let id = std::process::id();
        let socket = base.join(format!("oxide-advapi-delete-{id}.sock")); let database = base.join(format!("oxide-advapi-delete-{id}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap(); let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = crate::RegistryStore::open(&server_database).unwrap(); crate::serve_connection(&mut stream, &mut store).unwrap(); });
        let mut api = Advapi::connect(&socket).unwrap();
        let (_, key) = api.reg_create_key_ex_w(HKEY_CURRENT_USER, Some(&"Software\\Oxide".encode_utf16().chain([0]).collect::<Vec<_>>()), 0, 0, 0); let key = key.unwrap();
        assert_eq!(api.reg_set_value_ex_w(key, None, 0, ValueType::String as u32, Some(b"default"), 7), ERROR_SUCCESS);
        assert_eq!(api.reg_delete_value_w(key, None), ERROR_SUCCESS);
        let mut kind = None; let mut count = 0; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, None, &mut count), ERROR_FILE_NOT_FOUND);
        assert_eq!(api.reg_delete_value_w(key, None), ERROR_FILE_NOT_FOUND);
        assert_eq!(api.reg_delete_value_w(key, Some(&[b'x' as u16, 0])), ERROR_FILE_NOT_FOUND);
        assert_eq!(api.reg_delete_value_w(key, Some(&[b'x' as u16])), ERROR_INVALID_PARAMETER);
        assert_eq!(api.reg_delete_value_w(0xdead, None), ERROR_INVALID_HANDLE);
        drop(api); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }

    #[test]
    fn get_value_matches_wine_subkey_type_filter_size_and_zero_failure_contract() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let base = std::env::temp_dir(); let id = std::process::id();
        let socket = base.join(format!("oxide-advapi-get-{id}.sock")); let database = base.join(format!("oxide-advapi-get-{id}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap(); let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = crate::RegistryStore::open(&server_database).unwrap(); crate::serve_connection(&mut stream, &mut store).unwrap(); });
        let mut api = Advapi::connect(&socket).unwrap();
        let key_name: Vec<u16> = "Software\\Game\\Settings".encode_utf16().chain([0]).collect();
        let (_, key) = api.reg_create_key_ex_w(HKEY_CURRENT_USER, Some(&key_name), 0, 0, 0); let key = key.unwrap();
        let binary_name: Vec<u16> = "Blob".encode_utf16().chain([0]).collect();
        assert_eq!(api.reg_set_value_ex_w(key, Some(&binary_name), 0, ValueType::Binary as u32, Some(&[1, 2, 3]), 3), ERROR_SUCCESS);
        let subkey: Vec<u16> = "Software\\Game\\Settings".encode_utf16().chain([0]).collect();
        let mut kind = 0; let mut small = [0xaa; 2]; let mut size = small.len() as u32;
        assert_eq!(api.reg_get_value_w(HKEY_CURRENT_USER, Some(&subkey), Some(&binary_name), RRF_RT_DWORD | RRF_ZEROONFAILURE, Some(&mut kind), Some(&mut small), Some(&mut size)), ERROR_DATATYPE_MISMATCH);
        assert_eq!(small, [0; 2]);
        let string_name: Vec<u16> = "Title".encode_utf16().chain([0]).collect();
        assert_eq!(api.reg_set_value_ex_w(key, Some(&string_name), 0, ValueType::String as u32, Some(b"Oxide"), 5), ERROR_SUCCESS);
        let mut output = [0u8; 7]; let mut output_size = 0;
        assert_eq!(api.reg_get_value_w(HKEY_CURRENT_USER, Some(&subkey), Some(&string_name), RRF_RT_REG_SZ, Some(&mut kind), None, Some(&mut output_size)), ERROR_SUCCESS);
        assert_eq!((kind, output_size), (ValueType::String as u32, 7));
        output_size = output.len() as u32;
        assert_eq!(api.reg_get_value_w(HKEY_CURRENT_USER, Some(&subkey), Some(&string_name), RRF_RT_REG_SZ, Some(&mut kind), Some(&mut output), Some(&mut output_size)), ERROR_SUCCESS);
        assert_eq!((&output[..5], &output[5..]), (b"Oxide".as_slice(), &[0, 0][..]));
        assert_eq!(api.reg_get_value_w(HKEY_CURRENT_USER, Some(&subkey), Some(&string_name), RRF_RT_REG_EXPAND_SZ, Some(&mut kind), None, None), ERROR_INVALID_PARAMETER);
        drop(api); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }

    #[test]
    fn advapi_operations_round_trip_default_value_and_more_data_semantics() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let base = std::env::temp_dir(); let id = std::process::id();
        let socket = base.join(format!("oxide-advapi-{id}.sock")); let database = base.join(format!("oxide-advapi-{id}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap(); let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = crate::RegistryStore::open(&server_database).unwrap(); crate::serve_connection(&mut stream, &mut store).unwrap(); });
        let mut api = Advapi::connect(&socket).unwrap(); let key_name: Vec<u16> = "Software\\Oxide".encode_utf16().chain([0]).collect();
        let (created, key) = api.reg_create_key_ex_w(HKEY_CURRENT_USER, Some(&key_name), 0, 0, 0); let key = key.unwrap(); assert_eq!(created, ERROR_SUCCESS);
        let (opened, opened_key) = api.reg_open_key_w(HKEY_CURRENT_USER, Some(&key_name)); assert_eq!(opened, ERROR_SUCCESS); assert!(opened_key.is_some());
        let data = b"oxide"; assert_eq!(api.reg_set_value_ex_w(key, None, 0, ValueType::String as u32, Some(data), data.len() as u32), ERROR_SUCCESS);
        let mut kind = None; let mut count = 0; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, None, &mut count), ERROR_SUCCESS); assert_eq!((kind, count), (Some(ValueType::String as u32), 5));
        let mut short = [0u8; 2]; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, Some(&mut short), &mut 2), ERROR_MORE_DATA);
        let mut full = [0u8; 5]; let mut full_count = 5; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, Some(&mut full), &mut full_count), ERROR_SUCCESS); assert_eq!(&full, data);
        assert_eq!(api.reg_flush_key(key), ERROR_SUCCESS);
        let mut value_name = [0u16; 8]; let mut value_name_len = value_name.len() as u32; assert_eq!(api.reg_enum_value_w(key, 0, &mut value_name, &mut value_name_len, 0, &mut kind, None, &mut 0), ERROR_SUCCESS); assert_eq!(String::from_utf16(&value_name[..value_name_len as usize]).unwrap(), "");
        let mut child_name = [0u16; 8]; let mut child_name_len = child_name.len() as u32; assert_eq!(api.reg_enum_key_ex_w(key, 0, &mut child_name, &mut child_name_len, 0), ERROR_NO_MORE_ITEMS);
        assert_eq!(api.reg_close_key(key), ERROR_SUCCESS); assert_eq!(api.reg_flush_key(key), ERROR_INVALID_HANDLE); drop(api); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }

    #[test]
    fn query_info_maps_canonical_metadata_to_windows_units_and_rejects_bad_arguments() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let base = std::env::temp_dir(); let id = std::process::id();
        let socket = base.join(format!("oxide-advapi-info-{id}.sock")); let database = base.join(format!("oxide-advapi-info-{id}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap(); let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = crate::RegistryStore::open(&server_database).unwrap(); crate::serve_connection(&mut stream, &mut store).unwrap(); });
        let mut api = Advapi::connect(&socket).unwrap();
        let parent = "Software\\Oxide".encode_utf16().chain([0]).collect::<Vec<_>>();
        let child = "LongChild".encode_utf16().chain([0]).collect::<Vec<_>>();
        let (status, key) = api.reg_create_key_ex_w(HKEY_CURRENT_USER, Some(&parent), 0, 0, 0); assert_eq!(status, ERROR_SUCCESS);
        let key = key.unwrap(); let (_, child_key) = api.reg_create_key_ex_w(key, Some(&child), 0, 0, 0); assert!(child_key.is_some());
        assert_eq!(api.reg_set_value_ex_w(key, Some(&"ValueName".encode_utf16().chain([0]).collect::<Vec<_>>()), 0, ValueType::Binary as u32, Some(&[1, 2, 3, 4]), 4), ERROR_SUCCESS);
        assert_eq!(api.reg_query_info_key_w(key, Some(&mut [0x55; 1]), None, 0, None, None, None, None, None, None, None, None), ERROR_INVALID_PARAMETER);
        let mut count = 0; let mut max_key = 0; let mut value_count = 0; let mut max_name = 0; let mut max_data = 0;
        assert_eq!(api.reg_query_info_key_w(key, None, None, 0, Some(&mut count), Some(&mut max_key), None, Some(&mut value_count), Some(&mut max_name), Some(&mut max_data), None, None), ERROR_SUCCESS);
        assert_eq!((count, max_key, value_count, max_name, max_data), (1, 9, 1, 9, 4));
        assert_eq!(api.reg_query_info_key_w(key, None, None, 1, None, None, None, None, None, None, None, None), ERROR_INVALID_PARAMETER);
        assert_eq!(api.reg_query_info_key_w(0xdead, None, None, 0, None, None, None, None, None, None, None, None), ERROR_INVALID_HANDLE);
        drop(api); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }
}
