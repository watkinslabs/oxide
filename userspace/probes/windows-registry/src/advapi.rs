//! Win32 registry operations backed by the canonical native service.

use crate::{Client, Error, KeyHandle, Response, Root, Value, ValueType, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_GEN_FAILURE: u32 = 31;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

/// One Win32 `advapi32` registry view over a native Linux service session.
pub struct Advapi { client: Client }

impl Advapi {
    /// Attach the Win32 adapter to one registryd Unix endpoint. # C: O(1)
    pub fn connect(path: &std::path::Path) -> std::io::Result<Self> { Ok(Self { client: Client::connect(path)? }) }

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

    /// Implement `RegSetValueExW` for bounded safe buffers. # C: O(value bytes)
    pub fn reg_set_value_ex_w(&mut self, key: u64, name: Option<&[u16]>, reserved: u32, value_type: u32, data: Option<&[u8]>, count: u32) -> u32 {
        if reserved != 0 { return ERROR_INVALID_PARAMETER; }
        let Some(kind) = ValueType::decode_for_adapter(value_type) else { return ERROR_INVALID_PARAMETER; };
        let data = match data { Some(data) => data, None => { if count != 0 { return ERROR_INVALID_PARAMETER; } &[] } };
        if count as usize > data.len() { return ERROR_INVALID_PARAMETER; }
        let name = name.unwrap_or(&[]);
        match self.client.set_utf16(KeyHandle(key), name, Value { kind, data: data[..count as usize].to_vec() }) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
    }

    /// Implement `RegCloseKey`; predefined root handles remain open. # C: O(log N)
    pub fn reg_close_key(&mut self, key: u64) -> u32 {
        match self.client.execute(crate::Request::Close { key: KeyHandle(key) }) { Ok(Response::Success) => ERROR_SUCCESS, Ok(Response::Failure(error)) => status_handle(error), Ok(_) | Err(_) => ERROR_GEN_FAILURE }
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
fn status(error: Error) -> u32 { match error { Error::MissingKey | Error::MissingValue => ERROR_FILE_NOT_FOUND, Error::InvalidPath => ERROR_INVALID_PARAMETER, Error::Io(_) | Error::InvalidFile => ERROR_GEN_FAILURE } }
fn status_handle(error: Error) -> u32 { match error { Error::MissingKey => ERROR_INVALID_HANDLE, other => status(other) } }
fn copy_name(value: &str, buffer: &mut [u16], length: &mut u32) -> u32 {
    let encoded: Vec<u16> = value.encode_utf16().collect();
    if *length as usize <= encoded.len() { return ERROR_MORE_DATA; }
    if encoded.len() + 1 > buffer.len() { return ERROR_INVALID_PARAMETER; }
    buffer[..encoded.len()].copy_from_slice(&encoded); buffer[encoded.len()] = 0; *length = encoded.len() as u32; ERROR_SUCCESS
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
        let data = b"oxide"; assert_eq!(api.reg_set_value_ex_w(key, None, 0, ValueType::String as u32, Some(data), data.len() as u32), ERROR_SUCCESS);
        let mut kind = None; let mut count = 0; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, None, &mut count), ERROR_SUCCESS); assert_eq!((kind, count), (Some(ValueType::String as u32), 5));
        let mut short = [0u8; 2]; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, Some(&mut short), &mut 2), ERROR_MORE_DATA);
        let mut full = [0u8; 5]; let mut full_count = 5; assert_eq!(api.reg_query_value_ex_w(key, None, 0, &mut kind, Some(&mut full), &mut full_count), ERROR_SUCCESS); assert_eq!(&full, data);
        let mut value_name = [0u16; 8]; let mut value_name_len = value_name.len() as u32; assert_eq!(api.reg_enum_value_w(key, 0, &mut value_name, &mut value_name_len, 0, &mut kind, None, &mut 0), ERROR_SUCCESS); assert_eq!(String::from_utf16(&value_name[..value_name_len as usize]).unwrap(), "");
        let mut child_name = [0u16; 8]; let mut child_name_len = child_name.len() as u32; assert_eq!(api.reg_enum_key_ex_w(key, 0, &mut child_name, &mut child_name_len, 0), ERROR_NO_MORE_ITEMS);
        assert_eq!(api.reg_close_key(key), ERROR_SUCCESS); drop(api); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }
}
