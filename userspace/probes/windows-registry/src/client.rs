use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use syscall::registry_wire;

use crate::{Error, KeyHandle, KeyInfo, Request, Response, Root, Value, ValueType};

/// Native Linux socket client for one canonical registry service session.
pub struct Client { stream: UnixStream }

impl Client {
    /// Connect to a registryd Unix endpoint. # C: O(1)
    pub fn connect(path: &Path) -> io::Result<Self> { Ok(Self { stream: UnixStream::connect(path)? }) }

    /// Send one request and receive exactly one response. # C: O(request bytes)
    pub fn execute(&mut self, request: Request) -> io::Result<Response> {
        let frame = encode_request(&request).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid registry request"))?;
        if frame.len() > u32::MAX as usize { return Err(io::Error::new(io::ErrorKind::InvalidInput, "registry request too large")); }
        self.stream.write_all(&(frame.len() as u32).to_le_bytes())?; self.stream.write_all(&frame)?; self.stream.flush()?;
        let mut length = [0u8; 4]; self.stream.read_exact(&mut length)?; let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > super::MAX_FRAME { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid registry response length")); }
        let mut response = vec![0u8; length]; self.stream.read_exact(&mut response)?; decode_response(&response).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid registry response"))
    }

    /// Open a key from a Windows UTF-16 subkey string. # C: O(name length)
    pub fn open_utf16(&mut self, root: Root, subkey: &[u16]) -> io::Result<Response> {
        self.execute(Request::Open { root, subkey: utf16_text(subkey).map_err(invalid_input)? })
    }

    /// Create a key from a Windows UTF-16 subkey string. # C: O(name length)
    pub fn create_utf16(&mut self, root: Root, subkey: &[u16]) -> io::Result<Response> {
        self.execute(Request::Create { root, subkey: utf16_text(subkey).map_err(invalid_input)? })
    }

    /// Open a key relative to an existing Windows handle. # C: O(name length)
    pub fn open_relative_utf16(&mut self, key: KeyHandle, subkey: &[u16]) -> io::Result<Response> {
        self.execute(Request::OpenRelative { key, subkey: utf16_text(subkey).map_err(invalid_input)? })
    }

    /// Create a key relative to an existing Windows handle. # C: O(name length)
    pub fn create_relative_utf16(&mut self, key: KeyHandle, subkey: &[u16]) -> io::Result<Response> {
        self.execute(Request::CreateRelative { key, subkey: utf16_text(subkey).map_err(invalid_input)? })
    }

    /// Rename an open key through the canonical registry owner. # C: O(subtree)
    pub fn rename_utf16(&mut self, key: KeyHandle, name: &[u16]) -> io::Result<Response> {
        self.execute(Request::Rename { key, name: utf16_text(name).map_err(invalid_input)? })
    }

    /// Query a value whose name is supplied in Windows UTF-16. # C: O(name length)
    pub fn query_utf16(&mut self, key: KeyHandle, name: &[u16]) -> io::Result<Response> {
        self.execute(Request::Query { key, name: utf16_text(name).map_err(invalid_input)? })
    }

    /// Set a value whose name is supplied in Windows UTF-16. # C: O(name length)
    pub fn set_utf16(&mut self, key: KeyHandle, name: &[u16], value: Value) -> io::Result<Response> {
        self.execute(Request::Set { key, name: utf16_text(name).map_err(invalid_input)?, value })
    }

    /// Delete a value whose name is supplied in Windows UTF-16. # C: O(name length)
    pub fn delete_utf16(&mut self, key: KeyHandle, name: &[u16]) -> io::Result<Response> {
        self.execute(Request::DeleteValue { key, name: utf16_text(name).map_err(invalid_input)? })
    }

    /// Enumerate child keys through a Windows UTF-16-compatible session. # C: O(response bytes)
    pub fn enum_keys(&mut self, key: KeyHandle) -> io::Result<Response> { self.execute(Request::EnumKeys { key }) }

    /// Enumerate typed values through a Windows-compatible session. # C: O(response bytes)
    pub fn enum_values(&mut self, key: KeyHandle) -> io::Result<Response> { self.execute(Request::EnumValues { key }) }

    /// Query key metadata through the canonical registry service. # C: O(response bytes)
    pub fn query_key(&mut self, key: KeyHandle) -> io::Result<Response> { self.execute(Request::QueryKey { key }) }

    /// Flush one open key through the canonical registry session. # C: O(1)
    pub fn flush(&mut self, key: KeyHandle) -> io::Result<Response> { self.execute(Request::Flush { key }) }
}

fn invalid_input(_: Error) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, "invalid UTF-16 registry name") }
fn utf16_text(units: &[u16]) -> Result<String, Error> {
    let length = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
    if units[length..].iter().any(|unit| *unit != 0) { return Err(Error::InvalidPath); }
    String::from_utf16(&units[..length]).map_err(|_| Error::InvalidPath)
}

fn encode_request(request: &Request) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match request {
        Request::Open { root, subkey } => { out.extend_from_slice(&[1, root_code(*root)]); put_text(&mut out, subkey)?; }
        Request::Create { root, subkey } => { out.extend_from_slice(&[2, root_code(*root)]); put_text(&mut out, subkey)?; }
        Request::OpenRelative { key, subkey } => { out.push(8); put_u64(&mut out, key.raw()); put_text(&mut out, subkey)?; }
        Request::CreateRelative { key, subkey } => { out.push(9); put_u64(&mut out, key.raw()); put_text(&mut out, subkey)?; }
        Request::Rename { key, name } => { out.push(10); put_u64(&mut out, key.raw()); put_text(&mut out, name)?; }
        Request::Set { key, name, value } => { out.push(3); put_u64(&mut out, key.raw()); put_text(&mut out, name)?; put_u32(&mut out, value.kind as u32); put_bytes(&mut out, &value.data)?; }
        Request::DeleteValue { key, name } => { out.push(registry_wire::DELETE_VALUE); put_u64(&mut out, key.raw()); put_text(&mut out, name)?; }
        Request::Query { key, name } => { out.push(4); put_u64(&mut out, key.raw()); put_text(&mut out, name)?; }
        Request::Close { key } => { out.push(5); put_u64(&mut out, key.raw()); }
        Request::EnumKeys { key } => { out.push(6); put_u64(&mut out, key.raw()); }
        Request::EnumValues { key } => { out.push(7); put_u64(&mut out, key.raw()); }
        Request::QueryKey { key } => { out.push(registry_wire::QUERY_KEY); put_u64(&mut out, key.raw()); }
        Request::Flush { key } => { out.push(11); put_u64(&mut out, key.raw()); }
    } Ok(out)
}

fn decode_response(frame: &[u8]) -> Result<Response, Error> {
    let Some(&code) = frame.first() else { return Err(Error::InvalidFile) };
    let response = match code {
        0 if frame.len() == 1 => Response::Success,
        1 if frame.len() == 9 => Response::Handle(KeyHandle(u64::from_le_bytes(frame[1..9].try_into().unwrap()))),
        2 => { let mut at = 1; let kind = ValueType::decode(take_u32(frame, &mut at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?; Response::Value(Value { kind, data: take_bytes(frame, &mut at)?.to_vec() }) },
        3 if frame.len() == 2 => Response::Failure(match frame[1] { 1 => Error::InvalidPath, 2 => Error::MissingKey, 3 => Error::MissingValue, 4 => Error::InvalidFile, 5 => Error::Io("remote I/O failure".into()), _ => return Err(Error::InvalidFile) }),
        registry_wire::RESPONSE_KEYS => { let mut at = 1; let count = take_u32(frame, &mut at).ok_or(Error::InvalidFile)? as usize; if count > super::MAX_RECORDS as usize { return Err(Error::InvalidFile); } let mut keys = Vec::with_capacity(count); for _ in 0..count { keys.push(String::from_utf8(take_bytes(frame, &mut at)?.to_vec()).map_err(|_| Error::InvalidFile)?); } if at != frame.len() { return Err(Error::InvalidFile); } Response::Keys(keys) },
        registry_wire::RESPONSE_VALUES => { let mut at = 1; let count = take_u32(frame, &mut at).ok_or(Error::InvalidFile)? as usize; if count > super::MAX_RECORDS as usize { return Err(Error::InvalidFile); } let mut values = Vec::with_capacity(count); for _ in 0..count { let name = String::from_utf8(take_bytes(frame, &mut at)?.to_vec()).map_err(|_| Error::InvalidFile)?; let kind = ValueType::decode(take_u32(frame, &mut at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?; let data = take_bytes(frame, &mut at)?.to_vec(); values.push((name, Value { kind, data })); } if at != frame.len() { return Err(Error::InvalidFile); } Response::Values(values) },
        registry_wire::RESPONSE_KEY_INFO => { let mut at = 1; let name = String::from_utf8(take_bytes(frame, &mut at)?.to_vec()).map_err(|_| Error::InvalidFile)?; let subkeys = take_u32(frame, &mut at).ok_or(Error::InvalidFile)?; let max_subkey = take_u32(frame, &mut at).ok_or(Error::InvalidFile)?; let values = take_u32(frame, &mut at).ok_or(Error::InvalidFile)?; let max_value_name = take_u32(frame, &mut at).ok_or(Error::InvalidFile)?; let max_value_data = take_u32(frame, &mut at).ok_or(Error::InvalidFile)?; if at != frame.len() { return Err(Error::InvalidFile); } Response::KeyInfo(KeyInfo { name, subkeys, max_subkey, values, max_value_name, max_value_data }) },
        _ => return Err(Error::InvalidFile),
    };
    Ok(response)
}

fn root_code(root: Root) -> u8 { match root { Root::LocalMachine => 0, Root::CurrentUser => 1, Root::Classes => 2 } }
fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> { if bytes.len() > u32::MAX as usize { return Err(Error::InvalidFile); } put_u32(out, bytes.len() as u32); out.extend_from_slice(bytes); Ok(()) }
fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), Error> { put_bytes(out, text.as_bytes()) }
fn take_u32(bytes: &[u8], at: &mut usize) -> Option<u32> { let end = at.checked_add(4)?; let value = u32::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
fn take_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], Error> { let len = take_u32(bytes, at).ok_or(Error::InvalidFile)? as usize; let end = at.checked_add(len).ok_or(Error::InvalidFile)?; let value = bytes.get(*at..end).ok_or(Error::InvalidFile)?; *at = end; Ok(value) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serve_connection, RegistryStore};
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn client_round_trips_typed_operations_over_unix_socket() {
        let base = std::env::temp_dir(); let suffix = std::process::id();
        let socket = base.join(format!("oxide-registry-client-{suffix}.sock")); let database = base.join(format!("oxide-registry-client-{suffix}.db"));
        let _ = std::fs::remove_file(&socket); let _ = std::fs::remove_file(&database);
        let listener = UnixListener::bind(&socket).unwrap();
        let server_database = database.clone();
        let server = thread::spawn(move || { let (mut stream, _) = listener.accept().unwrap(); let mut store = RegistryStore::open(&server_database).unwrap(); serve_connection(&mut stream, &mut store).unwrap(); });
        let mut client = Client::connect(&socket).unwrap();
        let key = match client.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Oxide".into() }).unwrap() { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
        assert_eq!(client.execute(Request::Set { key, name: "Build".into(), value: Value { kind: ValueType::Dword, data: vec![7, 0, 0, 0] } }).unwrap(), Response::Success);
        assert_eq!(client.execute(Request::Query { key, name: "build".into() }).unwrap(), Response::Value(Value { kind: ValueType::Dword, data: vec![7, 0, 0, 0] }));
        assert_eq!(client.enum_values(key).unwrap(), Response::Values(vec![("Build".into(), Value { kind: ValueType::Dword, data: vec![7, 0, 0, 0] })]));
        assert_eq!(client.enum_keys(key).unwrap(), Response::Keys(Vec::new()));
        assert_eq!(client.flush(key).unwrap(), Response::Success);
        let child_name: Vec<u16> = "Child".encode_utf16().chain([0]).collect();
        let child = match client.create_relative_utf16(key, &child_name).unwrap() { Response::Handle(child) => child, response => panic!("unexpected response: {response:?}") };
        assert_eq!(client.open_relative_utf16(key, &child_name).unwrap(), Response::Handle(KeyHandle(child.raw() + 1)));
        drop(client); server.join().unwrap(); let _ = std::fs::remove_file(socket); let _ = std::fs::remove_file(database);
    }

    #[test]
    fn utf16_client_methods_require_one_terminated_windows_string() {
        assert_eq!(utf16_text(&[b'S' as u16, b'W' as u16, 0]).unwrap(), "SW");
        assert_eq!(utf16_text(&[b'S' as u16, 0, b'W' as u16]), Err(Error::InvalidPath));
        assert_eq!(utf16_text(&[0xd800, 0]), Err(Error::InvalidPath));
    }
}
