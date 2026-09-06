//! Bounded registry framing over native streams.
use super::*;
/// Serve framed registry requests over one native Linux stream. The caller
/// owns listener lifetime and chooses the per-user store.
pub fn serve_connection<S: Read + Write>(stream: &mut S, store: &mut RegistryStore) -> io::Result<()> {
    serve_requests(stream, |request| execute_request(store, request))
}

/// Commit one request before its response can leave the canonical store owner.
pub(crate) fn execute_request(store: &mut RegistryStore, request: Result<Request, Error>) -> io::Result<Response> {
    let response = request.map_or_else(Response::Failure, |request| store.execute(request));
    if store.is_dirty() {
        store.flush().map_err(|error| io::Error::other(format!("registry commit failed: {error:?}")))?;
    }
    Ok(response)
}

/// Socket I/O surrounds the transaction callback; no store borrow spans peer waits.
pub(crate) fn serve_requests<S: Read + Write>(stream: &mut S,
    mut transact: impl FnMut(Result<Request, Error>) -> io::Result<Response>) -> io::Result<()> {
    loop {
        let mut length = [0u8; 4];
        loop {
            match stream.read(&mut length[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        stream.read_exact(&mut length[1..])?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME { return Err(io::Error::new(io::ErrorKind::InvalidData, "registry frame exceeds bound")); }
        let mut frame = vec![0u8; length]; stream.read_exact(&mut frame)?;
        let response = transact(decode_request(&frame))?;
        let encoded = encode_response(&response).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "registry response exceeds bound"))?;
        if encoded.len() > MAX_FRAME { return Err(io::Error::new(io::ErrorKind::InvalidData, "registry response too large")); }
        stream.write_all(&(encoded.len() as u32).to_le_bytes())?; stream.write_all(&encoded)?; stream.flush()?;
    }
}

#[cfg(test)]
#[path = "wire/tests.rs"]
mod tests;

pub(super) fn decode_request(frame: &[u8]) -> Result<Request, Error> {
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
        registry_wire::SAVE_HIVE => Request::SaveHive { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::LOAD_HIVE_ROOT => Request::LoadHive { root: take_root(frame, &mut at)?, subkey: take_text(frame, &mut at)?, bytes: take_bytes(frame, &mut at)?.to_vec() },
        registry_wire::LOAD_HIVE_RELATIVE => Request::LoadHiveRelative { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), subkey: take_text(frame, &mut at)?, bytes: take_bytes(frame, &mut at)?.to_vec() },
        registry_wire::QUERY_PATH => Request::QueryPath { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?) },
        registry_wire::SUBSCRIBE => Request::Subscribe { key: KeyHandle(take_u64(frame, &mut at).ok_or(Error::InvalidFile)?), filter: take_u64(frame, &mut at).ok_or(Error::InvalidFile)?, subtree: take_u8(frame, &mut at).ok_or(Error::InvalidFile)? != 0 },
        registry_wire::POLL_SUBSCRIPTION => Request::PollSubscription { subscription: take_u64(frame, &mut at).ok_or(Error::InvalidFile)? },
        registry_wire::UNSUBSCRIBE => Request::Unsubscribe { subscription: take_u64(frame, &mut at).ok_or(Error::InvalidFile)? },
        _ => return Err(Error::InvalidFile),
    };
    if at == frame.len() { Ok(request) } else { Err(Error::InvalidFile) }
}

pub(super) fn encode_response(response: &Response) -> Result<Vec<u8>, Error> {
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

pub(super) fn take_root(bytes: &[u8], at: &mut usize) -> Result<Root, Error> {
    match take_u8(bytes, at).ok_or(Error::InvalidFile)? { 0 => Ok(Root::LocalMachine), 1 => Ok(Root::CurrentUser), 2 => Ok(Root::Classes), _ => Err(Error::InvalidFile) }
}
pub(super) fn take_value(bytes: &[u8], at: &mut usize) -> Result<Value, Error> {
    let kind = ValueType::decode(take_u32(bytes, at).ok_or(Error::InvalidFile)?).ok_or(Error::InvalidFile)?;
    Ok(Value { kind, data: take_bytes(bytes, at)?.to_vec() })
}
pub(super) fn take_text(bytes: &[u8], at: &mut usize) -> Result<String, Error> { String::from_utf8(take_bytes(bytes, at)?.to_vec()).map_err(|_| Error::InvalidFile) }
pub(super) fn take_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], Error> { let length = take_u32(bytes, at).ok_or(Error::InvalidFile)? as usize; if length > MAX_BYTES as usize { return Err(Error::InvalidFile); } let end = at.checked_add(length).ok_or(Error::InvalidFile)?; let value = bytes.get(*at..end).ok_or(Error::InvalidFile)?; *at = end; Ok(value) }
pub(super) fn take_u8(bytes: &[u8], at: &mut usize) -> Option<u8> { let value = *bytes.get(*at)?; *at += 1; Some(value) }
pub(super) fn take_u32(bytes: &[u8], at: &mut usize) -> Option<u32> { let end = at.checked_add(4)?; let value = u32::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
pub(super) fn take_u64(bytes: &[u8], at: &mut usize) -> Option<u64> { let end = at.checked_add(8)?; let value = u64::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?); *at = end; Some(value) }
pub(super) fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
pub(super) fn error_code(error: &Error) -> u8 { match error { Error::InvalidPath => 1, Error::MissingKey => 2, Error::MissingValue => 3, Error::InvalidFile => 4, Error::Io(_) => 5, Error::Deleted => registry_wire::ERROR_DELETED } }
