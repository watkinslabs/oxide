use super::*;
use std::io::Cursor;

struct Peer { input: Cursor<Vec<u8>>, output: Vec<u8> }
impl Read for Peer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.input.read(bytes) }
}
impl Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.output.extend_from_slice(bytes); Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn peer(bytes: Vec<u8>) -> Peer { Peer { input: Cursor::new(bytes), output: Vec::new() } }

#[test]
fn only_empty_header_is_clean_disconnect() {
    let mut empty = peer(Vec::new());
    assert!(serve_requests(&mut empty, |_| panic!("EOF cannot execute")).is_ok());
    for count in 1..4 {
        let mut truncated = peer(vec![1; count]);
        let error = serve_requests(&mut truncated, |_| panic!("partial header cannot execute")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(truncated.output.is_empty());
    }
}

#[test]
fn failed_transaction_has_no_success_response() {
    let request = vec![registry_wire::OPEN, 1, 0, 0, 0, 0];
    let mut bytes = (request.len() as u32).to_le_bytes().to_vec(); bytes.extend(request);
    let mut stream = peer(bytes);
    let mut calls = 0;
    let error = serve_requests(&mut stream, |request| {
        assert!(matches!(request, Ok(Request::Open { root: Root::CurrentUser, .. })));
        calls += 1; Err(io::Error::other("fixture persistence failure"))
    }).unwrap_err();
    assert_eq!(calls, 1); assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(stream.output.is_empty());
}

/// One database write per set is what made a startup that sets 47 values pay
/// 47 whole-database commits. Each commit creates a temporary file and renames
/// it over the database, so the database inode changes exactly once per commit
/// and counts them without reaching into the store's internals.
fn database_identity(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).expect("committed database must be linked").ino()
}

fn scratch(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("oxide-registry-{label}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("oxide-registry.lock"));
    path
}

fn set_request(key: KeyHandle, name: &str) -> Result<Request, Error> {
    Ok(Request::Set { key, name: name.to_string(), value: Value { kind: ValueType::Dword, data: vec![1, 0, 0, 0] } })
}

#[test]
fn sets_do_not_each_commit_the_whole_database() {
    const SETS: usize = 47;
    let path = scratch("lazy-commit");
    let mut store = RegistryStore::open(&path).unwrap();
    let key = match execute_request(&mut store, Ok(Request::Create { root: Root::CurrentUser, subkey: "Software\\Startup".into() })).unwrap() {
        Response::Handle(handle) => handle, other => panic!("create answered {other:?}"),
    };
    let opened = database_identity(&path);
    for index in 0..SETS {
        assert!(matches!(execute_request(&mut store, set_request(key, &format!("Value{index}"))).unwrap(), Response::Success));
    }
    assert_eq!(database_identity(&path), opened, "a set committed the database on its own");
    assert!(store.is_dirty(), "unflushed sets must leave the session dirty");
    commit(&mut store).unwrap();
    let flushed = database_identity(&path);
    assert_ne!(flushed, opened, "the flush must reach the database");
    commit(&mut store).unwrap();
    assert_eq!(database_identity(&path), flushed, "a clean session must not rewrite the database");
    drop(store);
    let restored = RegistryStore::open(&path).unwrap();
    let key = restored.registry().open_key(Root::CurrentUser, "software\\startup").unwrap();
    for index in 0..SETS {
        assert_eq!(restored.registry().query_value(&key, &format!("value{index}")).unwrap().data, vec![1, 0, 0, 0]);
    }
    drop(restored);
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("oxide-registry.lock"));
}

#[test]
fn an_explicit_flush_request_still_reaches_the_database() {
    let path = scratch("explicit-flush");
    let mut store = RegistryStore::open(&path).unwrap();
    let key = match execute_request(&mut store, Ok(Request::Create { root: Root::CurrentUser, subkey: "Software\\Explicit".into() })).unwrap() {
        Response::Handle(handle) => handle, other => panic!("create answered {other:?}"),
    };
    execute_request(&mut store, set_request(key, "Durable")).unwrap();
    let before = database_identity(&path);
    assert!(matches!(execute_request(&mut store, Ok(Request::Flush { key })).unwrap(), Response::Success));
    assert_ne!(database_identity(&path), before, "a flush request must commit the hive");
    assert!(!store.is_dirty());
    drop(store);
    let restored = RegistryStore::open(&path).unwrap();
    let key = restored.registry().open_key(Root::CurrentUser, "software\\explicit").unwrap();
    assert_eq!(restored.registry().query_value(&key, "durable").unwrap().data, vec![1, 0, 0, 0]);
    drop(restored);
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("oxide-registry.lock"));
}

#[test]
fn a_disconnecting_connection_commits_its_unflushed_sets() {
    let path = scratch("disconnect-commit");
    let mut store = RegistryStore::open(&path).unwrap();
    let mut frames = Vec::new();
    let mut create = vec![registry_wire::CREATE, 1u8];
    put_text(&mut create, "Software\\Disconnect").unwrap();
    frames.extend_from_slice(&(create.len() as u32).to_le_bytes()); frames.extend_from_slice(&create);
    let mut stream = peer(frames);
    serve_connection(&mut stream, &mut store).unwrap();
    drop(store);
    let restored = RegistryStore::open(&path).unwrap();
    restored.registry().open_key(Root::CurrentUser, "software\\disconnect").expect("disconnect must commit the session");
    drop(restored);
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("oxide-registry.lock"));
}
