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
fn first_run_materializes_canonical_windows_startup_environment() {
    let registry = Registry::new_with_startup_state().unwrap();
    let machine = registry.open_key(Root::LocalMachine, r"System\CurrentControlSet\Control\Session Manager\Environment").unwrap();
    let value = registry.query_value(&machine, "systemroot").unwrap();
    assert_eq!(value.kind, ValueType::String);
    assert_eq!(String::from_utf16(&value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>()).unwrap(), "C:\\Windows\0");
    assert!(registry.open_key(Root::CurrentUser, "Environment").is_ok());
    assert!(registry.open_key(Root::CurrentUser, "Volatile Environment").is_ok());
    let current_version = registry.open_key(Root::LocalMachine, r"Software\Microsoft\Windows NT\CurrentVersion").unwrap();
    assert!(registry.query_value(&current_version, "ProgramFilesDir").is_ok());
}

#[test]
fn existing_database_is_not_reseeded_on_open() {
    let path = std::env::temp_dir().join(format!("oxide-registry-no-reseed-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut registry = Registry::new();
    registry.create_key(Root::CurrentUser, "Software\\OnlyUserState").unwrap();
    registry.save(&path).unwrap();
    let restored = RegistryStore::open(&path).unwrap();
    assert!(restored.registry().open_key(Root::CurrentUser, "Software\\OnlyUserState").is_ok());
    assert_eq!(restored.registry().open_key(Root::LocalMachine, r"System\CurrentControlSet\Control\Session Manager\Environment"), Err(Error::MissingKey));
    drop(restored);
    fs::remove_file(path).unwrap();
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
    let mut store = RegistryStore::open(&path).unwrap(); assert!(path.is_file()); assert!(!store.is_dirty());
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
    fs::remove_file(&path).unwrap();
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
    let bytes = match store.execute(Request::SaveHive { key: source }) { Response::Bytes(bytes) => bytes, response => panic!("unexpected response: {response:?}") };
    let target = match store.execute(Request::Create { root: Root::CurrentUser, subkey: "Software\\Target".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
    assert_eq!(store.execute(Request::LoadHiveRelative { key: target, subkey: String::new(), bytes: bytes.clone() }), Response::Success);
    let imported = match store.execute(Request::OpenRelative { key: target, subkey: "Child".into() }) { Response::Handle(key) => key, response => panic!("unexpected response: {response:?}") };
    assert_eq!(store.execute(Request::Query { key: imported, name: "value".into() }), Response::Value(Value { kind: ValueType::Binary, data: vec![1, 2, 3] }));
    assert_eq!(store.execute(Request::LoadHiveRelative { key: target, subkey: String::new(), bytes: b"invalid".to_vec() }), Response::Failure(Error::InvalidFile));
    assert_eq!(store.execute(Request::Query { key: imported, name: "value".into() }), Response::Value(Value { kind: ValueType::Binary, data: vec![1, 2, 3] }));
}
