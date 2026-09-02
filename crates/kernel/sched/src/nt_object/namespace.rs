//! Canonical named NT object-directory namespace.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use super::{NtObject, NtObjectType};

struct NamedObject {
    path: String,
    object: Arc<NtObject>,
}

struct Namespace {
    objects: Vec<NamedObject>,
    next_id: AtomicU64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamedObjectState { Created, Existing, TypeMismatch, ParentMissing }

static OBJECT_NAMESPACE: Spinlock<Namespace, TaskListClass> = Spinlock::new(Namespace {
    objects: Vec::new(), next_id: AtomicU64::new(1),
});

fn fold(byte: u8) -> u8 { if byte.is_ascii_lowercase() { byte - b'a' + b'A' } else { byte } }

fn equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.bytes().zip(right.bytes()).all(|(a, b)| fold(a) == fold(b))
}

fn parent(path: &str) -> Option<&str> {
    let end = path.rfind('\\')?;
    if end == 0 { Some("\\") } else { Some(&path[..end]) }
}

fn leaf(path: &str) -> &str { path.rsplit('\\').next().unwrap_or(path) }

fn seed(namespace: &mut Namespace) {
    if !namespace.objects.is_empty() { return; }
    for path in ["\\", "\\KnownDlls", "\\BaseNamedObjects", "\\Device", "\\Sessions", "\\Windows"] {
        let id = namespace.next_id.fetch_add(1, Ordering::Relaxed);
        namespace.objects.push(NamedObject { path: path.into(), object: NtObject::new(NtObjectType::Directory, id) });
    }
}

/// Resolve a case-insensitive absolute object-directory path. # C: O(N_namespace)
pub fn lookup_directory(path: &str) -> Option<Arc<NtObject>> {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    namespace.objects.iter().find(|entry| equal(&entry.path, path)
        && entry.object.kind() == NtObjectType::Directory).map(|entry| Arc::clone(&entry.object))
}

/// Resolve a named object of the requested type without creating state. # C: O(N_namespace)
pub fn lookup_object(path: &str, kind: NtObjectType) -> Option<Arc<NtObject>> {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    namespace.objects.iter().find(|entry| equal(&entry.path, path)
        && entry.object.kind() == kind).map(|entry| Arc::clone(&entry.object))
}

/// Create or reopen one named event while retaining one canonical object. # C: O(N_namespace)
pub fn create_event(path: &str, manual_reset: bool, initial_state: bool) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::Event {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else {
        return (NtObject::new_event(0, manual_reset, initial_state), NamedObjectState::ParentMissing);
    };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (NtObject::new_event(0, manual_reset, initial_state), NamedObjectState::ParentMissing);
    }
    let id = namespace.next_id.fetch_add(1, Ordering::Relaxed);
    let object = NtObject::new_event(id, manual_reset, initial_state);
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object) });
    (object, NamedObjectState::Created)
}

/// Create or reopen one named semaphore while retaining one canonical object. # C: O(N_namespace)
pub fn create_semaphore(path: &str, initial: i64, maximum: i64) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::Semaphore {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else {
        return (NtObject::new_semaphore(0, initial, maximum), NamedObjectState::ParentMissing);
    };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (NtObject::new_semaphore(0, initial, maximum), NamedObjectState::ParentMissing);
    }
    let id = namespace.next_id.fetch_add(1, Ordering::Relaxed);
    let object = NtObject::new_semaphore(id, initial, maximum);
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object) });
    (object, NamedObjectState::Created)
}

/// Return the canonical path of a directory object. # C: O(N_namespace)
pub fn directory_path(object: &NtObject) -> Option<String> {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    namespace.objects.iter().find(|entry| core::ptr::eq(entry.object.as_ref(), object)
        && entry.object.kind() == NtObjectType::Directory).map(|entry| entry.path.clone())
}

/// Snapshot immediate object-directory children for a directory handle. # C: O(N_namespace)
pub fn directory_entries(object: &NtObject) -> Vec<(String, String)> {
    let Some(path) = directory_path(object) else { return Vec::new(); };
    let namespace = OBJECT_NAMESPACE.lock();
    namespace.objects.iter().filter_map(|entry| {
        if parent(&entry.path).map(|value| equal(value, &path)) != Some(true) { return None; }
        let kind = match entry.object.kind() {
            NtObjectType::Directory => "Directory",
            NtObjectType::Event => "Event",
            NtObjectType::Semaphore => "Semaphore",
            _ => "Object",
        };
        Some((leaf(&entry.path).into(), kind.into()))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_namespace_resolves_standard_directories_case_insensitively() {
        let object = lookup_directory("\\knowndlls").unwrap();
        assert_eq!(object.kind(), NtObjectType::Directory);
        assert_eq!(directory_path(&object).as_deref(), Some("\\KnownDlls"));
    }

    #[test]
    fn root_lists_only_immediate_directory_children() {
        let root = lookup_directory("\\").unwrap();
        let entries = directory_entries(&root);
        assert!(entries.iter().any(|(name, kind)| name == "KnownDlls" && kind == "Directory"));
        assert!(!entries.iter().any(|(name, _)| name == "Windows\\x"));
    }

    #[test]
    fn unknown_directory_does_not_create_namespace_state() {
        assert!(lookup_directory("\\NoSuchDirectory").is_none());
    }

    #[test]
    fn a_same_id_foreign_object_is_not_a_namespace_directory() {
        let table = super::super::NtHandleTable::new();
        let foreign = table.new_object(NtObjectType::Directory);
        assert!(directory_path(&foreign).is_none());
    }

    #[test]
    fn opening_a_seeded_directory_returns_a_queryable_process_handle() {
        let table = super::super::NtHandleTable::new();
        let handle = table.open_directory("\\KnownDlls", 1).unwrap();
        let object = table.get(handle, 1).unwrap();
        assert_eq!(object.kind(), NtObjectType::Directory);
        assert_eq!(directory_path(&object).as_deref(), Some("\\KnownDlls"));
    }

    #[test]
    fn named_event_creation_reuses_identity_and_rejects_type_collision() {
        let path = "\\BaseNamedObjects\\f1450_event";
        let (first, first_state) = create_event(path, false, false);
        let (second, second_state) = create_event(path, true, true);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(first.as_ref(), second.as_ref()));
        assert_eq!(directory_entries(&lookup_directory("\\BaseNamedObjects").unwrap())
            .iter().find(|(name, _)| name == "f1450_event").map(|(_, kind)| kind.as_str()), Some("Event"));
        let (other, collision) = create_event(path, false, false);
        assert!(core::ptr::eq(first.as_ref(), other.as_ref()));
        assert_eq!(collision, NamedObjectState::Existing);
        let (directory, mismatch) = create_event("\\KnownDlls", false, false);
        assert_eq!(directory.kind(), NtObjectType::Directory);
        assert_eq!(mismatch, NamedObjectState::TypeMismatch);
    }

    #[test]
    fn named_semaphore_creation_reuses_identity_and_reports_as_semaphore() {
        let path = "\\BaseNamedObjects\\f1452_semaphore";
        let (first, first_state) = create_semaphore(path, 1, 2);
        let (second, second_state) = create_semaphore(path, 0, 4);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(first.as_ref(), second.as_ref()));
        assert_eq!(first.kind(), NtObjectType::Semaphore);
        assert_eq!(directory_entries(&lookup_directory("\\BaseNamedObjects").unwrap())
            .iter().find(|(name, _)| name == "f1452_semaphore").map(|(_, kind)| kind.as_str()), Some("Semaphore"));
    }
}
