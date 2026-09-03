//! Canonical named NT object-directory namespace.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use super::{NtObject, NtObjectType};

struct NamedObject {
    path: String,
    object: Arc<NtObject>,
    permanent: bool,
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
    for path in ["\\", "\\KnownDlls", "\\BaseNamedObjects", "\\Device", "\\Device\\NamedPipe", "\\DosDevices", "\\??", "\\??\\pipe", "\\Sessions", "\\Windows"] {
        let id = namespace.next_id.fetch_add(1, Ordering::Relaxed);
        namespace.objects.push(NamedObject { path: path.into(), object: NtObject::new(NtObjectType::Directory, id), permanent: true });
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
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
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
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Publish one section in the canonical namespace or return its existing identity. # C: O(N_namespace)
pub fn publish_section(path: &str, object: Arc<NtObject>) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::Section {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else { return (object, NamedObjectState::ParentMissing); };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (object, NamedObjectState::ParentMissing);
    }
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Publish one mutant in the canonical namespace or return its existing identity. # C: O(N_namespace)
pub fn publish_mutant(path: &str, object: Arc<NtObject>) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::Mutant {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else { return (object, NamedObjectState::ParentMissing); };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (object, NamedObjectState::ParentMissing);
    }
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Publish one timer in the canonical namespace or return its existing identity. # C: O(N_namespace)
pub fn publish_timer(path: &str, object: Arc<NtObject>) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::Timer {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else { return (object, NamedObjectState::ParentMissing); };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (object, NamedObjectState::ParentMissing);
    }
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Publish one symbolic link in the canonical namespace or return its existing identity. # C: O(N_namespace)
pub fn publish_symbolic_link(path: &str, object: Arc<NtObject>) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::SymbolicLink {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else { return (object, NamedObjectState::ParentMissing); };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (object, NamedObjectState::ParentMissing);
    }
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Publish one named pipe in the canonical NT namespace. # C: O(N_namespace)
pub fn publish_named_pipe(path: &str, object: Arc<NtObject>) -> (Arc<NtObject>, NamedObjectState) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    if let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, path)) {
        return (Arc::clone(&entry.object), if entry.object.kind() == NtObjectType::NamedPipe {
            NamedObjectState::Existing
        } else { NamedObjectState::TypeMismatch });
    }
    let Some(parent_path) = parent(path) else { return (object, NamedObjectState::ParentMissing); };
    if !namespace.objects.iter().any(|entry| equal(&entry.path, parent_path)
        && entry.object.kind() == NtObjectType::Directory) {
        return (object, NamedObjectState::ParentMissing);
    }
    namespace.objects.push(NamedObject { path: path.into(), object: Arc::clone(&object), permanent: false });
    (object, NamedObjectState::Created)
}

/// Remove the permanence reference from a named object. # C: O(N_namespace)
pub fn make_temporary(object: &NtObject) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    let Some(index) = namespace.objects.iter().position(|entry|
        core::ptr::eq(entry.object.as_ref(), object)) else { return; };
    namespace.objects[index].permanent = false;
}

/// Remove a temporary object's name after its final handle reference closes. # C: O(N_namespace)
pub fn release_temporary(object: &Arc<NtObject>, has_live_handle: bool) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    let Some(index) = namespace.objects.iter().position(|entry|
        !entry.permanent && core::ptr::eq(entry.object.as_ref(), object.as_ref())) else { return; };
    if !has_live_handle {
        namespace.objects.remove(index);
    }
}

/// Return the canonical path of a directory object. # C: O(N_namespace)
pub fn directory_path(object: &NtObject) -> Option<String> {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    namespace.objects.iter().find(|entry| core::ptr::eq(entry.object.as_ref(), object)
        && entry.object.kind() == NtObjectType::Directory).map(|entry| entry.path.clone())
}

/// Return the canonical name for one published object, if it has one. # C: O(N_namespace)
pub fn object_name(object: &NtObject) -> Option<String> {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    namespace.objects.iter().find(|entry| core::ptr::eq(entry.object.as_ref(), object))
        .map(|entry| entry.path.clone())
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
            NtObjectType::Section => "Section",
            NtObjectType::Mutant => "Mutant",
            NtObjectType::Timer => "Timer",
            NtObjectType::SymbolicLink => "SymbolicLink",
            NtObjectType::NamedPipe => "NamedPipe",
            NtObjectType::ActivationContext => "ActivationContext",
            _ => "Object",
        };
        Some((leaf(&entry.path).into(), kind.into()))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::NtSection;

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
    fn published_object_name_is_canonical_and_unnamed_objects_have_none() {
        let named = lookup_directory("\\KnownDlls").unwrap();
        assert_eq!(object_name(&named).as_deref(), Some("\\KnownDlls"));
        let unnamed = NtObject::new(NtObjectType::Event, 9901);
        assert_eq!(object_name(&unnamed), None);
    }

    #[test]
    fn named_pipe_publication_preserves_one_namespace_identity() {
        let table = super::super::NtHandleTable::new();
        let config = super::super::NtPipeConfig { pipe_type: 0, read_mode: 0,
            completion_mode: 0, max_instances: 1, inbound_quota: 4096,
            outbound_quota: 4096, timeout_100ns: -1, sharing: 3 };
        let first = table.new_named_pipe(config);
        let (published, state) = publish_named_pipe("\\BaseNamedObjects\\oxide-pipe", first.clone());
        assert_eq!(state, NamedObjectState::Created);
        assert!(Arc::ptr_eq(&published, &first));
        let second = table.new_named_pipe(config);
        let (existing, state) = publish_named_pipe("\\basenamedobjects\\OXIDE-PIPE", second);
        assert_eq!(state, NamedObjectState::Existing);
        assert!(Arc::ptr_eq(&existing, &first));
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

    #[test]
    fn temporary_named_object_name_survives_until_last_handle_closes() {
        let path = "\\BaseNamedObjects\\f1477_temporary_event";
        let (object, state) = create_event(path, false, false);
        assert_eq!(state, NamedObjectState::Created);
        let table = super::super::NtHandleTable::new();
        let first = table.insert(object.clone(), 0x0001_0000).unwrap();
        let second = table.insert(object.clone(), 0x0001_0000).unwrap();
        make_temporary(&object);
        assert!(lookup_object(path, NtObjectType::Event).is_some());
        assert!(table.close(first));
        assert!(lookup_object(path, NtObjectType::Event).is_some());
        assert!(table.close(second));
        assert!(lookup_object(path, NtObjectType::Event).is_none());
    }

    #[test]
    fn named_section_publication_reuses_identity_and_reports_as_section() {
        let path = "\\BaseNamedObjects\\f1453_section";
        let first = NtObject::new_section(9001, NtSection::new(4096).unwrap());
        let second = NtObject::new_section(9002, NtSection::new(8192).unwrap());
        let (published, first_state) = publish_section(path, first.clone());
        let (reopened, second_state) = publish_section(path, second);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(published.as_ref(), reopened.as_ref()));
        assert_eq!(published.section().unwrap().size(), 4096);
        assert_eq!(directory_entries(&lookup_directory("\\BaseNamedObjects").unwrap())
            .iter().find(|(name, _)| name == "f1453_section").map(|(_, kind)| kind.as_str()), Some("Section"));
    }

    #[test]
    fn named_mutant_publication_reuses_identity_and_reports_as_mutant() {
        let path = "\\BaseNamedObjects\\f1454_mutant";
        let first = NtObject::new_mutant(9101, None);
        let second = NtObject::new_mutant(9102, None);
        let (published, first_state) = publish_mutant(path, first);
        let (reopened, second_state) = publish_mutant(path, second);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(published.as_ref(), reopened.as_ref()));
        assert_eq!(published.kind(), NtObjectType::Mutant);
        assert_eq!(directory_entries(&lookup_directory("\\BaseNamedObjects").unwrap())
            .iter().find(|(name, _)| name == "f1454_mutant").map(|(_, kind)| kind.as_str()), Some("Mutant"));
    }

    #[test]
    fn named_timer_publication_reuses_identity_and_reports_as_timer() {
        let path = "\\BaseNamedObjects\\f1455_timer";
        let first = NtObject::new_timer(9201, true);
        let second = NtObject::new_timer(9202, false);
        let (published, first_state) = publish_timer(path, first);
        let (reopened, second_state) = publish_timer(path, second);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(published.as_ref(), reopened.as_ref()));
        assert_eq!(published.kind(), NtObjectType::Timer);
        assert_eq!(directory_entries(&lookup_directory("\\BaseNamedObjects").unwrap())
            .iter().find(|(name, _)| name == "f1455_timer").map(|(_, kind)| kind.as_str()), Some("Timer"));
    }

    #[test]
    fn named_symbolic_link_publication_reuses_identity_and_preserves_target() {
        let path = "\\DosDevices\\f1456_link";
        let first = NtObject::new_symbolic_link(9301, "\\Device\\HarddiskVolume1".into());
        let second = NtObject::new_symbolic_link(9302, "\\Device\\Other".into());
        let (published, first_state) = publish_symbolic_link(path, first);
        let (reopened, second_state) = publish_symbolic_link(path, second);
        assert_eq!(first_state, NamedObjectState::Created);
        assert_eq!(second_state, NamedObjectState::Existing);
        assert!(core::ptr::eq(published.as_ref(), reopened.as_ref()));
        assert_eq!(published.kind(), NtObjectType::SymbolicLink);
        assert_eq!(published.symbolic_link().unwrap().target(), "\\Device\\HarddiskVolume1");
        assert!(directory_entries(&lookup_directory("\\DosDevices").unwrap())
            .iter().any(|(name, kind)| name == "f1456_link" && kind == "SymbolicLink"));
    }
}
