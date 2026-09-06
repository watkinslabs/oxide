//! Canonical named NT object-directory namespace.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use super::{NtObject, NtObjectType};

mod desktop;
pub use desktop::{create_desktop, create_window_station, publish_desktop, publish_window_station, DesktopPublishError};

#[path = "namespace/lifetime.rs"]
mod lifetime;
pub(super) use lifetime::{retain_handle, release_handle};
pub use lifetime::release_temporary;

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

/// Maximum number of native object symbolic-link substitutions in one walk.
pub const MAX_SYMBOLIC_LINK_DEPTH: usize = 32;

/// Failure classes for native object-directory symbolic-link traversal.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SymbolicLinkResolutionError { InvalidPath, Loop, Depth }

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

fn path_components(path: &str) -> Result<Vec<&str>, SymbolicLinkResolutionError> {
    if path.is_empty() || !path.starts_with('\\') || path.contains('/') || path.contains('\0') {
        return Err(SymbolicLinkResolutionError::InvalidPath);
    }
    if path == "\\" { return Ok(Vec::new()); }
    let mut components = Vec::new();
    for component in path.split('\\').skip(1) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(SymbolicLinkResolutionError::InvalidPath);
        }
        components.push(component);
    }
    Ok(components)
}

fn relative_components(path: &str) -> Result<Vec<&str>, SymbolicLinkResolutionError> {
    if path.is_empty() || path.contains('/') || path.contains('\0') {
        return Err(SymbolicLinkResolutionError::InvalidPath);
    }
    let mut components = Vec::new();
    for component in path.split('\\') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(SymbolicLinkResolutionError::InvalidPath);
        }
        components.push(component);
    }
    Ok(components)
}

fn make_path(components: &[String]) -> String {
    let mut path = String::from("\\");
    for component in components {
        if path.len() != 1 { path.push('\\'); }
        path.push_str(component);
    }
    path
}

/// Follow native object-directory links while retaining one namespace owner.
/// # C: O(depth × N_namespace)
pub fn resolve_symbolic_links(path: &str) -> Result<String, SymbolicLinkResolutionError> {
    let initial = path_components(path)?;
    let mut components: Vec<String> = initial.into_iter().map(String::from).collect();
    let mut seen = Vec::new();
    let mut depth = 0;
    loop {
        let mut namespace = OBJECT_NAMESPACE.lock();
        seed(&mut namespace);
        let mut replacement = None;
        let mut prefix = String::from("\\");
        for index in 0..components.len() {
            if prefix.len() != 1 { prefix.push('\\'); }
            prefix.push_str(&components[index]);
            let Some(entry) = namespace.objects.iter().find(|entry| equal(&entry.path, &prefix)) else { continue; };
            if entry.object.kind() != NtObjectType::SymbolicLink { continue; }
            if seen.iter().any(|id| *id == entry.object.id()) {
                return Err(SymbolicLinkResolutionError::Loop);
            }
            if depth >= MAX_SYMBOLIC_LINK_DEPTH {
                return Err(SymbolicLinkResolutionError::Depth);
            }
            let Some(link) = entry.object.symbolic_link() else {
                return Err(SymbolicLinkResolutionError::InvalidPath);
            };
            let target = link.target();
            let target_components = if target.is_empty() { Vec::new() }
                else if target.starts_with('\\') { path_components(target)? }
                else { relative_components(target)? };
            let target_components = target_components.into_iter().map(String::from).collect::<Vec<_>>();
            let mut next = if target.starts_with('\\') { Vec::new() } else {
                components[..index].to_vec()
            };
            next.extend(target_components);
            next.extend_from_slice(&components[index + 1..]);
            seen.push(entry.object.id());
            components = next;
            depth += 1;
            replacement = Some(());
            break;
        }
        drop(namespace);
        if replacement.is_none() { return Ok(make_path(&components)); }
    }
}

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

/// Retain a named object's namespace reference after its handles close. # C: O(N_namespace)
pub fn make_permanent(object: &NtObject) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    seed(&mut namespace);
    let Some(index) = namespace.objects.iter().position(|entry|
        core::ptr::eq(entry.object.as_ref(), object)) else { return; };
    namespace.objects[index].permanent = true;
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
            NtObjectType::WindowStation => "WindowStation",
            NtObjectType::Desktop => "Desktop",
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
    fn permanent_named_object_survives_final_handle_until_made_temporary() {
        let path = "\\BaseNamedObjects\\f1477_permanent";
        let (object, state) = create_event(path, false, false);
        assert_eq!(state, NamedObjectState::Created);
        let table = super::super::NtHandleTable::new();
        let handle = table.insert(object, 0x0001_0000).unwrap();
        let retained = lookup_object(path, NtObjectType::Event).unwrap();
        make_permanent(&retained);
        assert!(table.close(handle));
        assert!(lookup_object(path, NtObjectType::Event).is_some());
        let reopened = lookup_object(path, NtObjectType::Event).unwrap();
        let handle = table.insert(reopened.clone(), 0x0001_0000).unwrap();
        make_temporary(&reopened);
        assert!(table.close(handle));
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

    #[test]
    fn symbolic_link_walk_replaces_link_and_retains_suffix_case_insensitively() {
        let target = NtObject::new_symbolic_link(9401, "\\Device\\HarddiskVolume1".into());
        let (_, state) = publish_symbolic_link("\\DosDevices\\walk_link", target);
        assert_eq!(state, NamedObjectState::Created);
        assert_eq!(resolve_symbolic_links("\\DosDevices\\WALK_LINK\\Windows\\x").unwrap(),
            "\\Device\\HarddiskVolume1\\Windows\\x");
    }

    #[test]
    fn symbolic_link_walk_rejects_cycles_and_bounded_chains() {
        let first = NtObject::new_symbolic_link(9402, "\\DosDevices\\walk_b".into());
        let second = NtObject::new_symbolic_link(9403, "\\DosDevices\\walk_a".into());
        assert_eq!(publish_symbolic_link("\\DosDevices\\walk_a", first).1, NamedObjectState::Created);
        assert_eq!(publish_symbolic_link("\\DosDevices\\walk_b", second).1, NamedObjectState::Created);
        assert_eq!(resolve_symbolic_links("\\DosDevices\\walk_a\\leaf"), Err(SymbolicLinkResolutionError::Loop));

        for index in 0..=MAX_SYMBOLIC_LINK_DEPTH {
            let name = alloc::format!("\\DosDevices\\walk_depth_{index}");
            let target = if index == MAX_SYMBOLIC_LINK_DEPTH {
                "\\Device\\depth_terminal".into()
            } else { alloc::format!("\\DosDevices\\walk_depth_{}", index + 1) };
            assert_eq!(publish_symbolic_link(&name, NtObject::new_symbolic_link(9500 + index as u64, target)).1,
                NamedObjectState::Created);
        }
        assert_eq!(resolve_symbolic_links("\\DosDevices\\walk_depth_0"), Err(SymbolicLinkResolutionError::Depth));
    }

    #[test]
    fn symbolic_link_walk_does_not_follow_the_link_when_target_is_not_in_path() {
        let link = NtObject::new_symbolic_link(9404, "\\Device\\Target".into());
        assert_eq!(publish_symbolic_link("\\DosDevices\\walk_leaf", link).1, NamedObjectState::Created);
        assert_eq!(resolve_symbolic_links("\\DosDevices\\walk_leaf").unwrap(), "\\Device\\Target");
    }
}
