//! Desktop publication in the existing object namespace; no private name map.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopPublishError { InvalidPath, WrongType, WrongStation, ParentMissing, NoMemory, IdExhausted }

fn next_id() -> Result<u64, DesktopPublishError> {
    let namespace = OBJECT_NAMESPACE.lock();
    namespace.next_id.fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1)).map_err(|_| DesktopPublishError::IdExhausted)
}
/// Trusted bootstrap uses the same namespace allocator and publication rules. # C: O(namespace + path)
pub fn create_window_station(path: &str) -> Result<(Arc<NtObject>, NamedObjectState), DesktopPublishError> {
    publish_window_station(path, NtObject::new(NtObjectType::WindowStation, next_id()?))
}
/// Create/reopen under an already-authorized canonical station. # C: O(namespace + path)
pub fn create_desktop(path: &str, station: Arc<NtObject>) -> Result<(Arc<NtObject>, NamedObjectState), DesktopPublishError> {
    let object = NtObject::new_desktop(next_id()?, station).map_err(|_| DesktopPublishError::WrongType)?;
    publish_desktop(path, object)
}

/// Publish/reopen a station below a canonical directory. # C: O(namespace + path)
pub fn publish_window_station(path: &str, object: Arc<NtObject>) -> Result<(Arc<NtObject>, NamedObjectState), DesktopPublishError> {
    publish(path, object, NtObjectType::WindowStation)
}
/// Publish/reopen a desktop below its exact canonical station. # C: O(namespace + path)
pub fn publish_desktop(path: &str, object: Arc<NtObject>) -> Result<(Arc<NtObject>, NamedObjectState), DesktopPublishError> {
    publish(path, object, NtObjectType::Desktop)
}
fn publish(path: &str, object: Arc<NtObject>, kind: NtObjectType) -> Result<(Arc<NtObject>, NamedObjectState), DesktopPublishError> {
    path_components(path).map_err(|_| DesktopPublishError::InvalidPath)?;
    if object.kind() != kind { return Err(DesktopPublishError::WrongType); }
    let parent_path = parent(path).ok_or(DesktopPublishError::InvalidPath)?;
    let station = if kind == NtObjectType::Desktop {
        Some(object.desktop().ok_or(DesktopPublishError::WrongType)?.station())
    } else { None };
    let mut owned = String::new();owned.try_reserve_exact(path.len()).map_err(|_| DesktopPublishError::NoMemory)?;owned.push_str(path);
    let mut namespace = OBJECT_NAMESPACE.lock();seed(&mut namespace);
    let parent = namespace.objects.iter().find(|entry| equal(&entry.path,parent_path)).ok_or(DesktopPublishError::ParentMissing)?;
    if let Some(station) = station {
        if !Arc::ptr_eq(&station,&parent.object) { return Err(DesktopPublishError::WrongStation); }
    } else if parent.object.kind() != NtObjectType::Directory { return Err(DesktopPublishError::ParentMissing); }
    if let Some(existing) = namespace.objects.iter().find(|entry| equal(&entry.path,path)) {
        return Ok((existing.object.clone(),if existing.object.kind()==kind {NamedObjectState::Existing}else{NamedObjectState::TypeMismatch}));
    }
    namespace.objects.try_reserve(1).map_err(|_| DesktopPublishError::NoMemory)?;
    namespace.objects.push(NamedObject {path:owned,object:object.clone(),permanent:false});
    Ok((object,NamedObjectState::Created))
}

#[cfg(test)]
#[path="desktop/tests.rs"] mod tests;
