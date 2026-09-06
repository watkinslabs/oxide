//! Object-wide handle lifetime, serialized with canonical name removal.
use super::*;
const MAX_OBJECT_HANDLES: u32 = u32::MAX;

pub(in super::super) fn retain_handle(object: &NtObject) -> bool {
    let _namespace = OBJECT_NAMESPACE.lock();
    object.handle_refs.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |count| if count < MAX_OBJECT_HANDLES { Some(count + 1) } else { None }).is_ok()
}

pub(in super::super) fn release_handle(object: &Arc<NtObject>) -> bool {
    let mut namespace = OBJECT_NAMESPACE.lock();
    let previous = object.handle_refs.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| count.checked_sub(1));
    hal::kassert!(previous.is_ok(), "NT object handle count underflow");
    let last = previous == Ok(1);
    if last { unlink_temporary(&mut namespace, object); }
    last
}

/// Compatibility caller hint is not authoritative across process handle tables. # C: O(namespace)
pub fn release_temporary(object: &Arc<NtObject>, _local_has_live_handle: bool) {
    let mut namespace = OBJECT_NAMESPACE.lock();
    if object.handle_refs.load(Ordering::Acquire) == 0 { unlink_temporary(&mut namespace, object); }
}

fn unlink_temporary(namespace: &mut Namespace, object: &Arc<NtObject>) {
    if let Some(index) = namespace.objects.iter().position(|entry|
        !entry.permanent && Arc::ptr_eq(&entry.object, object)) { namespace.objects.remove(index); }
}
