//! Source and dependency context for one native Wine Unixlib load.

use alloc::{vec, vec::Vec};
use super::{admit_dependency_closure, LoadError};

/// One canonical VFS source retained for a native Unixlib load transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixlibSourceObject { pub name: Vec<u8>, pub path: Vec<u8>, pub file: Vec<u8> }

/// Complete source context; objects are dependency-first and root-last.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixlibLoadContext { pub root_name: Vec<u8>, pub objects: Vec<UnixlibSourceObject> }

impl UnixlibLoadContext {
    /// Validate source identity, path ownership, and root placement.
    /// # C: O(objects * object_name_length)
    pub fn validate(&self) -> Result<(), LoadError> {
        if self.root_name.is_empty() || self.objects.is_empty() || self.objects.last().map(|o| o.name.as_slice()) != Some(self.root_name.as_slice()) { return Err(LoadError::Einval); }
        for (index, object) in self.objects.iter().enumerate() {
            if object.name.is_empty() || object.name.len() > 255 || object.name.iter().any(|byte| *byte == 0)
                || object.path.first().copied() != Some(b'/') || object.path.iter().any(|byte| *byte == 0)
                || object.file.is_empty() { return Err(LoadError::Einval); }
            if self.objects[..index].iter().any(|prior| prior.name == object.name) { return Err(LoadError::Einval); }
        }
        Ok(())
    }
}

/// Resolve and validate the source/dependency context for fixed Wine ABI.
/// `open` is the canonical VFS provider for each `DT_NEEDED` name.
/// # C: O(objects * (dynamic entries + symbols))
pub fn build_load_context<F>(root_name: &[u8], root_path: &[u8], root_file: &[u8], mut open: F)
    -> Result<UnixlibLoadContext, LoadError>
where F: FnMut(&[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut sources = vec![UnixlibSourceObject { name: root_name.to_vec(), path: root_path.to_vec(), file: root_file.to_vec() }];
    let scope = admit_dependency_closure(root_name, root_file, |name| {
        let (path, file) = open(name)?;
        if !sources.iter().any(|source| source.name == name) { sources.push(UnixlibSourceObject { name: name.to_vec(), path, file: file.clone() }); }
        Some(file)
    })?;
    let mut objects = Vec::with_capacity(scope.len());
    for admitted in scope {
        objects.push(sources.iter().find(|source| source.name == admitted.name).cloned().ok_or(LoadError::Enoexec)?);
    }
    let context = UnixlibLoadContext { root_name: root_name.to_vec(), objects };
    context.validate()?;
    Ok(context)
}
