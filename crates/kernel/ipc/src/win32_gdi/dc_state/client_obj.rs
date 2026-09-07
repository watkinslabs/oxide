//! Opaque client-owned object handles.
//!
//! The kernel keeps only the handle and its object type; the client owns
//! whatever the handle stands for. Metafile and metafile-device-context
//! handles reach the object table this way.
use super::{GdiError, GdiManager};

impl GdiManager {
    /// Allocate a handle of a caller-chosen object type. Type zero marks a free
    /// table entry and is never allocated. # C: O(1) amortized
    pub fn create_client_obj(&mut self, kind: u32) -> Result<u32, GdiError> {
        if kind == 0 { return Err(GdiError::InvalidDimensions); }
        self.client_objs.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        let handle = self.allocate(kind & !crate::win32_gdi::SLOT_MASK)?;
        self.client_objs.push(handle);
        Ok(handle)
    }

    /// Release a client object handle; a handle the table does not hold is
    /// refused rather than silently accepted. # C: O(N_client_objects)
    pub fn delete_client_obj(&mut self, handle: u32) -> Result<(), GdiError> {
        let index = self.client_objs.iter().position(|candidate| *candidate == handle).ok_or(GdiError::NoSuchObject)?;
        self.client_objs.remove(index);
        Ok(())
    }

    /// Whether a handle names a live client object. # C: O(N_client_objects)
    pub fn contains_client_obj(&self, handle: u32) -> bool { self.client_objs.contains(&handle) }
}

#[cfg(test)]
#[path = "tests/client_obj.rs"]
mod tests;
