//! Protected canonical system-colour pens.
//!
//! One solid width-one pen per system colour role, the exact analogue of the
//! protected system brushes: the identity is cached so repeated queries answer
//! the same handle, the pen is marked system so application deletion cannot
//! free it, and a changed role colour retires the cached pen for a new one.
//! Control borders and window frames are drawn with these, so a role that
//! answers nothing is a control with no border.
use super::*;

const PS_SOLID: i32 = 0;
const SYSTEM_PEN_WIDTH: i32 = 1;

#[derive(Default)]
pub struct SystemPens { handles: [Option<u32>; SYSTEM_COLOR_COUNT], values: [u32; SYSTEM_COLOR_COUNT] }

impl GdiManager {
    /// Allocate at most one canonical solid pen for each represented role.
    /// # C: O(N_pens)
    pub fn system_pen(&mut self, role: SystemColor) -> Result<u32, GdiError> {
        self.system_pen_value(role, role.color())
    }

    /// The cached pen is reused only while it still carries the role's current
    /// colour, so a changed system colour produces a new pen. # C: O(N_objects)
    pub fn system_pen_value(&mut self, role: SystemColor, value: u32) -> Result<u32, GdiError> {
        let slot = role as usize;
        if let Some(handle) = self.system_pens.handles[slot].filter(|_| self.system_pens.values[slot] == value) {
            return if self.contains_object(handle) { Ok(handle) } else { Err(GdiError::NoSuchObject) };
        }
        let handle = self.create_pen(PS_SOLID, SYSTEM_PEN_WIDTH, value)?;
        self.system_pens.handles[slot] = Some(handle);
        self.system_pens.values[slot] = value;
        Ok(handle)
    }

    /// A system pen is protected from application deletion. # C: O(N_roles)
    pub fn is_system_pen(&self, handle: u32) -> bool {
        self.system_pens.handles.iter().any(|candidate| *candidate == Some(handle))
    }
}

#[cfg(test)]
#[path = "tests/system_pen.rs"]
mod tests;
