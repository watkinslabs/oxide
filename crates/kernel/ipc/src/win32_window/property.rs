//! Canonical per-window properties and atom-name resolution (`31fj`).

use alloc::vec::Vec;

use super::{OwnedWindow, UserAtomTable, WindowError, WindowId, WindowManager};

pub const MAX_PROPERTY_NAME: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyOrigin { String, Atom }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowProperty { pub atom: u16, pub origin: PropertyOrigin, pub value: u64 }

#[derive(Clone, Debug, Default)]
pub struct WindowProperties { entries: Vec<WindowProperty> }

impl WindowProperties {
    pub fn new() -> Self { Self { entries: Vec::new() } }
    pub fn get(&self, atom: u16) -> Option<u64> { self.entries.iter().find(|entry| entry.atom == atom).map(|entry| entry.value) }
    pub fn set(&mut self, atom: u16, origin: PropertyOrigin, value: u64) -> Result<Option<WindowProperty>, WindowError> {
        if atom == 0 { return Err(WindowError::InvalidParent); }
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.atom == atom) {
            let previous = *entry;
            entry.origin = origin; entry.value = value; return Ok(Some(previous))
        }
        self.entries.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.entries.push(WindowProperty { atom, origin, value });
        Ok(None)
    }
    pub fn remove(&mut self, atom: u16) -> Option<WindowProperty> {
        let index = self.entries.iter().position(|entry| entry.atom == atom)?;
        Some(self.entries.swap_remove(index))
    }
    pub fn clear(&mut self) { self.entries.clear(); }
    pub fn entries(&self) -> &[WindowProperty] { &self.entries }
    pub fn string_atoms(&self) -> Vec<u16> { self.entries.iter().filter_map(|entry| (entry.origin == PropertyOrigin::String).then_some(entry.atom)).collect() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyName { Atom(u16), String(Vec<u16>) }

impl UserAtomTable {
    pub fn property_atom_for_set(&mut self, name: &[u16]) -> Option<u16> {
        if name.is_empty() || name.len() > MAX_PROPERTY_NAME { return None; }
        if let Some(index) = self.names.iter().position(|entry| entry.as_ref().is_some_and(|entry| super::same_name(&entry.name, name))) {
            let refs = self.names[index].as_ref()?.property_refs.checked_add(1)?;
            self.names[index].as_mut()?.property_refs = refs;
            return u16::try_from(0xc000usize + index + 1).ok();
        }
        let index = self.names.iter().position(Option::is_none).unwrap_or(self.names.len());
        if index >= 0x4000 - 1 { return None; }
        let entry = Some(super::AtomName { name: name.to_vec(), permanent: false, property_refs: 1 });
        if index == self.names.len() { self.names.push(entry); } else { self.names[index] = entry; }
        u16::try_from(0xc000usize + index + 1).ok()
    }
    pub fn property_atom_for_lookup(&self, name: &[u16]) -> Option<u16> {
        if name.is_empty() || name.len() > MAX_PROPERTY_NAME { return None; }
        self.names.iter().position(|entry| entry.as_ref().is_some_and(|entry| super::same_name(&entry.name, name))).and_then(|index| u16::try_from(0xc000usize + index + 1).ok())
    }
    pub fn release_property_atom(&mut self, atom: u16) {
        let Some(index) = atom.checked_sub(0xc000).and_then(|value| value.checked_sub(1)).map(usize::from) else { return; };
        let Some(Some(entry)) = self.names.get_mut(index) else { return; };
        if entry.property_refs == 0 { return; }
        entry.property_refs -= 1;
        if entry.property_refs == 0 && !entry.permanent { self.names[index] = None; }
    }
}

impl OwnedWindow {
    pub fn properties(&self) -> &WindowProperties { &self.properties }
    pub fn properties_mut(&mut self) -> &mut WindowProperties { &mut self.properties }
}

impl WindowManager {
    pub fn set_property(&mut self, window: WindowId, atom: u16, origin: PropertyOrigin, value: u64) -> Result<Option<WindowProperty>, WindowError> {
        let entry = &mut self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1;
        entry.properties_mut().set(atom, origin, value)
    }
    pub fn get_property(&self, window: WindowId, atom: u16) -> Result<Option<u64>, WindowError> {
        let entry = &self.windows.iter().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1;
        Ok(entry.properties().get(atom))
    }
    pub fn remove_property(&mut self, window: WindowId, atom: u16) -> Result<Option<WindowProperty>, WindowError> {
        let entry = &mut self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1;
        Ok(entry.properties_mut().remove(atom))
    }
    pub fn property_atoms(&self, window: WindowId) -> Result<Vec<u16>, WindowError> {
        let entry = &self.windows.iter().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1;
        Ok(entry.properties().string_atoms())
    }
    pub fn destroy_with_property_atoms(&mut self, window: WindowId) -> Result<(super::WindowRecord, Vec<u16>), WindowError> {
        let order = self.destruction_order(window).ok_or(WindowError::NoSuchWindow)?;
        let mut atoms = Vec::new();
        for id in &order { atoms.extend(self.property_atoms(*id)?); }
        let record = self.destroy(window)?;
        Ok((record, atoms))
    }
}

#[cfg(test)]
#[path = "property/tests.rs"]
mod tests;
