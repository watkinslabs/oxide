//! Canonical class registration, lookup and class-bound window creation.
use super::*;
impl WindowManager {
    /// Register one process-local window class and retain its procedure. # C: O(N_classes)
    pub fn register_class(&mut self, name: &[u16], wndproc: u64) -> Result<u16, WindowError> {
        self.register_class_with_extra(name, wndproc, 0)
    }
    /// Retain the admitted per-window allocation size on the canonical class. # C: O(N_classes + name)
    pub fn register_class_with_extra(&mut self, name: &[u16], wndproc: u64, cb_wnd_extra: i32) -> Result<u16, WindowError> {
        self.register_class_with_encoding(name, wndproc, cb_wnd_extra, true)
    }
    /// Retain class procedure encoding with its extra-byte contract. # C: O(N_classes + name)
    pub fn register_class_with_encoding(&mut self, name: &[u16], wndproc: u64, cb_wnd_extra: i32, unicode: bool) -> Result<u16, WindowError> {
        self.register_class_with_style(name, wndproc, cb_wnd_extra, unicode, 0)
    }
    /// Admit the raw WNDCLASSEX style into the canonical class record. # C: O(N_classes + name)
    pub fn register_class_with_style(&mut self, name: &[u16], wndproc: u64, cb_wnd_extra: i32, unicode: bool, style: u32) -> Result<u16, WindowError> {
        self.register_class_with_background(name, wndproc, cb_wnd_extra, unicode, style, 0)
    }
    /// Retain the raw hbrBackground with the class; the default procedure erases with it. # C: O(N_classes + name)
    pub fn register_class_with_background(&mut self, name: &[u16], wndproc: u64, cb_wnd_extra: i32, unicode: bool, style: u32, background: u64) -> Result<u16, WindowError> {
        let cb_wnd_extra = u32::try_from(cb_wnd_extra).ok().filter(|size| *size <= extra::MAX_WINDOW_EXTRA as u32).ok_or(WindowError::InvalidParent)?;
        if name.is_empty() || self.classes.iter().any(|class| same_name(&class.name, name)) { return Err(WindowError::InvalidParent); }
        let atom = self.next_atom;
        let next = self.next_atom.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        let mut owned_name = Vec::new();
        owned_name.try_reserve_exact(name.len()).map_err(|_| WindowError::NoMemory)?;
        owned_name.extend_from_slice(name);
        self.classes.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.classes.push(WindowClass { name: owned_name, wndproc, atom, cb_wnd_extra, unicode, style, background });
        self.next_atom = next;
        Ok(atom)
    }
    /// Resolve a registered class for native Wine window creation. # C: O(N_classes)
    pub fn class_wndproc(&self, name: &[u16]) -> Option<u64> {
        self.classes.iter().find(|class| same_name(&class.name, name)).map(|class| class.wndproc)
    }
    /// Resolve a registered class atom without leaving the canonical owner. # C: O(N_classes)
    pub fn class_wndproc_by_atom(&self, atom: u16) -> Option<u64> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.wndproc)
    }
    /// Query the registered per-window byte extent without creating a window. # C: O(N_classes)
    pub fn class_extra_by_atom(&self, atom: u16) -> Option<u32> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.cb_wnd_extra)
    }
    /// Class background brush of a window; None for an unclassed HWND. # C: O(N_windows + N_classes)
    pub fn class_background(&self, id: WindowId) -> Option<u64> {
        let atom = self.get(id)?.class_atom?;
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.background)
    }
    /// Resolve a registered class name from its atom. # C: O(N_classes)
    pub fn class_name_by_atom(&self, atom: u16) -> Option<&[u16]> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.name.as_slice())
    }
    /// Return the canonical class tuple for a name. # C: O(N_classes)
    pub fn class_info(&self, name: &[u16]) -> Option<(u16, u64, &[u16])> {
        self.classes.iter().find(|class| same_name(&class.name, name)).map(|class| (class.atom, class.wndproc, class.name.as_slice()))
    }
    /// Return the canonical class tuple for an atom. # C: O(N_classes)
    pub fn class_info_by_atom(&self, atom: u16) -> Option<(u16, u64, &[u16])> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| (class.atom, class.wndproc, class.name.as_slice()))
    }
    /// Create a window while retaining its class identity in the owner. # C: O(N_classes + N_windows)
    pub fn create_class(&mut self, owner_tid: u64, parent: Option<WindowId>, name: &[u16]) -> Result<WindowId, WindowError> {
        let atom = self.classes.iter().find(|class| same_name(&class.name, name)).ok_or(WindowError::NoSuchWindow)?.atom;
        self.create_class_atom(owner_tid, parent, atom)
    }
    /// Create a window from a registered atom in the owner. # C: O(N_windows)
    pub fn create_class_atom(&mut self, owner_tid: u64, parent: Option<WindowId>, atom: u16) -> Result<WindowId, WindowError> {
        let class = self.classes.iter().find(|class| class.atom == atom).ok_or(WindowError::NoSuchWindow)?;
        let wndproc = class.wndproc;
        let unicode = class.unicode;
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let extra = WindowExtra::new(class.cb_wnd_extra as i32, 0).map_err(|error| match error {
            LongPtrError::NoMemory => WindowError::NoMemory,
            _ => WindowError::InvalidParent,
        })?;
        let window = self.create(owner_tid, parent, wndproc)?;
        let entry = &mut self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1;
        entry.class_atom = Some(atom);
        entry.unicode = unicode;
        entry.extra = extra;
        Ok(window)
    }
    /// Return the registered class name associated with one window. # C: O(N_windows + N_classes)
    pub fn class_name(&self, window: WindowId) -> Option<&[u16]> {
        let atom = self.get(window)?.class_atom?;
        self.class_name_by_atom(atom)
    }
    /// Remove a class only after all windows carrying its atom are gone. # C: O(N_classes + N_windows)
    pub fn unregister_class(&mut self, name: &[u16]) -> Result<(), WindowError> {
        let index = self.classes.iter().position(|class| same_name(&class.name, name)).ok_or(WindowError::NoSuchWindow)?;
        let atom = self.classes[index].atom;
        if self.windows.iter().any(|(_, window)| window.class_atom == Some(atom)) { return Err(WindowError::ClassInUse); }
        self.classes.remove(index);
        Ok(())
    }
}
