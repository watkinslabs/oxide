//! The window record's input-context association, and the window facts the
//! association decision reads.
use super::*;
use crate::win32_imc::{ImcId, WindowFacts};

impl WindowManager {
    /// # C: O(N_windows)
    pub fn window_imc(&self, id: WindowId) -> Option<ImcId> { self.get(id)?.imc }

    /// # C: O(N_windows)
    pub fn set_window_imc(&mut self, id: WindowId, imc: Option<ImcId>) -> Result<(), WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        record.imc = imc;
        Ok(())
    }

    /// None for a handle this manager does not own. # C: O(N_windows)
    pub fn imc_window_facts(&self, id: WindowId) -> Option<WindowFacts> {
        let record = self.get(id)?;
        Some(WindowFacts { thread_id: record.owner_tid, imc: record.imc, focused: self.focus == Some(id) })
    }
}

#[cfg(test)]
#[path = "tests/imc_assoc.rs"]
mod tests;
