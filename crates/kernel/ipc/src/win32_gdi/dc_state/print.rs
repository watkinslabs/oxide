//! Document and page job results, and the escape and spool channels beside them.
//!
//! No print driver is loaded, so every job call resolves its device context and
//! then reports the null print driver's own result. A call that cannot resolve
//! its device context reports the spooler error instead.
use super::{GdiError, GdiManager};

/// A print job call whose device context could not be resolved.
pub const SP_ERROR: i32 = -1;
/// The null print driver starts a page.
pub const START_PAGE_RESULT: i32 = 1;
/// Every other null print driver job call reports no job identifier.
pub const JOB_RESULT: i32 = 0;
/// Spooler initialisation succeeds without a spooler.
pub const INIT_SPOOL_RESULT: u32 = 1;
/// No spool message is ever queued.
pub const SPOOL_MESSAGE_RESULT: u32 = 0;
/// The null driver understands no device escape.
pub const EXT_ESCAPE_RESULT: i32 = 0;

impl GdiManager {
    /// Resolve a device context for a print job call, reporting the spooler
    /// error when it cannot be resolved and the driver result when it can.
    /// # C: O(DCs)
    pub fn print_job_result(&self, dc: u32, driver_result: i32) -> i32 {
        match self.dc_attr(dc) { Ok(_) => driver_result, Err(_) => SP_ERROR }
    }

    /// A device escape resolves its device context, then reports that the null
    /// driver handled nothing. An unresolvable context reports the same zero.
    /// # C: O(DCs)
    pub fn ext_escape(&self, dc: u32) -> i32 {
        let _ = self.dc_attr(dc);
        EXT_ESCAPE_RESULT
    }

    /// Reset a device context to a new device mode. No print or display driver
    /// accepts a mode change, so the reset never happens and the visible
    /// region is left alone. # C: O(DCs)
    pub fn reset_device_mode(&self, dc: u32) -> Result<bool, GdiError> {
        self.dc_attr(dc)?;
        Ok(false)
    }
}

#[cfg(test)]
#[path = "tests/print.rs"]
mod tests;
