use block::{BlockError, KResult};

use super::Zram;

impl Zram {
    /// Configure the Linux maximum count of in-flight backing writes.
    /// # C: O(1)
    pub fn set_writeback_batch_size_text(&self, text: &str) -> KResult<()> {
        let batch = text.trim().parse::<u32>().map_err(|_| BlockError::Einval)?;
        if batch == 0 { return Err(BlockError::Einval); }
        self.state.lock().writeback_batch_size = batch;
        Ok(())
    }
}
