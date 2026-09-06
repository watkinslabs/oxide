//! Consume an elapsed queue deadline against canonical caret identity and phase.
use super::{CaretState,CaretCommit};
use super::super::{WindowManager,ExpiredCaretCommit};

impl WindowManager {
    /// Reject stale expiry before changing phase; publication follows after the caller unlocks.
    /// # C: O(windows + queues)
    pub fn apply_expired_caret(&mut self,tid:u64,expired:ExpiredCaretCommit)->Option<CaretCommit>{
        if expired.owner_tid!=tid||self.get(expired.hwnd)?.owner_tid!=tid{return None;}
        let queue=&mut self.queues.iter_mut().find(|(owner,_)|*owner==tid)?.1;
        let old=queue.caret;
        if old.hwnd!=Some(expired.hwnd)||old.hide_depth!=0||queue.caret_generation!=expired.generation{return None;}
        if queue.caret_blink.hwnd!=Some(expired.hwnd)||queue.caret_blink.owner_tid!=tid
            ||queue.caret_blink.generation!=expired.generation||queue.caret_blink.deadline_ns.is_none(){return None;}
        let generation=queue.caret_generation.checked_add(1)?;
        queue.caret.on=!old.on;
        queue.caret_generation=generation;queue.caret_blink.generation=generation;
        Some(CaretCommit{transition:CaretState::transition(old,queue.caret),generation})
    }
}

#[cfg(test)]
#[path="phase/tests.rs"]mod tests;
