//! `NtUserAssociateInputContext` decision: which flags are admitted, which
//! ownership checks run and in what order, and whether the window record's
//! association changes.
use super::*;

/// Window facts the decision reads from the canonical window owner.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowFacts {
    pub thread_id: u64,
    pub imc: Option<ImcId>,
    /// The window holds the input focus.
    pub focused: bool,
}

/// `window` is None for a handle the calling process does not own.
/// `ctx_thread` is None for a handle the input-context object type does not own.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AssociateFacts {
    pub flags: u32,
    pub ctx: Option<ImcId>,
    pub ctx_thread: Option<u64>,
    pub default_ctx: Option<ImcId>,
    pub current_tid: u64,
    pub window: Option<WindowFacts>,
}

/// `assign` is the association the window record takes when the call changes it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AssociateOutcome { pub result: u32, pub assign: Option<Option<ImcId>> }

const FAILED: AssociateOutcome = AssociateOutcome { result: AICR_FAILED, assign: None };

/// Only the three admitted flag words reach an ownership check; a context from
/// another thread, or a window the calling thread does not own while a context
/// is named, is refused before the record is read. Replacing the association of
/// the focused window reports the focus change. # C: O(1)
pub fn associate(facts: AssociateFacts) -> AssociateOutcome {
    if !matches!(facts.flags, 0 | IACE_IGNORENOCONTEXT | IACE_DEFAULT) { return FAILED; }
    let ctx = if facts.flags == IACE_DEFAULT {
        let Some(default) = facts.default_ctx else { return FAILED; };
        Some(default)
    } else {
        if facts.ctx.is_some() && facts.ctx_thread != Some(facts.current_tid) { return FAILED; }
        facts.ctx
    };
    let Some(window) = facts.window else { return FAILED; };
    if ctx.is_some() && window.thread_id != facts.current_tid { return FAILED; }
    if facts.flags == IACE_IGNORENOCONTEXT && window.imc.is_none() { return AssociateOutcome { result: AICR_OK, assign: None }; }
    let result = if window.imc != ctx && window.focused { AICR_FOCUS_CHANGED } else { AICR_OK };
    AssociateOutcome { result, assign: Some(ctx) }
}
