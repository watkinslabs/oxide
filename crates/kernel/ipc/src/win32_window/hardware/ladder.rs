//! The activation ladder a removed pointer message runs before the
//! application is handed it: notify the parent chain, ask the clicked window
//! whether it wants activating, act on the answer, then set the cursor.
//!
//! Every step enters a window procedure, so the ladder is a position and the
//! result of the call it is waiting on: the driver performs one step, reports
//! its `LRESULT`, and asks for the next.
use alloc::vec::Vec;
use super::uapi::*;

/// One window-procedure call the ladder makes. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcCall { pub hwnd: u32, pub message: u32, pub wparam: u64, pub lparam: i64 }

/// What the driver must do before the ladder takes its next step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LadderStep {
    /// Enter a window procedure and resume the ladder with the `LRESULT`.
    Send(ProcCall),
    /// Make this window the foreground window; resume with whether it became
    /// foreground, because a refused activation eats the click.
    Activate(u32),
    /// The ladder is over. `eat` says the click never reaches the application.
    Done { eat: bool },
}

/// What the ladder needs about the clicked window's place in the tree.
/// `notify` is the `WM_PARENTNOTIFY` chain the caller resolved, innermost
/// parent first, each already carrying the point in that parent's client
/// coordinates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LadderContext {
    pub hwnd: u32,
    pub hit_test: i32,
    /// The message number before nonclient renumbering; the reference reports
    /// the client form here even for a nonclient click.
    pub origin: u32,
    /// True when this pointer message is a button going down, which is the
    /// only transition that notifies a parent or decides activation.
    pub button_down: bool,
    /// The active window, which a click into already-active windows does not
    /// re-activate.
    pub active: Option<u32>,
    /// The clicked window's root ancestor, which is what gets activated.
    pub root: u32,
    /// The root's window style. A pure child never activates.
    pub root_style: u32,
    pub notify: Vec<ProcCall>,
}

impl LadderContext {
    /// A root that is a child and not a popup owns no activation. # C: O(1)
    fn activates(&self) -> bool {
        self.button_down && self.active != Some(self.hwnd) && self.root_style & (WS_POPUP | WS_CHILD) != WS_CHILD
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase { Notify(usize), MouseActivate, Activated, SetCursor, Single(ProcCall), Done }

/// The ladder's position plus the result of the call it is waiting on.
#[derive(Clone, Debug)]
pub struct Ladder { ctx: LadderContext, phase: Phase, eat: bool, result: Option<Result<u64, ()>> }

impl Ladder {
    /// # C: O(1)
    pub fn new(ctx: LadderContext) -> Self { Self { ctx, phase: Phase::Notify(0), eat: false, result: None } }

    /// A ladder that makes one call and then ends, for the two messages whose
    /// fate the preparation already settled: an error or nowhere hit that only
    /// sets the cursor, and a key that turns into a sent command. # C: O(1)
    pub fn single(call: ProcCall) -> Self { Self { ctx: LadderContext::default(), phase: Phase::Single(call), eat: false, result: None } }

    /// Publish the result of the call the previous step made. # C: O(1)
    pub fn call_result(&mut self, result: Result<u64, ()>) { self.result = Some(result); }

    /// Advance to the next step, consuming any result the previous one
    /// produced. A failed call reads as the zero the reference treats as an
    /// unhandled message. # C: O(1) per step, O(N_parents) over the ladder
    pub fn next(&mut self) -> LadderStep {
        let result = self.result.take().map_or(0, |value| value.unwrap_or(0));
        match self.phase {
            Phase::Notify(index) => self.notify(index),
            Phase::MouseActivate => self.activate_code(result),
            Phase::Activated => {
                // A window that could not be brought to the foreground never
                // sees the click that asked for it.
                if result == 0 { self.eat = true; }
                self.phase = Phase::SetCursor;
                self.next()
            }
            Phase::SetCursor => {
                self.phase = Phase::Done;
                LadderStep::Send(ProcCall { hwnd: self.ctx.hwnd, message: super::super::WM_SETCURSOR,
                    wparam: self.ctx.hwnd as u64, lparam: make_hit_param(self.ctx.hit_test, self.ctx.origin) })
            }
            Phase::Single(call) => { self.phase = Phase::Done; LadderStep::Send(call) }
            Phase::Done => LadderStep::Done { eat: self.eat },
        }
    }

    /// The parent chain is notified before anything is asked about activation.
    /// # C: O(1)
    fn notify(&mut self, index: usize) -> LadderStep {
        if self.ctx.button_down {
            if let Some(call) = self.ctx.notify.get(index).copied() { self.phase = Phase::Notify(index + 1); return LadderStep::Send(call); }
        }
        if !self.ctx.activates() { self.phase = Phase::SetCursor; return self.next(); }
        self.phase = Phase::MouseActivate;
        LadderStep::Send(ProcCall { hwnd: self.ctx.hwnd, message: WM_MOUSEACTIVATE, wparam: self.ctx.root as u64,
            lparam: make_hit_param(self.ctx.hit_test, self.ctx.origin) })
    }

    /// The four documented answers plus the unhandled zero. An answer the
    /// reference does not know activates nothing and eats nothing. # C: O(1)
    fn activate_code(&mut self, code: u64) -> LadderStep {
        let activate = match code {
            MA_NOACTIVATEANDEAT => { self.eat = true; false }
            MA_NOACTIVATE => false,
            MA_ACTIVATEANDEAT => { self.eat = true; true }
            MA_ACTIVATE | 0 => true,
            _ => false,
        };
        if !activate { self.phase = Phase::SetCursor; return self.next(); }
        self.phase = Phase::Activated;
        LadderStep::Activate(self.ctx.root)
    }
}
