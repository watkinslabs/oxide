//! The modal menu-tracking loop as a resumable step machine.
//!
//! The loop cannot run to completion on one kernel stack: every notification it
//! makes to the owner, and every message it does not consume, has to enter a
//! window procedure and be resumed with the result. So the loop is a queue of
//! steps plus the position it is resumed at; the driver performs one step,
//! reports its result, and asks for the next. Geometry, the live windows and
//! the message queue belong to the driver — every decision here is pure.
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use super::popup::{NO_SELECTED_ITEM, TF_ENDMENU, TPM_BUTTONDOWN, TPM_NONOTIFY, TPM_POPUPMENU, TPM_RETURNCMD};
use super::track::{PointerEvent, TrackEffect, Tracker, EXEC_NOTHING, EXEC_POPUP_SHOWN,
    WM_CANCELMODE, WM_MENUSELECT, WM_UNINITMENUPOPUP};
use super::MenuManager;

#[path = "track_keys.rs"]
mod keys;

pub const WM_SETCURSOR: u32 = 0x0020;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_ENTERMENULOOP: u32 = 0x0211;
pub const WM_EXITMENULOOP: u32 = 0x0212;

pub const WM_MOUSEFIRST: u32 = 0x0200;
pub const WM_MOUSELAST: u32 = 0x0209;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_RBUTTONDBLCLK: u32 = 0x0206;
pub const WM_KEYFIRST: u32 = 0x0100;
pub const WM_KEYLAST: u32 = 0x0108;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSCHAR: u32 = 0x0106;

pub const VK_ESCAPE: u32 = 0x1b;
pub const VK_MENU: u32 = 0x12;
pub const VK_END: u32 = 0x23;
pub const VK_HOME: u32 = 0x24;
pub const VK_LEFT: u32 = 0x25;
pub const VK_UP: u32 = 0x26;
pub const VK_RIGHT: u32 = 0x27;
pub const VK_DOWN: u32 = 0x28;
pub const VK_F10: u32 = 0x79;
pub const VK_RETURN: u32 = 0x0d;

/// The `WM_ENTERIDLE` code naming a menu rather than a dialog.
pub const MSGF_MENU: u64 = 2;
/// The `WM_SETCURSOR` hit code the loop reports for the owner's frame.
pub const HTCAPTION: i64 = 2;
/// The `WM_MENUSELECT` word saying tracking is over.
pub const MENUSELECT_CLOSED: u64 = 0xffff_0000;

/// What the modal loop does with one retrieved message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoopAction {
    /// `NtUserEndMenu` asked for the loop to end.
    Cancel,
    /// A pointer event at a screen point; `down`/`up` name the transition.
    ButtonDown { point: (i32, i32), right: bool },
    ButtonUp { point: (i32, i32), right: bool },
    Move { point: (i32, i32) },
    /// Another pointer message inside the tracked range, consumed silently.
    Pointer,
    Key { vk: u32 },
    Char { ch: u16 },
    /// Anything else: dispatched to the window procedure it names.
    Other,
}

/// Classify one message. Pointer coordinates come from the message parameter
/// rather than the queue point, so a synthesised event is placed where it
/// says it is. # C: O(1)
pub fn classify(message: u32, wparam: u64, lparam: i64) -> LoopAction {
    if message == WM_CANCELMODE { return LoopAction::Cancel; }
    if (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&message) {
        let point = ((lparam as u64 as u16 as i16) as i32, ((lparam as u64 >> 16) as u16 as i16) as i32);
        return match message {
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => LoopAction::ButtonDown { point, right: false },
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => LoopAction::ButtonDown { point, right: true },
            WM_LBUTTONUP => LoopAction::ButtonUp { point, right: false },
            WM_RBUTTONUP => LoopAction::ButtonUp { point, right: true },
            WM_MOUSEMOVE => LoopAction::Move { point },
            _ => LoopAction::Pointer,
        };
    }
    if (WM_KEYFIRST..=WM_KEYLAST).contains(&message) {
        return match message {
            WM_KEYDOWN | WM_SYSKEYDOWN => LoopAction::Key { vk: wparam as u32 },
            WM_CHAR | WM_SYSCHAR => LoopAction::Char { ch: wparam as u16 },
            _ => LoopAction::Other,
        };
    }
    LoopAction::Other
}

/// One window-procedure call the loop makes and reads the result of.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProcCall { pub hwnd: u64, pub message: u32, pub wparam: u64, pub lparam: i64 }

/// One message the loop took off the thread's queue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RetrievedMessage { pub hwnd: u64, pub message: u32, pub wparam: u64, pub lparam: i64 }

/// What the driver must do before the loop takes its next step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoopStep {
    /// Notify the menu's owner and resume the loop with the `LRESULT`.
    Send(ProcCall),
    /// Hand one retrieved message to the window procedure it names, the way
    /// the reference dispatches every message the loop does not consume.
    Dispatch(ProcCall),
    /// Apply one tracking decision to the live windows.
    Effect(TrackEffect),
    /// Measure, place and show the top menu at the tracking point.
    ShowTop,
    /// Measure, place and show the submenu of one item, whose owner
    /// notification the previous step already made.
    ShowSub { menu: u32, position: u32, submenu: u32, select_first: bool },
    /// Retire the window showing one menu.
    Close { menu: u32 },
    /// Resolve the press that entered tracking against the tracked menus and
    /// apply it, the way the reference performs it at the entry point.
    PressAt { point: (i32, i32) },
    /// Take the next message off the queue, waiting when it is empty.
    NextMessage,
    /// Tracking is over; report this command.
    Done(i32),
}

/// The tracking loop's resumable position: the tracked menus, the steps still
/// owed to the driver, and the result of the call it last made.
pub struct TrackLoop {
    pub tracker: Tracker,
    flags: u32,
    popup: bool,
    executed: i32,
    steps: VecDeque<LoopStep>,
    current_window: u64,
    enter_idle_sent: bool,
    tearing_down: bool,
    result: Result<u64, ()>,
}

impl TrackLoop {
    /// # C: O(1)
    pub fn new(flags: u32, owner: u32, menu: u32, pt: (i32, i32)) -> Self {
        let mut tracker = Tracker::new(flags, owner, menu, pt);
        if flags & TF_ENDMENU != 0 { tracker.exit = true; }
        Self { tracker, flags, popup: flags & TPM_POPUPMENU != 0, executed: EXEC_NOTHING, steps: VecDeque::new(),
            current_window: 0, enter_idle_sent: false, tearing_down: false, result: Ok(0) }
    }

    /// # C: O(1)
    pub fn owner(&self) -> u64 { self.tracker.owner as u64 }
    /// # C: O(1)
    pub fn flags(&self) -> u32 { self.flags }
    /// # C: O(1)
    pub fn top(&self) -> u32 { self.tracker.top_menu }
    /// # C: O(1)
    pub fn current(&self) -> u32 { self.tracker.current_menu }
    /// The menu tracking follows, and the window showing it. # C: O(1)
    pub fn set_current(&mut self, menu: u32, hwnd: u64) { self.tracker.current_menu = menu; self.current_window = hwnd; }
    /// The result of the call the previous step made. # C: O(1)
    pub fn call_result(&mut self, result: Result<u64, ()>) { self.result = result; }
    /// # C: O(1)
    pub fn last_result(&self) -> Result<u64, ()> { self.result }
    /// `NtUserEndMenu`, or a queue that can no longer answer. # C: O(1)
    pub fn cancel(&mut self) { self.tracker.exit = true; }

    /// Queue the notifications the owner gets before the menu is shown, and
    /// the step that shows it. # C: O(1)
    pub fn begin(&mut self) {
        let owner = self.owner();
        if self.flags & TPM_NONOTIFY == 0 { self.send(owner, WM_ENTERMENULOOP, self.popup as u64, 0); }
        self.send(owner, WM_SETCURSOR, owner, HTCAPTION);
        if self.flags & TPM_NONOTIFY == 0 {
            self.send(owner, WM_INITMENU, self.tracker.top_menu as u64, 0);
            if self.popup { self.send(owner, super::track::WM_INITMENUPOPUP, self.tracker.top_menu as u64, 0); }
        }
        self.steps.push_back(LoopStep::ShowTop);
        // Tracking entered by a press acts on that press before it ever takes
        // a message, so the item under it is selected and its popup opened.
        if self.flags & TPM_BUTTONDOWN != 0 { self.steps.push_back(LoopStep::PressAt { point: self.tracker.pt }); }
    }

    /// Apply the press that entered tracking. A press that names no menu ends
    /// tracking before the loop takes its first message. # C: O(N_items)
    pub fn press(&mut self, menus: &mut MenuManager, event: &PointerEvent) {
        let mut effects: Vec<TrackEffect> = Vec::new();
        if !self.tracker.button_down(menus, event, &mut effects) { self.tracker.exit = true; }
        self.queue_effects(effects);
    }

    /// A popup carrying no item is never tracked: the reference abandons the
    /// loop before its teardown, leaving only the exit notification.
    /// # C: O(1)
    pub fn abandon(&mut self) {
        self.tracker.exit = true;
        self.tearing_down = true;
        self.steps.clear();
        self.exit_steps();
        if self.popup { self.close_top(); }
    }

    /// The next step, or the report that the loop must take a message.
    /// # C: O(N_items)
    pub fn next(&mut self, menus: &mut MenuManager) -> LoopStep {
        if let Some(step) = self.steps.pop_front() { return step; }
        if !self.tracker.exit { return LoopStep::NextMessage; }
        if !self.tearing_down { self.tearing_down = true; self.teardown(menus); return self.next(menus); }
        LoopStep::Done(if self.flags & TPM_RETURNCMD == 0 { 1 } else if self.executed == EXEC_NOTHING { 0 } else { self.executed })
    }

    /// The queue is empty: the owner is told the menu is idle once, and only
    /// then does the loop wait. Reports whether the driver must wait.
    /// # C: O(1)
    pub fn idle(&mut self) -> bool {
        if self.enter_idle_sent { return true; }
        self.enter_idle_sent = true;
        let owner = self.owner();
        let window = if self.popup { self.current_window } else { 0 };
        self.send(owner, WM_ENTERIDLE, MSGF_MENU, window as i64);
        false
    }

    /// Act on one retrieved message, reporting whether it must be taken off
    /// the queue. A message the loop does not consume is dispatched to its own
    /// window procedure; a message that ends tracking without being consumed
    /// stays queued for the application. # C: O(N_items)
    pub fn message(&mut self, menus: &mut MenuManager, msg: RetrievedMessage, event: Option<PointerEvent>) -> bool {
        if msg.hwnd == self.current_window || msg.message != WM_TIMER { self.enter_idle_sent = false; }
        let mut effects: Vec<TrackEffect> = Vec::new();
        let mut remove = false;
        match classify(msg.message, msg.wparam, msg.lparam) {
            LoopAction::Cancel => { self.tracker.exit = true; return true; }
            LoopAction::ButtonDown { .. } => {
                let Some(event) = event else { return true; };
                remove = self.tracker.button_down(menus, &event, &mut effects);
                self.tracker.exit = !remove;
            }
            LoopAction::ButtonUp { .. } => {
                let Some(event) = event else { return true; };
                if event.menu.is_some() {
                    let chosen = self.tracker.button_up(menus, &event, &mut effects);
                    self.executed = chosen;
                    self.tracker.exit = chosen != EXEC_NOTHING;
                    remove = self.tracker.exit;
                } else { self.tracker.exit = !self.popup; }
            }
            LoopAction::Move { .. } => {
                if let Some(event) = event { if event.menu.is_some() { self.tracker.mouse_move(menus, &event, &mut effects); } }
            }
            LoopAction::Pointer => {}
            LoopAction::Key { vk } => { remove = true; self.key_down(menus, vk, &mut effects); }
            LoopAction::Char { ch } => {
                remove = true;
                let chosen = self.tracker.char_key(menus, ch, &mut effects);
                if self.tracker.exit && chosen != EXEC_POPUP_SHOWN { self.executed = chosen; }
            }
            LoopAction::Other => {
                self.steps.push_back(LoopStep::Dispatch(ProcCall { hwnd: msg.hwnd, message: msg.message, wparam: msg.wparam, lparam: msg.lparam }));
                return true;
            }
        }
        self.queue_effects(effects);
        if !self.tracker.exit { remove = true; }
        remove
    }

    /// Queue the steps that open a submenu: its owner is told to update it
    /// before it is measured, exactly as the reference orders the two.
    /// # C: O(1)
    pub fn open_submenu(&mut self, menu: u32, position: u32, submenu: u32, select_first: bool) {
        if self.flags & TPM_NONOTIFY == 0 {
            let owner = self.owner();
            self.push_front(LoopStep::ShowSub { menu, position, submenu, select_first });
            self.push_front(LoopStep::Send(ProcCall { hwnd: owner, message: super::track::WM_INITMENUPOPUP, wparam: submenu as u64, lparam: position as i64 }));
            return;
        }
        self.push_front(LoopStep::ShowSub { menu, position, submenu, select_first });
    }

    /// Queue the retirement of one popup window and the notification that goes
    /// with it, innermost first. # C: O(N_closed)
    pub fn close_popups(&mut self, closed: &[u32]) {
        let owner = self.owner();
        for menu in closed.iter().rev() {
            if self.flags & TPM_NONOTIFY == 0 {
                self.push_front(LoopStep::Send(ProcCall { hwnd: owner, message: WM_UNINITMENUPOPUP, wparam: *menu as u64, lparam: 0 }));
            }
            self.push_front(LoopStep::Close { menu: *menu });
        }
    }

    /// Queue one decision's effects, turning the owner notification among them
    /// into the call it is. # C: O(N_effects)
    fn queue_effects(&mut self, effects: Vec<TrackEffect>) {
        let owner = self.owner();
        for effect in effects {
            match effect {
                TrackEffect::MenuSelect { wparam, lparam } => self.send(owner, WM_MENUSELECT, wparam, lparam),
                other => self.steps.push_back(LoopStep::Effect(other)),
            }
        }
    }

    fn send(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: i64) {
        self.steps.push_back(LoopStep::Send(ProcCall { hwnd, message, wparam, lparam }));
    }

    fn push_front(&mut self, step: LoopStep) { self.steps.push_front(step); }

    /// Unwind the chain, clear the highlight and tell the owner tracking is
    /// over, in the order the reference unwinds them. # C: O(N_items)
    fn teardown(&mut self, menus: &mut MenuManager) {
        let top = self.tracker.top_menu;
        self.steps.push_back(LoopStep::Effect(TrackEffect::HideSubPopups { menu: top }));
        if self.popup { self.close_top(); }
        let mut effects = Vec::new();
        let tracker = self.tracker;
        tracker.select_item(menus, &mut effects, top, NO_SELECTED_ITEM, false, 0);
        self.queue_effects(effects);
        self.send(self.tracker.owner as u64, WM_MENUSELECT, MENUSELECT_CLOSED, 0);
        self.exit_steps();
    }

    fn close_top(&mut self) {
        let (owner, top) = (self.owner(), self.tracker.top_menu);
        self.steps.push_back(LoopStep::Close { menu: top });
        if self.flags & TPM_NONOTIFY == 0 { self.send(owner, WM_UNINITMENUPOPUP, top as u64, 0); }
    }

    fn exit_steps(&mut self) {
        let (owner, popup) = (self.owner(), self.popup);
        self.send(owner, WM_EXITMENULOOP, popup as u64, 0);
    }
}

#[cfg(test)]
#[path = "tests/track_loop.rs"]
mod tests;
