//! Accepted input and message-time key state belong to the window owner and its queues.
use super::*;
const KEY_COUNT: usize = 256;
const DOWN: u8 = 0x80;
const RECENT: u8 = 0x40;
const TOGGLE: u8 = 1;
const VK_SHIFT: u8 = 0x10;
const VK_CONTROL: u8 = 0x11;
const VK_MENU: u8 = 0x12;
const VK_LSHIFT: u8 = 0xa0;
const VK_RSHIFT: u8 = 0xa1;
const VK_LCONTROL: u8 = 0xa2;
const VK_RCONTROL: u8 = 0xa3;
const VK_LMENU: u8 = 0xa4;
const VK_RMENU: u8 = 0xa5;
const RIGHT_SHIFT_SCAN: u8 = 0x36;
const EXTENDED: u32 = 1 << 24;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;

#[derive(Clone)]
pub(super) struct KeyboardState { bytes: [u8; KEY_COUNT] }
impl Default for KeyboardState { fn default() -> Self { Self { bytes: [0; KEY_COUNT] } } }
#[derive(Clone, Copy)]
pub(super) struct KeyTransition { key: u8, pressed: bool }
#[derive(Clone, Copy)]
pub(super) struct QueuedMessage { pub message: WinMessage, pub key: Option<KeyTransition> }

fn generic(key: u8) -> u8 {
    match key { VK_LSHIFT | VK_RSHIFT => VK_SHIFT, VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
        VK_LMENU | VK_RMENU => VK_MENU, _ => key }
}
fn sided(key: u8, lparam: i64) -> u8 {
    let right = lparam as u32 & EXTENDED != 0;
    match key { VK_SHIFT => if (lparam >> 16) as u8 == RIGHT_SHIFT_SCAN { VK_RSHIFT } else { VK_LSHIFT },
        VK_CONTROL => if right { VK_RCONTROL } else { VK_LCONTROL },
        VK_MENU => if right { VK_RMENU } else { VK_LMENU }, _ => key }
}
impl KeyboardState {
    fn set(&mut self, key: u8, down: u8) {
        let state = &mut self.bytes[key as usize];
        if down != 0 { if *state & DOWN == 0 { *state ^= TOGGLE; } *state |= down; }
        else { *state &= !DOWN; }
    }
    fn apply(&mut self, transition: KeyTransition, asynchronous: bool) {
        let key = transition.key;
        self.set(key, if transition.pressed { DOWN | if asynchronous { RECENT } else { 0 } } else { 0 });
        let pair = match generic(key) { VK_SHIFT => Some((VK_LSHIFT, VK_RSHIFT)),
            VK_CONTROL => Some((VK_LCONTROL, VK_RCONTROL)), VK_MENU => Some((VK_LMENU, VK_RMENU)), _ => None };
        if let Some((left, right)) = pair {
            self.set(generic(key), (self.bytes[left as usize] | self.bytes[right as usize]) & DOWN);
        }
    }
    fn snapshot(&self) -> [u8; KEY_COUNT] { self.bytes.map(|value| value & (DOWN | TOGGLE)) }
}

impl MessageQueue {
    pub(super) fn read_entry(&mut self, index: usize, remove: bool) -> Option<WinMessage> {
        if !remove { return self.messages.get(index).map(|entry| entry.message); }
        let entry = self.messages.remove(index)?;
        if let Some(transition) = entry.key { self.keyboard.apply(transition, false); }
        Some(entry.message)
    }
}

impl WindowManager {
    /// Only accepted backend key input changes physical state; ordinary PostMessage does not.
    /// # C: O(windows + queues); # Sleeps: no
    pub fn post_compositor_key(&mut self, id: WindowId, mut message: WinMessage) -> Result<(), WindowError> {
        let pressed = match message.message { WM_KEYDOWN | WM_SYSKEYDOWN => true,
            WM_KEYUP | WM_SYSKEYUP => false, _ => return Err(WindowError::InvalidParent) };
        let raw = u8::try_from(message.wparam).ok().filter(|key| *key != 0).ok_or(WindowError::InvalidParent)?;
        if message.hwnd != Some(id) { return Err(WindowError::InvalidParent); }
        self.check_message_capacity(id, 1)?;
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue).ok_or(WindowError::NoSuchWindow)?;
        let transition = KeyTransition { key: sided(raw, message.lparam), pressed };
        message.wparam = generic(raw) as u64;
        queue.messages.push_back(QueuedMessage { message, key: Some(transition) });
        self.keyboard.apply(transition, true);
        Ok(())
    }
    /// Synchronous state follows this thread's consumed hardware input. # C: O(queues)
    pub fn key_state(&self, tid: u64, key: i32) -> i16 {
        let Some((_, queue)) = self.queues.iter().find(|(owner, _)| *owner == tid) else { return 0; };
        (queue.keyboard.bytes[(key as u32 & 0xff) as usize] & (DOWN | TOGGLE)) as i8 as i16
    }
    /// The low result bit consumes accepted-input press history, not the toggle bit. # C: O(1)
    pub fn async_key_state(&mut self, key: i32) -> i16 {
        let Ok(index) = usize::try_from(key) else { return 0; };
        let Some(state) = self.keyboard.bytes.get_mut(index) else { return 0; };
        let result = ((*state & DOWN) as u16) << 8 | u16::from(*state & RECENT != 0);
        *state &= !RECENT; result as i16
    }
    /// # C: O(queues + 256)
    pub fn keyboard_state(&self, tid: u64) -> [u8; KEY_COUNT] {
        self.queues.iter().find(|(owner, _)| *owner == tid).map_or([0; KEY_COUNT], |(_, queue)| queue.keyboard.snapshot())
    }
    /// Thread-local override never changes accepted physical input state. # C: O(queues + 256)
    pub fn set_keyboard_state(&mut self, tid: u64, state: &[u8; KEY_COUNT]) {
        if self.queues.iter().all(|(owner, _)| *owner != tid) { self.queues.push((tid, MessageQueue::default())); }
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.keyboard.bytes = *state; }
    }
}

#[cfg(test)]
#[path = "tests/keyboard.rs"]
mod tests;
