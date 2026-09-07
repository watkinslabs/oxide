//! Pointer input records: the per-thread table of pointers a thread has seen,
//! built from the pointer messages it retrieves, and the queries that read it.
//!
//! A pointer message names its pointer in the low half of its wparam and its
//! flags in the high half; retrieving one creates the pointer record on first
//! sight and refreshes it afterwards, recording which buttons changed between
//! the previous record and this one. The three queries — the pointer's type,
//! its information list and the device rectangles — read only what those
//! retrievals recorded.

use super::{MessageQueue, WindowManager};

/// Pointer input types, in the order the client enumeration declares them.
pub const PT_POINTER: u32 = 1;
pub const PT_TOUCH: u32 = 2;
pub const PT_PEN: u32 = 3;
pub const PT_MOUSE: u32 = 4;
pub const PT_TOUCHPAD: u32 = 5;

/// The mouse always answers this pointer identity, whether or not any pointer
/// message has been retrieved.
pub const MOUSE_POINTER_ID: u32 = 1;

pub const POINTER_FLAG_NONE: u32 = 0x0000_0000;
pub const POINTER_FLAG_NEW: u32 = 0x0000_0001;
pub const POINTER_FLAG_INRANGE: u32 = 0x0000_0002;
pub const POINTER_FLAG_INCONTACT: u32 = 0x0000_0004;
pub const POINTER_FLAG_FIRSTBUTTON: u32 = 0x0000_0010;
pub const POINTER_FLAG_SECONDBUTTON: u32 = 0x0000_0020;
pub const POINTER_FLAG_THIRDBUTTON: u32 = 0x0000_0040;
pub const POINTER_FLAG_FOURTHBUTTON: u32 = 0x0000_0080;
pub const POINTER_FLAG_FIFTHBUTTON: u32 = 0x0000_0100;
pub const POINTER_FLAG_DOWN: u32 = 0x0001_0000;
pub const POINTER_FLAG_UPDATE: u32 = 0x0002_0000;
pub const POINTER_FLAG_UP: u32 = 0x0004_0000;

pub const POINTER_CHANGE_NONE: u32 = 0;
pub const POINTER_CHANGE_FIRSTBUTTON_DOWN: u32 = 1;
pub const POINTER_CHANGE_FIRSTBUTTON_UP: u32 = 2;
pub const POINTER_CHANGE_SECONDBUTTON_DOWN: u32 = 3;
pub const POINTER_CHANGE_SECONDBUTTON_UP: u32 = 4;
pub const POINTER_CHANGE_THIRDBUTTON_DOWN: u32 = 5;
pub const POINTER_CHANGE_THIRDBUTTON_UP: u32 = 6;
pub const POINTER_CHANGE_FOURTHBUTTON_DOWN: u32 = 7;
pub const POINTER_CHANGE_FOURTHBUTTON_UP: u32 = 8;
pub const POINTER_CHANGE_FIFTHBUTTON_DOWN: u32 = 9;
pub const POINTER_CHANGE_FIFTHBUTTON_UP: u32 = 10;

/// Pointer messages, whose retrieval refreshes the table.
pub const WM_POINTERUPDATE: u32 = 0x0245;
pub const WM_POINTERDOWN: u32 = 0x0246;
pub const WM_POINTERUP: u32 = 0x0247;
pub const WM_POINTERLEAVE: u32 = 0x024a;

/// `POINTER_INFO` on the 64-bit client ABI.
pub const POINTER_INFO_BYTES: usize = 96;
/// `POINTER_PEN_INFO`: the pointer record then six 32-bit pen fields.
pub const POINTER_PEN_INFO_BYTES: usize = POINTER_INFO_BYTES + 24;
/// `POINTER_TOUCH_INFO`: the pointer record, two masks, two rectangles and two
/// 32-bit fields.
pub const POINTER_TOUCH_INFO_BYTES: usize = POINTER_INFO_BYTES + 48;

/// Hundredths of a millimetre per inch, the unit the himetric location uses.
pub const HIMETRIC_PER_INCH: i32 = 2540;

/// Whether one message is a pointer message. # C: O(1)
pub const fn is_pointer_message(message: u32) -> bool {
    message >= WM_POINTERUPDATE && message <= WM_POINTERLEAVE
}

/// Pointer identity a pointer message names. # C: O(1)
pub const fn pointer_id_of(wparam: u64) -> u32 { wparam as u16 as u32 }

/// Pointer flags a pointer message carries, plus the transition its own
/// message number implies. # C: O(1)
pub const fn pointer_flags_of(message: u32, wparam: u64) -> u32 {
    let flags = ((wparam >> 16) as u16) as u32;
    match message {
        WM_POINTERUPDATE => flags | POINTER_FLAG_UPDATE,
        WM_POINTERDOWN => flags | POINTER_FLAG_DOWN,
        WM_POINTERUP => flags | POINTER_FLAG_UP,
        _ => flags,
    }
}

/// Buttons that changed between two flag words, encoded as the single change
/// the record reports. # C: O(N_buttons)
pub const fn button_change(old: u32, new: u32) -> u32 {
    const MAP: [(u32, u32, u32); 5] = [
        (POINTER_FLAG_FIRSTBUTTON, POINTER_CHANGE_FIRSTBUTTON_DOWN, POINTER_CHANGE_FIRSTBUTTON_UP),
        (POINTER_FLAG_SECONDBUTTON, POINTER_CHANGE_SECONDBUTTON_DOWN, POINTER_CHANGE_SECONDBUTTON_UP),
        (POINTER_FLAG_THIRDBUTTON, POINTER_CHANGE_THIRDBUTTON_DOWN, POINTER_CHANGE_THIRDBUTTON_UP),
        (POINTER_FLAG_FOURTHBUTTON, POINTER_CHANGE_FOURTHBUTTON_DOWN, POINTER_CHANGE_FOURTHBUTTON_UP),
        (POINTER_FLAG_FIFTHBUTTON, POINTER_CHANGE_FIFTHBUTTON_DOWN, POINTER_CHANGE_FIFTHBUTTON_UP),
    ];
    let (down, up) = (!old & new, old & !new);
    let mut change = POINTER_CHANGE_NONE;
    let mut index = 0;
    while index < MAP.len() {
        let (flag, on, off) = MAP[index];
        if down & flag != 0 { change |= on; }
        if up & flag != 0 { change |= off; }
        index += 1;
    }
    change
}

/// Record size one pointer type reports its information in; a type outside the
/// enumeration names none. # C: O(1)
pub const fn info_record_bytes(kind: u32) -> Option<usize> {
    Some(match kind {
        PT_MOUSE | PT_PEN => POINTER_PEN_INFO_BYTES,
        PT_POINTER => POINTER_INFO_BYTES,
        PT_TOUCH | PT_TOUCHPAD => POINTER_TOUCH_INFO_BYTES,
        _ => return None,
    })
}

/// Admit one information-list request: the mouse type is refused outright, and
/// every other type demands exactly the record size it reports in. A type
/// outside the enumeration names no size and so matches none. # C: O(1)
pub const fn info_list_admitted(kind: u32, size: u64) -> bool {
    if kind == PT_MOUSE { return false; }
    match info_record_bytes(kind) { Some(bytes) => size == bytes as u64, None => false }
}

/// The information one pointer record carries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PointerInfo {
    pub kind: u32, pub id: u32, pub frame: u32, pub flags: u32,
    pub source_device: u64, pub target: u32,
    pub pixel: (i32, i32),
    pub time: u32, pub history: u32, pub input_data: i32, pub key_states: u32,
    pub performance_count: u64, pub button_change: u32,
}

/// The source device of a pointer with no device behind it.
pub const NO_SOURCE_DEVICE: u64 = u64::MAX;

/// Build one pointer record from the message that refreshed it. The pixel
/// location is the point the message's lparam names. # C: O(1)
pub fn info_from_message(message: u32, wparam: u64, lparam: i64, target: u32, time: u32,
    frame: u32, performance_count: u64) -> PointerInfo {
    let pixel = (((lparam as u32) as u16) as i16 as i32, (((lparam as u32) >> 16) as u16) as i16 as i32);
    PointerInfo { kind: PT_POINTER, id: pointer_id_of(wparam), frame, flags: pointer_flags_of(message, wparam),
        source_device: NO_SOURCE_DEVICE, target, pixel, time, history: 1, input_data: 0, key_states: 0,
        performance_count, button_change: POINTER_CHANGE_NONE }
}

/// One pixel coordinate in hundredths of a millimetre at the given dots per
/// inch, the unit the himetric location of a pointer record uses. A dots-per-
/// inch of zero or less names no scale and answers the origin. # C: O(1)
pub const fn himetric_of(pixel: i32, dpi: i32) -> i32 {
    if dpi <= 0 { return 0; }
    pixel * HIMETRIC_PER_INCH / dpi
}

/// One pointer a thread has seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pointer { pub id: u32, pub kind: u32, pub info: PointerInfo }

impl MessageQueue {
    /// Refresh, or create, the record of the pointer a retrieved message names.
    /// The stored type wins over the type the record was built with, and the
    /// button change is measured against what the previous record held.
    /// # C: O(N_pointers)
    pub(super) fn update_pointer(&mut self, kind: u32, mut info: PointerInfo) {
        let change = self.pointers.iter().find(|pointer| pointer.id == info.id)
            .map_or(button_change(POINTER_FLAG_NONE, info.flags), |pointer| button_change(pointer.info.flags, info.flags));
        info.button_change = change;
        match self.pointers.iter_mut().find(|pointer| pointer.id == info.id) {
            Some(pointer) => { info.kind = pointer.kind; pointer.info = info; }
            None => { info.kind = kind; self.pointers.push(Pointer { id: info.id, kind, info }); }
        }
    }
    /// # C: O(N_pointers)
    pub(super) fn find_pointer(&self, id: u32) -> Option<&Pointer> { self.pointers.iter().find(|pointer| pointer.id == id) }
}

impl WindowManager {
    /// Type of one pointer this thread has seen. The mouse identity always
    /// answers the mouse type, whether or not a pointer message named it; a
    /// zero identity and an unknown one name no pointer. # C: O(N_queues + N_pointers)
    pub fn pointer_type(&self, tid: u64, id: u32) -> Option<u32> {
        if id == MOUSE_POINTER_ID { return Some(PT_MOUSE); }
        if id == 0 { return None; }
        self.queues.iter().find(|(owner, _)| *owner == tid)
            .and_then(|(_, queue)| queue.find_pointer(id)).map(|pointer| pointer.kind)
    }

    /// The record of one pointer this thread has seen. # C: O(N_queues + N_pointers)
    pub fn pointer_info(&self, tid: u64, id: u32) -> Option<PointerInfo> {
        self.queues.iter().find(|(owner, _)| *owner == tid)
            .and_then(|(_, queue)| queue.find_pointer(id)).map(|pointer| pointer.info)
    }

    /// Refresh this thread's table from one retrieved pointer message.
    /// # C: O(N_queues + N_pointers)
    pub fn update_pointer_from_message(&mut self, tid: u64, kind: u32, info: PointerInfo) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.update_pointer(kind, info); }
    }

    /// Refresh this thread's pointer table from one message it just retrieved.
    /// Only a pointer message refreshes it; every other retrieval is ignored,
    /// as the reference's retrieval path only builds a record for a pointer
    /// message. # C: O(N_queues + N_pointers)
    pub(super) fn note_retrieved_message(&mut self, tid: u64, message: super::WinMessage, performance_count: u64) {
        if !is_pointer_message(message.message) { return; }
        self.pointer_frame = self.pointer_frame.wrapping_add(1);
        let info = info_from_message(message.message, message.wparam, message.lparam,
            message.hwnd.map_or(0, |hwnd| hwnd.raw()), self.message_time(tid), self.pointer_frame, performance_count);
        self.update_pointer_from_message(tid, PT_POINTER, info);
    }
}

#[cfg(test)]
#[path = "tests/pointer.rs"]
mod tests;
