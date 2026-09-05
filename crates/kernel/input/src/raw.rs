use alloc::vec::Vec;

use crate::registry::VirtioInputDev;
use crate::{BTN_LEFT, EV_KEY, EV_REL};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RawInputKind { Keyboard, Mouse }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RawInputEvent { pub device_id: u32, pub kind: RawInputKind, pub code: u16, pub value: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RawInputPublish { Queued, Dropped }

pub(crate) const RAW_INPUT_QUEUE_LIMIT: usize = 256;

impl VirtioInputDev {
    pub(crate) fn publish_raw(&mut self, ev_type: u16, code: u16, value: i32) -> Option<RawInputPublish> {
        let kind = match ev_type {
            EV_KEY if code < BTN_LEFT => RawInputKind::Keyboard,
            EV_KEY | EV_REL => RawInputKind::Mouse,
            _ => return None,
        };
        if self.raw_events.len() >= RAW_INPUT_QUEUE_LIMIT {
            self.raw_dropped = self.raw_dropped.saturating_add(1);
            return Some(RawInputPublish::Dropped);
        }
        self.raw_events.push_back(RawInputEvent { device_id: self.evdev_id, kind, code, value });
        Some(RawInputPublish::Queued)
    }

    pub(crate) fn take_raw(&mut self, limit: usize) -> Vec<RawInputEvent> {
        let count = limit.min(self.raw_events.len());
        self.raw_events.drain(..count).collect()
    }
}
