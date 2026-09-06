//! Snapshot nonclient geometry and canonical profile without nested GUI/GDI locks.
use super::*;
use ipc::win32_gdi::{ScrollColors, ScrollMetrics, ScrollPart, SystemColor};
use crate::nt_gdi::nonclient_scroll::{NonclientScrollContext, nonclient_scroll_context};

/// No usercopy or display call while GUI owns the window snapshot. # C: O(processes + windows)
pub(crate) fn nonclient_scroll_context_for_current(hwnd: u64) -> Option<NonclientScrollContext> {
    let current = sched::live::current().filter(|current| current.is_nt_personality())?;
    let window = valid_window(hwnd)?;
    let (bounds, client, style, ex_style) = {
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
        let record = entry.state.get(window)?;
        let bounds = entry.state.rect(window)?;
        (bounds, record.client_rect.unwrap_or(bounds), record.style, record.ex_style)
    };
    let metrics = ScrollMetrics { arrow_size: ipc::win32_gdi::system_metric_default(20)?, dpi: 96 };
    let colors = ScrollColors { face: SystemColor::Face.color(), highlight: SystemColor::ButtonHighlight.color(),
        light: SystemColor::Light.color(), shadow: SystemColor::ButtonShadow.color(), dark_shadow: SystemColor::DarkShadow.color(),
        text: SystemColor::ButtonText.color(), window: SystemColor::Window.color(), track: SystemColor::Scrollbar.color() };
    nonclient_scroll_context(bounds, client, style, ex_style, metrics, colors, ScrollPart::None)
}
