//! End-to-end native window, message, GDI, and scanout smoke.

use std::process::ExitCode;
use syscall::nt::NtWindowRect;
use windows_gdi::{Gdi, Rect};
use windows_user32::{ClassRegistry, User32, WM_KEYDOWN};

const SW_SHOW: u32 = 1;
const WM_PAINT: u32 = 0x000f;
const WM_QUIT: u32 = 0x0012;
const WM_CHAR: u32 = 0x0102;
const VK_A: u16 = 0x41;

fn run() -> Result<(), String> {
    let user32 = User32::new();
    let mut classes = ClassRegistry::new();
    let class = "OxideUiSmoke\0".encode_utf16().collect::<Vec<_>>();
    classes.register_class_ex_w(&class, 0).map_err(|error| format!("register class: {error:?}"))?;
    let hwnd = classes.create_window_ex_w(&user32, &class, 0).map_err(|error| format!("create window: {error:?}"))?;
    let title = "Untitled - Notepad\0".encode_utf16().collect::<Vec<_>>();
    user32.set_window_text(hwnd, &title).map_err(|error| format!("set title: {error:?}"))?;
    let mut title_readback = vec![0u16; 64];
    let title_len = user32.get_window_text(hwnd, &mut title_readback).map_err(|error| format!("get title: {error:?}"))?;
    if title_readback[..title_len] != title[..title.len() - 1] { return Err("window title round-trip mismatch".into()); }
    let rect = NtWindowRect { left: 80, top: 60, right: 720, bottom: 540 };
    user32.set_window_rect(hwnd, &rect).map_err(|error| format!("set rectangle: {error:?}"))?;
    let client = user32.get_client_rect(hwnd).map_err(|error| format!("get client rectangle: {error:?}"))?;
    if client != (NtWindowRect { left: 0, top: 0, right: 640, bottom: 480 }) { return Err("client rectangle mismatch".into()); }
    user32.show_window(hwnd, SW_SHOW).map_err(|error| format!("show window: {error:?}"))?;

    let child = classes.create_window_ex_w(&user32, &class, hwnd).map_err(|error| format!("create edit child: {error:?}"))?;
    let child_title = "edit control\0".encode_utf16().collect::<Vec<_>>();
    user32.set_window_text(child, &child_title).map_err(|error| format!("set child text: {error:?}"))?;
    if user32.get_parent(child).map_err(|error| format!("get child parent: {error:?}"))? != hwnd { return Err("child parent mismatch".into()); }

    let gdi = Gdi::new();
    let dc = gdi.create_compatible_dc(640, 480).map_err(|error| format!("create DC: {error:?}"))?;
    gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 640, bottom: 480 }, 0x001f_6feb)
        .map_err(|error| format!("paint background: {error:?}"))?;
    gdi.fill_rect(dc, Rect { left: 24, top: 24, right: 616, bottom: 456 }, 0x00f5_f5f5)
        .map_err(|error| format!("paint panel: {error:?}"))?;
    gdi.present_window(hwnd, dc).map_err(|error| format!("present window: {error:?}"))?;

    user32.invalidate_rect(hwnd, Some(&NtWindowRect { left: 10, top: 10, right: 100, bottom: 100 })).map_err(|error| format!("invalidate first region: {error:?}"))?;
    user32.invalidate_rect(hwnd, Some(&NtWindowRect { left: 80, top: 80, right: 200, bottom: 160 })).map_err(|error| format!("invalidate second region: {error:?}"))?;
    let mut message = user32.get_message(hwnd, 0, u32::MAX).map_err(|error| format!("get paint: {error:?}"))?;
    if message.message != WM_PAINT { return Err(format!("unexpected paint message: {}", message.message)); }
    let dirty = user32.begin_paint(hwnd).map_err(|error| format!("begin paint: {error:?}"))?;
    if dirty != (NtWindowRect { left: 10, top: 10, right: 200, bottom: 160 }) { return Err("paint region was not coalesced".into()); }
    user32.end_paint(hwnd).map_err(|error| format!("end paint: {error:?}"))?;
    if user32.peek_message(hwnd, WM_PAINT, WM_PAINT, false).map_err(|error| format!("peek coalesced paint: {error:?}"))?.is_some() { return Err("paint notification was duplicated".into()); }

    user32.set_focus(child).map_err(|error| format!("set child focus: {error:?}"))?;
    user32.inject_key(VK_A, true, false).map_err(|error| format!("inject key: {error:?}"))?;
    message = user32.get_message(child, WM_KEYDOWN, WM_KEYDOWN).map_err(|error| format!("get key: {error:?}"))?;
    if message.wparam != VK_A as u64 { return Err("key message mismatch".into()); }
    if !user32.translate_message(&message, false, false).map_err(|error| format!("translate key: {error:?}"))? { return Err("key was not translatable".into()); }
    message = user32.get_message(child, WM_CHAR, WM_CHAR).map_err(|error| format!("get char: {error:?}"))?;
    if message.wparam != b'a' as u64 { return Err("character message mismatch".into()); }
    user32.post_quit_message(0).map_err(|error| format!("post quit: {error:?}"))?;
    message = user32.get_message(0, 0, u32::MAX).map_err(|error| format!("get quit: {error:?}"))?;
    if message.message != WM_QUIT { return Err(format!("unexpected quit message: {}", message.message)); }

    gdi.delete_object(dc).map_err(|error| format!("delete DC: {error:?}"))?;
    user32.destroy_window(hwnd).map_err(|error| format!("destroy window: {error:?}"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => { println!("windows-ui-smoke: PASS"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("windows-ui-smoke: FAIL: {error}"); ExitCode::from(1) }
    }
}
