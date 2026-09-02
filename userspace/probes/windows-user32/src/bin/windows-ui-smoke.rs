//! End-to-end native window, message, GDI, and scanout smoke.

use std::process::ExitCode;
use syscall::nt::NtWindowRect;
use windows_gdi::{Gdi, Rect};
use windows_user32::{ClassRegistry, User32};

const SW_SHOW: u32 = 1;
const WM_PAINT: u32 = 0x000f;
const WM_QUIT: u32 = 0x0012;

fn run() -> Result<(), String> {
    let user32 = User32::new();
    let mut classes = ClassRegistry::new();
    let class = "OxideUiSmoke\0".encode_utf16().collect::<Vec<_>>();
    classes.register_class_ex_w(&class, 0).map_err(|error| format!("register class: {error:?}"))?;
    let hwnd = classes.create_window_ex_w(&user32, &class, 0).map_err(|error| format!("create window: {error:?}"))?;
    let title = "Oxide native UI smoke\0".encode_utf16().collect::<Vec<_>>();
    user32.set_window_text(hwnd, &title).map_err(|error| format!("set title: {error:?}"))?;
    let rect = NtWindowRect { left: 80, top: 60, right: 720, bottom: 540 };
    user32.set_window_rect(hwnd, &rect).map_err(|error| format!("set rectangle: {error:?}"))?;
    user32.show_window(hwnd, SW_SHOW).map_err(|error| format!("show window: {error:?}"))?;

    let gdi = Gdi::new();
    let dc = gdi.create_compatible_dc(640, 480).map_err(|error| format!("create DC: {error:?}"))?;
    gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 640, bottom: 480 }, 0x001f_6feb)
        .map_err(|error| format!("paint background: {error:?}"))?;
    gdi.fill_rect(dc, Rect { left: 24, top: 24, right: 616, bottom: 456 }, 0x00f5_f5f5)
        .map_err(|error| format!("paint panel: {error:?}"))?;
    gdi.present_window(hwnd, dc).map_err(|error| format!("present window: {error:?}"))?;

    user32.post_message(hwnd, WM_PAINT, 0, 0).map_err(|error| format!("post paint: {error:?}"))?;
    let mut message = user32.get_message(hwnd, 0, u32::MAX).map_err(|error| format!("get paint: {error:?}"))?;
    if message.message != WM_PAINT { return Err(format!("unexpected paint message: {}", message.message)); }
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
