use syscall::nt_native_gdi as abi;
use windows_gdi::{RasterSurface, Rect};
use super::render::{draw, Sink};

#[path = "../../../../../crates/kernel/syscalls/src/nt_wine_window/gdi_raw.rs"]
mod raw_gdi;

struct Surface { owner: ipc::win32_gdi::GdiManager, uploads: usize, fills: usize }
impl Sink for Surface {
    fn fill(&mut self, dc: u64, rect: Rect, color: u32) -> Result<(), ()> {
        self.fills += 1;
        self.owner.fill_rect(dc as u32, ipc::win32_gdi::Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }, color).map_err(|_| ())
    }
    fn upload(&mut self, dc: u64, x: i32, y: i32, raster: &RasterSurface, _: Option<Rect>, alpha: bool) -> Result<(), ()> {
        self.uploads += 1;
        assert!(alpha);
        self.owner.blend_pixels(dc as u32, x, y, raster.width, raster.height, &raster.pixels).map_err(|_| ())
    }
}
fn request(dc: u32, count: usize) -> abi::TextRequest {
    abi::TextRequest { version: abi::VERSION, size: 112, dc: dc as u64, x: 10, y: 10,
        flags: abi::GLYPH_INDEX | abi::IGNORE_LANGUAGE | abi::PDY, count: count as u32,
        text: 1, advances: 1, rect: [0, 0, 200, 100], height: 16, width: 7, weight: 700, italic: 0,
        foreground: 0xffad21, background: 0x102030, has_rect: 0, reserved: 0,
        background_mode: abi::TRANSPARENT, alignment: 0, current_x: 0, current_y: 0 }
}

#[test]
fn paired_glyph_pipeline_reaches_canonical_pixels_and_preserves_native_thread() {
    super::native::prepare_fonts().unwrap();
    std::thread::spawn(|| {
        std::thread_local! { static TLS: std::cell::Cell<u32> = const { std::cell::Cell::new(7) }; }
        // SAFETY: gettid has no pointer arguments and observes this real native pthread.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let font = super::native::selected_font_with_width(16, 7, 700, 0).unwrap();
        let text: Vec<u16> = "Notepad".encode_utf16().collect();
        let glyphs = font.glyph_indices(&text, 0, false);
        let pairs: Vec<i32> = text.iter().flat_map(|_| [10, 3]).collect();
        let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0, fills: 0 };
        let dc = sink.owner.create_dc(200, 100).unwrap();
        let req = request(dc, text.len());
        assert!(req.valid()); assert_eq!(req.advance_count(), text.len() * 2);
        draw(&font, &req, &glyphs, Some(&pairs), &mut sink).unwrap();
        let pixels = sink.owner.surface(dc).unwrap().2.to_vec();
        assert!(pixels.iter().filter(|p| **p != 0).count() > 50);
        assert!(pixels[30 * 200..].iter().any(|p| *p != 0), "positive paired Y displacements must reach later rows");
        let flat: Vec<i32> = text.iter().flat_map(|_| [10, 0]).collect();
        let (_, _, glyph_tile) = font.rasterize_positioned(&glyphs, Some(&flat), req.flags, 0xffad21, None).unwrap();
        let (_, _, text_tile) = font.rasterize_positioned(&text, Some(&flat), req.flags & !abi::GLYPH_INDEX, 0xffad21, None).unwrap();
        assert_eq!(glyph_tile.pixels, text_tile.pixels);
        let (_, _, paired_tile) = font.rasterize_positioned(&glyphs, Some(&pairs), req.flags, 0xffad21, None).unwrap();
        assert!(paired_tile.height > glyph_tile.height);
        assert_eq!((sink.uploads, sink.fills), (1, 0));
        TLS.with(|slot| assert_eq!(slot.get(), 7));
        // SAFETY: gettid confirms query/render never switched to another task or pthread.
        assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, tid);
    }).join().unwrap();
}

#[test]
fn glyph_and_pdy_admission_precede_opaque_fill_and_callback_stack_copy() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font_with_width(16, 7, 700, 0).unwrap();
    let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0, fills: 0 };
    let dc = sink.owner.create_dc(200, 100).unwrap();
    let req = abi::TextRequest { flags: request(dc, 2).flags | abi::OPAQUE, has_rect: 1, ..request(dc, 2) };
    let glyph = font.glyph_indices(&[65], 0, false)[0];
    assert!(draw(&font, &req, &[glyph, glyph], Some(&[10, 0]), &mut sink).is_err());
    assert!(draw(&font, &req, &[65535, glyph], Some(&[10, 0, 10, 0]), &mut sink).is_err());
    assert!(draw(&font, &req, &[glyph, glyph], Some(&[i32::MAX, i32::MAX, 1, 0]), &mut sink).is_err());
    assert_eq!((sink.fills, sink.uploads), (0, 0));
    assert!(sink.owner.surface(dc).unwrap().2.iter().all(|p| *p == 0));
    let req = abi::TextRequest { count: abi::MAX_UNITS, ..req };
    assert_eq!(req.payload_bytes(), Some(112 + abi::MAX_UNITS as usize * 10));
    for arch in [abi::CallbackArch::X86_64, abi::CallbackArch::Aarch64] {
        let layout = req.callback_layout(0x100000, arch).unwrap();
        assert_eq!(layout.advances + req.advance_count() as u64 * 4, layout.payload + layout.bytes as u64);
    }
    assert!(!abi::TextRequest { advances: u64::MAX - 8, ..req }.valid());
}

#[test]
fn raw_gdi_to_query_payload_to_renderer_preserves_glyph_index_and_pdy() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font_with_width(16, 7, 700, 0).unwrap();
    let bytes = super::native::selected_bytes(700, 0).unwrap();
    let text: Vec<u16> = "Notepad".encode_utf16().collect();
    let query = abi::QueryRequest { version: abi::VERSION, size: std::mem::size_of::<abi::QueryRequest>() as u32,
        dc: 1, kind: abi::QUERY_GLYPHS, flags: 1, height: 16, width: 7, weight: 700, italic: 0,
        first: 0, count: text.len() as u32, input: 1, output: 2, table: 0, offset: 0, capacity: 0, reserved: 0 };
    let glyph_bytes = super::query::execute(&font, bytes, &query, &text).unwrap().1;
    let glyphs: Vec<u16> = glyph_bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    assert_eq!(glyphs.len(), text.len());

    let flags = abi::GLYPH_INDEX | abi::IGNORE_LANGUAGE | abi::PDY;
    let args = [0x10001, 10, 10, flags as u64, 0, 0x5000, text.len() as u64, 0x6000, 0];
    let raw_gdi::Operation::ExtTextOutW { dc: raw_dc, x, y, flags, rect, text: text_ptr, count, dx, code_page } = raw_gdi::decode(raw_gdi::EXT_TEXT_OUT_W, &args).unwrap() else { panic!("raw decoder selected wrong operation"); };
    assert_eq!(raw_dc, 0x10001);
    let admitted = raw_gdi::text_output::validate(flags, rect, text_ptr, count, dx, code_page).unwrap();
    let request = abi::TextRequest { version: abi::VERSION, size: std::mem::size_of::<abi::TextRequest>() as u32,
        dc: 1, x, y, flags: admitted.flags, count: admitted.count, text: admitted.text,
        advances: admitted.advances.unwrap(), rect: [0, 0, 0, 0], height: 16, width: 7, weight: 700, italic: 0,
        foreground: 0xffad21, background: 0x102030, has_rect: u32::from(admitted.rect.is_some()), reserved: 0,
        background_mode: abi::TRANSPARENT, alignment: 0, current_x: 0, current_y: 0 };
    assert!(request.valid());
    assert_eq!(request.flags, flags);
    assert_eq!(request.advance_count(), text.len() * 2);

    let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0, fills: 0 };
    let dc_handle = sink.owner.create_dc(200, 100).unwrap();
    let request = abi::TextRequest { dc: dc_handle as u64, ..request };
    draw(&font, &request, &glyphs, Some(&[10, 3, 10, 3, 10, 3, 10, 3, 10, 3, 10, 3, 10, 3]), &mut sink).unwrap();
    assert_eq!((sink.uploads, sink.fills), (1, 0));
    assert!(sink.owner.surface(dc_handle).unwrap().2.iter().any(|pixel| *pixel != 0));
}

#[test]
fn raw_gdi_negative_hook_rejects_unknown_flag_before_native_render() {
    let args = [1, 0, 0, (abi::GLYPH_INDEX | 0x8000) as u64, 0, 0x2000, 1, 0, 0];
    let raw_gdi::Operation::ExtTextOutW { flags, rect, text, count, dx, code_page, .. } = raw_gdi::decode(raw_gdi::EXT_TEXT_OUT_W, &args).unwrap() else { panic!("raw decoder selected wrong operation"); };
    assert!(raw_gdi::text_output::validate(flags, rect, text, count, dx, code_page).is_err());
}

#[test]
fn raw_gdi_null_rect_normalizes_rectangle_flags_for_native_payload() {
    let args = [1, 0, 0, (abi::OPAQUE | abi::CLIPPED | abi::GLYPH_INDEX) as u64, 0, 0x2000, 1, 0, 0];
    let raw_gdi::Operation::ExtTextOutW { flags, rect, text, count, dx, code_page, .. } = raw_gdi::decode(raw_gdi::EXT_TEXT_OUT_W, &args).unwrap() else { panic!("raw decoder selected wrong operation"); };
    let admitted = raw_gdi::text_output::validate(flags, rect, text, count, dx, code_page).unwrap();
    let request = abi::TextRequest { version: abi::VERSION, size: std::mem::size_of::<abi::TextRequest>() as u32,
        dc: 1, x: 0, y: 0, flags: admitted.flags, count: admitted.count, text: admitted.text, advances: 0,
        rect: [0, 0, 0, 0], height: 16, width: 7, weight: 700, italic: 0, foreground: 0, background: 0xffffff,
        has_rect: 0, reserved: 0, background_mode: abi::BACKGROUND_OPAQUE, alignment: 0, current_x: 0, current_y: 0 };
    assert_eq!(admitted.flags, abi::GLYPH_INDEX);
    assert!(request.valid());
    assert!(!abi::TextRequest { alignment: 1, ..request }.valid());
}
