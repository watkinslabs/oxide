use super::render::{self, Sink};
use syscall::nt_native_gdi as abi;
use windows_gdi::{RasterFont, RasterSurface, Rect};

fn request() -> abi::TextRequest {
    abi::TextRequest { version: abi::VERSION, size: 112, dc: 1, x: 4, y: 3, flags: 0, count: 0,
        text: 1, advances: 0, rect: [0, 0, 200, 60], height: 16,
        width: 0, weight: 400, italic: 0, foreground: 0, background: 0xffffff, has_rect: 1, reserved: 0,
        background_mode: abi::BACKGROUND_OPAQUE, alignment: 0, current_x: 0, current_y: 0 }
}

#[test]
fn callback_abi_bounds_precede_any_pointer_dereference() {
    assert_eq!(std::mem::size_of::<abi::TextRequest>(), 112);
    assert_eq!(std::mem::offset_of!(abi::TextRequest, text), 32);
    assert_eq!(std::mem::offset_of!(abi::TextRequest, advances), 40);
    assert_eq!(std::mem::offset_of!(abi::TextRequest, rect), 48);
    assert_eq!(std::mem::offset_of!(abi::TextRequest, height), 64);
    assert_eq!(std::mem::offset_of!(abi::TextRequest, background_mode), 96);
    let valid = request(); assert!(valid.valid());
    for bad in [abi::TextRequest { version: 0, ..valid }, abi::TextRequest { count: abi::MAX_UNITS + 1, ..valid },
        abi::TextRequest { width: i32::MIN, ..valid }, abi::TextRequest { background_mode: 0, ..valid },
        abi::TextRequest { alignment: 24, ..valid }, abi::TextRequest { reserved: 1, ..valid },
        abi::TextRequest { height: i32::MIN, ..valid }, abi::TextRequest { flags: 0x80000000, ..valid },
        abi::TextRequest { flags: abi::CLIPPED, has_rect: 0, ..valid },
        abi::TextRequest { count: 1, text: u64::MAX, ..valid }] { assert!(!bad.valid()); assert!(bad.payload_bytes().is_none()); }
    assert_eq!(abi::TextRequest { count: 3, advances: 8, ..valid }.payload_bytes(), Some(132));
}

#[test]
fn real_callback_entry_uses_native_tls_and_returns_bool_without_registering_host_hooks() {
    super::native::prepare_fonts().unwrap();
    std::thread::spawn(|| {
        std::thread_local! { static TLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
        TLS.with(|slot| slot.set(0x12345678));
        // SAFETY: gettid has no pointer arguments and identifies this actual pthread.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let (entry, _) = super::platform::entries();
        #[cfg(target_arch = "x86_64")]
        type Entry = unsafe extern "win64" fn(*const abi::TextRequest) -> u64;
        #[cfg(target_arch = "aarch64")]
        type Entry = unsafe extern "C" fn(*const abi::TextRequest) -> u64;
        // SAFETY: production registration exposes precisely this architecture's callback entry ABI.
        let callback: Entry = unsafe { std::mem::transmute(entry as usize) };
        let text: [u16; 0] = [];
        for (weight, italic) in [(400, 0), (700, 0), (400, 1), (700, 1)] {
            let request = abi::TextRequest { text: text.as_ptr() as u64, weight, italic, ..request() };
            // SAFETY: valid initialized header and aligned zero-length text remain live through callback.
            assert_eq!(unsafe { callback(&request) }, 1);
            let bad = abi::TextRequest { version: 0, ..request };
            // SAFETY: invalid version is read from a valid header before any payload dereference.
            assert_eq!(unsafe { callback(&bad) }, 0);
        }
        TLS.with(|slot| assert_eq!(slot.get(), 0x12345678));
        // SAFETY: gettid verifies the native callback never changed pthread identity.
        assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, tid);
    }).join().unwrap();
}

#[test]
fn callback_layout_preserves_shadow_space_alignment_and_copied_array_bounds() {
    for count in [0, 1, 3, abi::MAX_UNITS] {
        let request = abi::TextRequest { count, advances: 4, ..request() };
        for original_sp in [0x100008, 0x100000] {
            let x86 = request.callback_layout(original_sp, abi::CallbackArch::X86_64).unwrap();
            let arm = request.callback_layout(original_sp, abi::CallbackArch::Aarch64).unwrap();
            assert_eq!(x86.stack % 16, 8);
            assert_eq!(arm.stack % 16, 0);
            assert!(x86.stack + 40 <= x86.payload);
            assert!(arm.stack + 16 <= arm.payload);
            for layout in [x86, arm] {
                assert_eq!(layout.payload % 16, 0);
                assert_eq!(layout.text, layout.payload + 112);
                assert_eq!(layout.advances % 4, 0);
                assert!(layout.advances >= layout.text + count as u64 * 2);
                assert_eq!(layout.advances + count as u64 * 4, layout.payload + layout.bytes as u64);
                assert!(layout.payload + layout.bytes as u64 <= original_sp);
            }
        }
        assert!(request.callback_layout(128, abi::CallbackArch::X86_64).is_none());
    }
    let layout = request().callback_layout(0x100000, abi::CallbackArch::Aarch64).unwrap();
    assert_eq!(layout.advances, 0);
}

#[test]
fn alpha_upload_clips_rows_without_changing_coverage_or_origin() {
    let surface = RasterSurface { width: 3, height: 2, pixels: vec![0, 0x40123456, 0xff123456, 0, 0x80123456, 0] };
    let (x, y, tile) = render::alpha_tile(-1, 5, &surface, Some(Rect { left: 0, top: 5, right: 1, bottom: 7 })).unwrap().unwrap();
    assert_eq!((x, y, tile.width, tile.height), (0, 5, 1, 2));
    assert_eq!(tile.pixels, [0x40123456, 0x80123456]);
    assert!(render::alpha_tile(i32::MAX, 0, &surface, None).is_err());
    assert!(render::alpha_tile(0, 0, &RasterSurface { width: 3, height: 2, pixels: vec![0] }, None).is_err());
    assert!(render::alpha_tile(0, 0, &surface, Some(Rect { left: 20, top: 20, right: 30, bottom: 30 })).unwrap().is_none());
}

struct Surface { owner: ipc::win32_gdi::GdiManager, uploads: usize }
impl Sink for Surface {
    fn fill(&mut self, dc: u64, rect: Rect, color: u32) -> Result<(), ()> {
        self.owner.fill_rect(dc as u32, ipc::win32_gdi::Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }, color).map_err(|_| ())
    }
    fn upload(&mut self, dc: u64, x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>, alpha: bool) -> Result<(), ()> {
        self.uploads += 1;
        if alpha {
            let Some((x, y, tile)) = render::alpha_tile(x, y, raster, clip)? else { return Ok(()); };
            return self.owner.blend_pixels(dc as u32, x, y, tile.width, tile.height, &tile.pixels).map_err(|_| ());
        }
        assert!(clip.is_none());
        self.owner.blit_pixels(dc as u32, x, y, raster.width as i32, raster.height as i32,
            raster.width as i32, &raster.pixels).map_err(|_| ())
    }
}

#[test]
fn transparent_clipped_text_blends_into_canonical_dc_without_erasing_destination() {
    let bytes = std::fs::read("/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf").unwrap();
    let font = RasterFont::from_bytes(&bytes, 16.0).unwrap();
    let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0 };
    let dc = sink.owner.create_dc(200, 60).unwrap();
    let background = 0x0010_2030;
    sink.fill(dc as u64, Rect { left: 0, top: 0, right: 200, bottom: 60 }, background).unwrap();
    let text: Vec<u16> = "Typed token".encode_utf16().collect();
    let request = abi::TextRequest { dc: dc as u64, count: text.len() as u32,
        foreground: 0x00e0_a040, background_mode: abi::TRANSPARENT, flags: abi::CLIPPED,
        rect: [5, 4, 30, 15], ..request() };
    let glyphs = font.rasterize_alpha(&text, None, request.foreground).unwrap();
    render::draw(&font, &request, &text, None, &mut sink).unwrap();
    let (_, _, pixels) = sink.owner.surface(dc).unwrap();
    let mut changed = 0;
    let mut antialiased = 0;
    for y in 0..60i32 { for x in 0..200i32 {
        let gx = x - request.x; let gy = y - request.y;
        let alpha = if x >= 5 && x < 30 && y >= 4 && y < 15 && gx >= 0 && gy >= 0
            && gx < glyphs.width as i32 && gy < glyphs.height as i32 {
            glyphs.pixels[gy as usize * glyphs.width as usize + gx as usize] >> 24
        } else { 0 };
        let channel = |shift: u32| -> u32 { (((request.foreground >> shift) & 255) * alpha
            + ((background >> shift) & 255) * (255 - alpha) + 127) / 255 };
        let expected = channel(16) << 16 | channel(8) << 8 | channel(0);
        assert_eq!(pixels[y as usize * 200 + x as usize], expected);
        changed += usize::from(expected != background);
        antialiased += usize::from(alpha > 0 && alpha < 255);
    } }
    assert!(changed > 10); assert!(antialiased > 0);
    assert_eq!(sink.uploads, 1);
}

#[test]
fn transparent_glyphs_keep_coverage_and_do_not_request_background_fill() {
    struct Alpha { uploads: usize }
    impl Sink for Alpha {
        fn fill(&mut self, _: u64, _: Rect, _: u32) -> Result<(), ()> { panic!("transparent output cannot erase background"); }
        fn upload(&mut self, _: u64, _: i32, _: i32, raster: &RasterSurface, _: Option<Rect>, alpha: bool) -> Result<(), ()> {
            assert!(alpha);
            assert!(raster.pixels.iter().any(|p| *p >> 24 == 0));
            assert!(raster.pixels.iter().any(|p| *p >> 24 > 0));
            assert!(raster.pixels.iter().any(|p| (1..255).contains(&(*p >> 24))));
            assert!(raster.pixels.iter().filter(|p| **p >> 24 != 0).all(|p| *p & 0x00ff_ffff == 0x006b_c134),
                "coverage upload carries non-premultiplied foreground RGB");
            self.uploads += 1; Ok(())
        }
    }
    let bytes = std::fs::read("/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf").unwrap();
    let font = RasterFont::from_bytes(&bytes, 16.0).unwrap();
    let text: Vec<u16> = "Typed".encode_utf16().collect();
    let mut sink = Alpha { uploads: 0 };
    let request = abi::TextRequest { count: text.len() as u32, background_mode: abi::TRANSPARENT,
        foreground: 0x006b_c134, ..request() };
    render::draw(&font, &request, &text, None, &mut sink).unwrap();
    assert_eq!(sink.uploads, 1);
    assert!(render::draw(&font, &abi::TextRequest { flags: 0x80000000, ..request }, &text, None, &mut sink).is_err());
    assert_eq!(sink.uploads, 1);
}

#[test]
fn empty_opaque_text_fills_but_bad_advances_never_mutate_the_dc() {
    let bytes = std::fs::read("/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf").unwrap();
    let font = RasterFont::from_bytes(&bytes, 16.0).unwrap();
    let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0 };
    let dc = sink.owner.create_dc(200, 60).unwrap();
    let request = abi::TextRequest { dc: dc as u64, flags: abi::OPAQUE, background: 0x00456789, ..request() };
    render::draw(&font, &request, &[], None, &mut sink).unwrap();
    assert_eq!(sink.uploads, 0);
    assert!(sink.owner.surface(dc).unwrap().2.iter().all(|p| *p == request.background));
    let invalid = abi::TextRequest { count: 2, advances: 4, background: 0, ..request };
    assert!(render::draw(&font, &invalid, &[65, 66], Some(&[8]), &mut sink).is_err());
    assert_eq!(sink.uploads, 0);
    assert!(sink.owner.surface(dc).unwrap().2.iter().all(|p| *p == request.background));
}

#[test]
fn typed_token_raster_reaches_canonical_surface_on_same_pthread() {
    std::thread::spawn(|| {
        std::thread_local! { static TLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
        TLS.with(|slot| slot.set(77));
        // SAFETY: gettid takes no pointer arguments and observes the real native test thread.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let bytes = std::fs::read("/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf").expect("installed TrueType test fixture");
        let font = RasterFont::from_bytes(&bytes, 16.0).unwrap();
        let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0 };
        let dc = sink.owner.create_dc(200, 60).unwrap();
        let text: Vec<u16> = "Oxide typed token".encode_utf16().collect();
        let request = abi::TextRequest { dc: dc as u64, count: text.len() as u32, flags: abi::OPAQUE, ..request() };
        render::draw(&font, &request, &text, None, &mut sink).unwrap();
        let (_, _, pixels) = sink.owner.surface(dc).unwrap();
        assert!(pixels.iter().filter(|p| **p != request.background).count() > 30, "glyph pixels must reach the real DC surface");
        assert_eq!(sink.uploads, 1);
        TLS.with(|slot| assert_eq!(slot.get(), 77));
        // SAFETY: gettid verifies rendering never switched to a second thread.
        assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, tid);
        sink.owner.delete_object(dc).unwrap();
        assert!(render::draw(&font, &request, &text, None, &mut sink).is_err());
    }).join().unwrap();
}
