use std::{collections::BTreeMap, sync::{Arc, Mutex, OnceLock}};
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;
#[path = "font_height.rs"]
pub(super) mod font_height;

struct Fonts { bytes: [Vec<u8>; 4], sizes: Mutex<BTreeMap<(i32, i32, usize), Arc<RasterFont>>> }
static FONTS: OnceLock<Fonts> = OnceLock::new();
const FONT_DIRECTORY: &str = "/usr/share/fonts/liberation-mono-fonts";
const FONT_FILES: [&str; 4] = ["LiberationMono-Regular.ttf", "LiberationMono-Bold.ttf", "LiberationMono-Italic.ttf", "LiberationMono-BoldItalic.ttf"];
const MAX_FONT_BYTES: u64 = 16 * 1024 * 1024;

/// Load installed userspace font and register after native NTDLL/factory attachment.
pub fn install() -> Result<(), String> {
    prepare_fonts()?;
    let (entry, ret) = super::platform::entries();
    // SAFETY: callback entries stay mapped for process lifetime; kernel validates ABI/version.
    let result = unsafe { libc::syscall(syscall::nt::NtService::QueryVirtualMemory.entry() as libc::c_long,
        abi::REGISTER, entry, abi::INFO_CLASS, ret, abi::VERSION as u64, 0u64) };
    if result == 0 { Ok(()) } else { Err(format!("native GDI registration failed: {result:#x}")) }
}

pub(super) fn prepare_fonts() -> Result<(), String> {
    if FONTS.get().is_none() {
        use std::io::Read;
        let mut bytes: [Vec<u8>; 4] = std::array::from_fn(|_| Vec::new());
        let mut sizes = BTreeMap::new();
        for (style, name) in FONT_FILES.iter().enumerate() {
            let file = std::fs::File::open(std::path::Path::new(FONT_DIRECTORY).join(name)).map_err(|e| e.to_string())?;
            file.take(MAX_FONT_BYTES + 1).read_to_end(&mut bytes[style]).map_err(|e| e.to_string())?;
            if bytes[style].len() as u64 > MAX_FONT_BYTES { return Err("native GDI font exceeds byte limit".into()); }
            let size = font_height::pixel_size(&bytes[style], 16).ok_or("native GDI font height metadata is invalid")?;
            let font = RasterFont::from_bytes(&bytes[style], size).map_err(|_| "native GDI font is invalid")?;
            sizes.insert((16, 0, style), Arc::new(font));
        }
        let _ = FONTS.set(Fonts { bytes, sizes: Mutex::new(sizes) });
    }
    Ok(())
}

pub(super) unsafe fn callback(pointer: *const abi::TextRequest) -> u64 {
    if pointer.is_null() { return 0; }
    // SAFETY: every callback starts with its fully copied fixed version/size prefix.
    let size = unsafe { pointer.cast::<u32>().add(1).read_unaligned() } as usize;
    let failure = if size == std::mem::size_of::<abi::QueryRequest>() {
        // SAFETY: query-sized copied header contains the operation-specific failure domain.
        unsafe { pointer.cast::<abi::QueryRequest>().read_unaligned() }.failure()
    } else { 0 };
    std::panic::catch_unwind(|| {
        // SAFETY: both callback variants begin with the same initialized version/size prefix.
        let size = unsafe { pointer.cast::<u32>().add(1).read_unaligned() };
        if size as usize == std::mem::size_of::<abi::QueryRequest>() {
            // SAFETY: query size identifies the complete kernel-copied query record.
            return unsafe { super::query::callback(pointer.cast()) };
        }
        if size as usize == std::mem::size_of::<abi::MeasureRequest>() {
            // SAFETY: kernel copied the complete measurement variant selected by its ABI size.
            return u64::from(unsafe { super::measure::callback(pointer.cast()) });
        }
        if size as usize != std::mem::size_of::<abi::TextRequest>() { return failure; }
        // SAFETY: kernel callback copied the fixed header into this Task's user stack.
        let request = unsafe { pointer.read_unaligned() };
        if !request.valid() { return 0; }
        let Some(font) = selected_font_with_width(request.height, request.width, request.weight, request.italic) else { return 0; };
        // SAFETY: kernel validates count and rewrites both aligned pointers to its complete stack copy.
        let text = if request.count == 0 { &[] } else { unsafe { std::slice::from_raw_parts(request.text as *const u16, request.count as usize) } };
        let advances = if request.advances == 0 { None } else {
            // SAFETY: non-null advances points at count copied, i32-aligned elements.
            Some(unsafe { std::slice::from_raw_parts(request.advances as *const i32, request.advance_count()) })
        };
        u64::from(super::render::draw(&font, &request, text, advances, &mut super::render::NativeSink).is_ok())
    }).unwrap_or(failure)
}

pub(super) fn selected_bytes(weight: i32, italic: u32) -> Option<&'static [u8]> {
    if !(0..=1000).contains(&weight) || italic > 1 { return None; }
    Some(&FONTS.get()?.bytes[usize::from(weight >= 600) | ((italic as usize) << 1)])
}

#[cfg(test)]
pub(super) fn selected_font(height: i32, weight: i32, italic: u32) -> Option<Arc<RasterFont>> {
    selected_font_with_width(height, 0, weight, italic)
}

pub(super) fn selected_font_with_width(height: i32, width: i32, weight: i32, italic: u32) -> Option<Arc<RasterFont>> {
    let fonts = FONTS.get()?;
    let width = width.checked_abs()?;
    if height.checked_abs()? > abi::MAX_HEIGHT || width > abi::MAX_WIDTH || italic > 1 || !(0..=1000).contains(&weight) { return None; }
    let height = if height == 0 { 16 } else { height };
    let style = usize::from(weight >= 600) | ((italic as usize) << 1);
    let mut sizes = fonts.sizes.lock().ok()?;
    if let Some(font) = sizes.get(&(height, width, style)) { return Some(Arc::clone(font)); }
    let size = font_height::pixel_size(&fonts.bytes[style], height)?;
    let font = Arc::new(RasterFont::from_bytes(&fonts.bytes[style], size).ok()?.with_logical_width(width).ok()?);
    sizes.insert((height, width, style), Arc::clone(&font));
    Some(font)
}
