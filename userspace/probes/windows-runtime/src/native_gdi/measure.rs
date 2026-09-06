use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

pub(super) struct Measurement { pub output: abi::MeasureOutput, pub cumulative: Vec<i32> }

pub(super) fn measure(font: &RasterFont, request: &abi::MeasureRequest, text: &[u16]) -> Result<Measurement, ()> {
    if !request.valid() || text.len() != request.count as usize { return Err(()); }
    let metrics = font.text_metrics_w(request.weight, request.italic).map_err(|_| ())?;
    let measured = if request.kind == abi::MEASURE_EXTENT && request.flags != 0 {
        font.measure_glyphs(text, request.max_extent)
    } else { font.measure_utf16(text, request.max_extent) }.map_err(|_| ())?;
    Ok(Measurement { output: abi::MeasureOutput { metrics, width: measured.width, height: measured.height,
        fit: measured.fit, count: request.count, reserved: 0, cumulative: 0 }, cumulative: measured.cumulative })
}

pub(super) unsafe fn callback(pointer: *const abi::MeasureRequest) -> bool {
    // SAFETY: caller selected the kernel-copied measurement header by its fixed ABI size.
    let request = unsafe { pointer.read_unaligned() };
    if !request.valid() { return false; }
    let Some(font) = super::native::selected_font_with_width(request.height, request.width, request.weight, request.italic) else { return false; };
    // SAFETY: kernel rewrites text to its aligned complete bounded UTF-16 stack copy, including empty text.
    let text = unsafe { std::slice::from_raw_parts(request.text as *const u16, request.count as usize) };
    let Ok(mut measured) = measure(&font, &request, text) else { return false; };
    measured.output.cumulative = measured.cumulative.as_ptr() as u64;
    // SAFETY: native result and cumulative allocation remain live through synchronous kernel copyout.
    let status = unsafe { libc::syscall(syscall::nt::NtService::QueryVirtualMemory.entry() as libc::c_long,
        abi::MEASURE_COPY, pointer as u64, abi::INFO_CLASS, &measured.output as *const abi::MeasureOutput as u64, 0u64, 0u64) };
    status == 0
}
