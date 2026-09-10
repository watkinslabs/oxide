use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

pub(super) struct Measurement { pub output: abi::MeasureOutput, pub cumulative: Vec<i32> }

pub(super) fn measure(font: &RasterFont, request: &abi::MeasureRequest, text: &[u16]) -> Result<Measurement, ()> {
    if !request.valid() || text.len() != request.count as usize { return Err(()); }
    let metrics = font.text_metrics_w(request.weight, request.italic).map_err(|_| ())?;
    let glyph_form = request.kind == abi::MEASURE_EXTENT && request.flags != 0;
    let mut measured = if glyph_form { font.measure_glyphs(text, request.max_extent) }
        else { font.measure_utf16(text, request.max_extent) }.map_err(|_| ())?;
    justify(font, &metrics, text, glyph_form, &mut measured.cumulative, request.break_extra, request.break_rem);
    measured.width = measured.cumulative.last().copied().unwrap_or(measured.width);
    measured.fit = measured.cumulative.iter().take_while(|p| **p as u32 <= request.max_extent as u32).count() as u32;
    Ok(Measurement { output: abi::MeasureOutput { metrics, width: measured.width, height: measured.height,
        fit: measured.fit, count: request.count, reserved: 0, cumulative: 0 }, cumulative: measured.cumulative })
}

/// Spread the justification amount over the break characters, one extra unit
/// at a time from the remainder, exactly as the character positions carry it.
/// # C: O(count)
pub(super) fn justify(font: &RasterFont, metrics: &[u8; abi::TEXTMETRIC_BYTES], text: &[u16], glyph_form: bool,
    positions: &mut [i32], extra: i32, remainder: i32) {
    if extra == 0 && remainder == 0 { return; }
    let break_char = u16::from_le_bytes([metrics[50], metrics[51]]);
    let target = if glyph_form { font.glyph_for(u32::from(break_char)) } else { break_char };
    let (mut space, mut rem) = (0i32, remainder);
    for (index, position) in positions.iter_mut().enumerate() {
        if text.get(index) == Some(&target) {
            space = space.saturating_add(extra);
            if rem > 0 { space += 1; rem -= 1; }
        }
        *position = position.saturating_add(space);
    }
}

pub(super) unsafe fn callback(pointer: *const abi::MeasureRequest) -> bool {
    // SAFETY: caller selected the kernel-copied measurement header by its fixed ABI size.
    let request = unsafe { pointer.read_unaligned() };
    if !request.valid() { trace(&request,"request",None,None);return false; }
    let Some(font) = super::native::selected_font_with_width(request.height, request.width, request.weight, request.italic) else { trace(&request,"font",None,None);return false; };
    // SAFETY: kernel rewrites text to its aligned complete bounded UTF-16 stack copy, including empty text.
    let text = unsafe { std::slice::from_raw_parts(request.text as *const u16, request.count as usize) };
    let Ok(mut measured) = measure(&font, &request, text) else { trace(&request,"measure",None,None);return false; };
    measured.output.cumulative = measured.cumulative.as_ptr() as u64;
    // SAFETY: native result and cumulative allocation remain live through synchronous kernel copyout.
    let status = unsafe { libc::syscall(syscall::nt::NtService::QueryVirtualMemory.entry() as libc::c_long,
        abi::MEASURE_COPY, pointer as u64, abi::INFO_CLASS, &measured.output as *const abi::MeasureOutput as u64, 0u64, 0u64) };
    trace(&request,"copy",Some(&measured.output),Some(status));status == 0
}

fn trace(request:&abi::MeasureRequest,step:&str,output:Option<&abi::MeasureOutput>,status:Option<libc::c_long>){
    if std::env::var_os("OXIDE_GDI_TRACE").as_deref()!=Some(std::ffi::OsStr::new("1")){return;}
    eprintln!("windows-gdi: measure pid={} dc={:#x} kind={} count={} font={},{},{},{} step={} extent={:?} status={:?}",
        std::process::id(),request.dc,request.kind,request.count,request.height,request.width,request.weight,request.italic,
        step,output.map(|o|(o.width,o.height,o.fit)),status);
}
