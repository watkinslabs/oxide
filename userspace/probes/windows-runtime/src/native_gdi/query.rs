use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

pub(super) fn execute(font: &RasterFont, bytes: &[u8], request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    if !request.valid() || (request.input != 0 && input.len() != request.count as usize) { return None; }
    match request.kind {
        abi::QUERY_SYSTEM_METRIC => Some((super::nonclient::system_metric(input, request.first)?, Vec::new())),
        abi::QUERY_NONCLIENT => Some((1, super::nonclient::normalize(input, request.capacity)?)),
        abi::QUERY_CHARSET => {
            let signature = super::resource::signature(bytes)?;
            Some((0, if request.output == 0 { Vec::new() } else { signature.to_vec() }))
        }
        abi::QUERY_DATA => super::resource::font_data(bytes, request.table, request.offset, request.capacity, request.output != 0),
        abi::QUERY_GLYPHS => {
            let default = super::resource::default_character(bytes)?;
            let glyphs = font.glyph_indices(input, default, request.flags & 1 != 0);
            Some((request.count, glyphs.iter().flat_map(|g| g.to_le_bytes()).collect()))
        }
        abi::QUERY_ABC => {
            let values = if request.input == 0 { (0..request.count).map(|i| (request.first + i) as u16).collect::<Vec<_>>() } else { input.to_vec() };
            let mut output = Vec::with_capacity(values.len() * 12);
            for value in values {
                let glyph = if request.flags & abi::ABC_INDICES != 0 { value } else { font.glyph_indices(&[value], 0, false)[0] };
                let abc = font.glyph_abc(glyph).ok()?;
                for value in abc {
                    if request.flags & abi::ABC_INTEGER != 0 { output.extend_from_slice(&value.to_le_bytes()); }
                    else { output.extend_from_slice(&(value as f32).to_le_bytes()); }
                }
            }
            Some((1, output))
        }
        abi::QUERY_OUTLINE => {
            let mut output = super::outline::metrics(font, bytes, request.weight, request.italic)?;
            if request.output == 0 { Some((output.len() as u32, Vec::new())) }
            else { output.truncate(request.capacity as usize); Some((output.len() as u32, output)) }
        }
        _ => None,
    }
}

pub(super) unsafe fn callback(pointer: *const abi::QueryRequest) -> u64 {
    // SAFETY: native entry selects the fully copied fixed-size query header by its ABI size.
    let request = unsafe { pointer.read_unaligned() };
    let failure = request.failure();
    if !request.valid() { return failure; }
    let Some(font) = super::native::selected_font_with_width(request.height, request.width, request.weight, request.italic) else { return failure; };
    let Some(bytes) = super::native::selected_bytes(request.weight, request.italic) else { return failure; };
    let input = if request.input == 0 || request.count == 0 { &[] } else {
        // SAFETY: kernel copied bounded WORD input onto this Task's aligned callback stack.
        unsafe { std::slice::from_raw_parts(request.input as *const u16, request.count as usize) }
    };
    let Some((result, data)) = execute(&font, bytes, &request, input) else { return failure; };
    let output = abi::QueryOutput { result, length: data.len() as u32, data: data.as_ptr() as u64, reserved: 0 };
    if !request.accepts(&output) { return failure; }
    // SAFETY: request, output and owned data remain live throughout synchronous bounded kernel copyout.
    let status = unsafe { libc::syscall(syscall::nt::NtService::QueryVirtualMemory.entry() as libc::c_long,
        abi::QUERY_COPY, &request as *const _, abi::INFO_CLASS, &output as *const _, 0u64, 0u64) };
    if status == 0 { result as u64 } else { failure }
}
