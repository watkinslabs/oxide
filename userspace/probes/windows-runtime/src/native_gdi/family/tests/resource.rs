use super::{dword, request, run, short, utf16, REGISTRY};
use super::super::super::{native, registry};
use syscall::nt_native_gdi as abi;

const FONT: &str = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf";
const FONT_DIR_FACE: usize = 118;

fn deviceless(kind: u32) -> abi::QueryRequest {
    abi::QueryRequest { dc: 0, height: 0, width: 0, weight: 0, italic: 0, output: 0, ..request(kind) }
}

#[test]
fn the_face_name_is_truncated_into_the_callers_buffer_and_terminated() {
    let full = run(&abi::QueryRequest { output: 0, value: 0, ..request(abi::QUERY_TEXT_FACE) }, &[]).unwrap();
    assert_eq!(full, ("Liberation Mono".len() as u32 + 1, Vec::new()));
    let length = full.0;
    let (written, data) = run(&abi::QueryRequest { output: 0x10000, value: u64::from(length),
        capacity: length * 2, ..request(abi::QUERY_TEXT_FACE) }, &[]).unwrap();
    assert_eq!(written, length);
    let name: Vec<u16> = data.chunks_exact(2).map(|u| u16::from_le_bytes([u[0], u[1]])).collect();
    assert_eq!(name, utf16("Liberation Mono"));
    let (written, data) = run(&abi::QueryRequest { output: 0x10000, value: 4, capacity: 8,
        ..request(abi::QUERY_TEXT_FACE) }, &[]).unwrap();
    assert_eq!((written, data.len()), (4, 8));
    assert_eq!(short(&data, 6), 0);
    // A buffer of no characters writes nothing and reports what it was given.
    assert_eq!(run(&abi::QueryRequest { output: 0x10000, value: 0, capacity: 0,
        ..request(abi::QUERY_TEXT_FACE) }, &[]), Some((0, Vec::new())));
}

#[test]
fn realization_identity_names_a_face_whose_file_can_be_read_back() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    for capacity in [abi::REALIZATION_V0_BYTES, abi::REALIZATION_BYTES] {
        let (result, data) = run(&abi::QueryRequest { capacity, ..request(abi::QUERY_REALIZATION) }, &[]).unwrap();
        assert_eq!((result, data.len()), (1, capacity as usize));
        assert_eq!(dword(&data, 0), capacity);
        // Both bits report a realized, scalable face.
        assert_eq!(dword(&data, 4), 3);
        assert!(dword(&data, 8) > 0);
        let instance = dword(&data, 12);
        if capacity == abi::REALIZATION_BYTES {
            assert_eq!(dword(&data, 16), 1);
            assert_eq!((short(&data, 20), short(&data, 22)), (0, 0));
        }
        let face = registry::face(instance).expect("the realization names a registered face");
        let request = abi::QueryRequest { first: instance, capacity: 12, output: 0x10000, value: 4,
            ..deviceless(abi::QUERY_FONT_FILE_DATA) };
        let (ok, bytes) = run(&request, &[]).unwrap();
        assert_eq!((ok, bytes.as_slice()), (1, &face.bytes[4..16]));
    }
}

#[test]
fn a_font_file_read_past_its_own_end_is_refused_without_data() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    let face = registry::realized(400, 0).unwrap();
    let size = face.bytes.len() as u64;
    let request = abi::QueryRequest { first: face.handle, capacity: 16, output: 0x10000,
        value: size - 16, ..deviceless(abi::QUERY_FONT_FILE_DATA) };
    assert_eq!(run(&request, &[]).unwrap().0, 1);
    assert_eq!(run(&abi::QueryRequest { value: size - 15, ..request }, &[]), Some((0, Vec::new())));
    assert!(run(&abi::QueryRequest { first: 0, ..request }, &[]).is_none());
}

#[test]
fn font_file_info_reports_the_needed_size_before_it_reports_the_record() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    let face = registry::realized(400, 0).unwrap();
    let short_call = abi::QueryRequest { first: face.handle, capacity: 8, output: 0x10000, aux: 0x30000,
        ..deviceless(abi::QUERY_FONT_FILE_INFO) };
    let (result, data) = run(&short_call, &[]).unwrap();
    assert_eq!((result, data.len()), (0, 8));
    let needed = u64::from_le_bytes(data[..8].try_into().unwrap()) as u32;
    assert_eq!(needed as usize, 24 + face.path.len() * 2);
    let (result, data) = run(&abi::QueryRequest { capacity: needed, ..short_call }, &[]).unwrap();
    assert_eq!((result, data.len()), (1, 8 + needed as usize));
    assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), face.writetime);
    assert_eq!(u64::from_le_bytes(data[16..24].try_into().unwrap()), face.bytes.len() as u64);
    let path: Vec<u16> = data[24..].chunks_exact(2).map(|u| u16::from_le_bytes([u[0], u[1]]))
        .take_while(|unit| *unit != 0).collect();
    assert_eq!(String::from_utf16(&path).unwrap(), FONT);
    // The record is terminated inside the size the caller was told to allocate.
    assert_eq!(needed as usize, 24 + path.len() * 2);
}

#[test]
fn the_font_directory_record_describes_the_file_it_was_asked_about() {
    let path = utf16(FONT);
    let request = abi::QueryRequest { count: path.len() as u32, input: 1, capacity: abi::FONT_DIR_BYTES,
        output: 0x10000, flags: 1, ..deviceless(abi::QUERY_MAKE_FONT_DIR) };
    let (result, record) = run(&request, &path).unwrap();
    assert_eq!(record.len(), abi::FONT_DIR_BYTES as usize);
    assert_eq!(short(&record, 0), 1);
    assert_eq!(short(&record, 4), 0x200);
    assert_eq!(dword(&record, 6), 149);
    assert_eq!(&record[10..22], b"Wine fontdir");
    // The embedding request sets the high bit of the type field.
    assert_eq!(short(&record, 70), 0x4083);
    assert_eq!(short(&record, 72), 2048);
    assert_eq!((short(&record, 74), short(&record, 76)), (72, 72));
    assert_eq!(dword(&record, 109), FONT_DIR_FACE as u32);
    let names: Vec<&[u8]> = record[FONT_DIR_FACE..result as usize].split(|byte| *byte == 0).collect();
    assert_eq!(names[0], b"Liberation Mono");
    assert_eq!(names[2], b"Regular");
    assert!(result as usize > FONT_DIR_FACE && result <= abi::FONT_DIR_BYTES);
    // A path that is not NUL-terminated names nothing.
    let unterminated: Vec<u16> = path.iter().copied().take(path.len() - 1).chain(std::iter::once(b'x' as u16)).collect();
    assert_eq!(run(&abi::QueryRequest { count: unterminated.len() as u32, ..request }, &unterminated),
        Some((0, Vec::new())));
}

#[test]
fn a_font_resource_is_added_once_per_call_and_removed_on_the_last_release() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    native::prepare_fonts().unwrap();
    let path = utf16("/usr/share/fonts/liberation-mono-fonts/LiberationMono-Bold.ttf");
    let add = abi::QueryRequest { count: path.len() as u32, input: 1, flags: 0,
        ..deviceless(abi::QUERY_ADD_FONT_RESOURCE) };
    let before = registry::faces().len();
    assert_eq!(run(&add, &path), Some((1, Vec::new())));
    assert_eq!(registry::faces().len(), before, "an installed file takes another reference");
    let remove = abi::QueryRequest { ..add };
    let remove = abi::QueryRequest { kind: abi::QUERY_REMOVE_FONT_RESOURCE, ..remove };
    assert_eq!(run(&remove, &path), Some((1, Vec::new())));
    assert_eq!(registry::faces().len(), before);
    // A name that is neither a path nor a bare font file names nothing.
    let relative = utf16("fonts/Nothing.ttf");
    assert_eq!(run(&abi::QueryRequest { count: relative.len() as u32, ..add }, &relative), None);
    let missing = utf16("NoSuchFont.ttf");
    assert_eq!(run(&abi::QueryRequest { count: missing.len() as u32, ..add }, &missing), None);
    assert_eq!(run(&abi::QueryRequest { count: missing.len() as u32, ..remove }, &missing),
        Some((0, Vec::new())));
}

#[test]
fn a_memory_resource_is_installed_from_the_callers_own_bytes_and_removed_by_handle() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    native::prepare_fonts().unwrap();
    let bytes = std::fs::read(FONT).unwrap();
    let add = abi::QueryRequest { value: bytes.as_ptr() as u64, capacity: bytes.len() as u32,
        aux: 0x30000, ..deviceless(abi::QUERY_ADD_MEM_FONT) };
    let before = registry::faces().len();
    let (handle, count) = run(&add, &[]).unwrap();
    assert_ne!(handle, 0);
    assert_eq!(dword(&count, 0), 1);
    assert_eq!(registry::faces().len(), before + 1);
    let remove = abi::QueryRequest { value: u64::from(handle), ..deviceless(abi::QUERY_REMOVE_MEM_FONT) };
    assert_eq!(run(&remove, &[]), Some((1, Vec::new())));
    assert_eq!(registry::faces().len(), before);
    // An unknown handle is still reported as removed, as the reference reports it.
    assert_eq!(run(&abi::QueryRequest { value: 0xdead, ..remove }, &[]), Some((1, Vec::new())));
}
