use super::*;

#[test]
fn entry_fixture_has_unique_type_stock_and_no_object_pointer() {
    let entry = HandleEntry::for_handle(0x12c10040, 0x1234, 0x12345678).unwrap();
    let bytes = entry.encode().unwrap();
    assert_eq!(bytes, [0,0,0,0,0,0,0,0,0x34,0x12,0,0,0xc1,0x12,1,0,0x78,0x56,0x34,0x12,0,0,0,0]);
    assert_eq!(HandleEntry::decode(&bytes), Ok(entry));
    assert_eq!((entry.extended_type(), entry.stock(), entry.generation()), (0x41, true, 0x12));
    assert!(entry.client_matches(0x12c10040)); assert!(entry.client_matches(0x40));
    assert!(!entry.client_matches(0x13c10040));
    let font = HandleEntry::for_handle(TYPE_FONT | 65, 1, 0).unwrap();
    assert_eq!(font.kind, 10); assert!(!font.stock());
}

#[test]
fn malformed_entries_and_kernel_pointers_are_rejected() {
    assert_eq!(HandleEntry::for_handle(64, 1, 0), Err(Error::Handle));
    assert_eq!(HandleEntry::for_handle(TYPE_DC | 64, 1, u64::MAX), Err(Error::Pointer));
    let mut bytes = HandleEntry::for_handle(TYPE_DC | 64, 1, 0).unwrap().encode().unwrap();
    bytes[0] = 1; assert_eq!(HandleEntry::decode(&bytes), Err(Error::ObjectPointer)); bytes[0] = 0;
    bytes[14] = 10; assert_eq!(HandleEntry::decode(&bytes), Err(Error::Handle));
    bytes[14] = 0; assert!(!HandleEntry::decode(&bytes).unwrap().client_matches(TYPE_DC | 64));
    for n in 0..ENTRY_SIZE { assert_eq!(HandleEntry::decode(&bytes[..n]), Err(Error::Length)); }
}

#[test]
fn retained_mapping_arithmetic_checks_entire_arena() {
    assert_eq!(entry_address(0x10000, 65535), Ok(0x10000 + 65535 * 24));
    assert_eq!(dc_attr_address(0x10000, 65535), Ok(0x10000 + 65535 * 192));
    assert_eq!(entry_address(0x10000, 65536), Err(Error::Handle));
    for base in [0, 1, u64::MAX, hal::USER_VA_END - 8] {
        assert_eq!(entry_address(base, 0), Err(Error::Pointer));
        assert_eq!(dc_attr_address(base, 0), Err(Error::Pointer));
    }
}

#[test]
fn dc_defaults_fill_complete_record_without_client_pointer_payloads() {
    let bytes = encode_dc_attr(TYPE_DC | 64, 640, 480, DcText::default()).unwrap();
    assert_eq!(bytes.len(), 192);
    assert_eq!(&bytes[48..60], &[0,0,2,0,1,0,13,0,1,0,1,0]);
    assert_eq!(&bytes[72..88], &[0,0,0,0,0,0,0,0,0x80,2,0,0,0xe0,1,0,0]);
    assert_eq!(get32(&bytes, 88), 10.0f32.to_bits());
    assert_eq!(&bytes[168..192], &[0;24]);
    assert_eq!(decode_text(&bytes, TYPE_DC | 64), Ok(DcText::default()));
}

#[test]
fn direct_client_writes_supply_snapshot_not_cached_defaults() {
    let mut bytes = encode_dc_attr(TYPE_DC | 64, 640, 480, DcText::default()).unwrap();
    put32(&mut bytes, 24, 0x00332211); put32(&mut bytes, 12, 0x00665544);
    put16(&mut bytes, 48, 0x011f); put16(&mut bytes, 50, 1);
    put32(&mut bytes, 28, (-19i32) as u32); put32(&mut bytes, 32, 73);
    assert_eq!(decode_text(&bytes, TYPE_DC | 64), Ok(DcText { foreground: 0x112233,
        background: 0x445566, alignment: 0x011f, background_mode: 1, current_position: (-19,73) }));
    assert_eq!(decode_text(&bytes, TYPE_DC | 65), Err(Error::Handle));
}

#[test]
fn malformed_text_attributes_fail_before_callback() {
    let initial = encode_dc_attr(TYPE_DC | 64, 640, 480, DcText::default()).unwrap();
    for (offset, value, error) in [(4,1,Error::Disabled),(24,0x01000001,Error::Color),
        (60,2,Error::UnsupportedTransform),(100,1,Error::UnsupportedTransform),(44,1,Error::UnsupportedTransform),
        (80,u32::MAX,Error::Dimensions)] {
        let mut bytes = initial; put32(&mut bytes, offset, value);
        assert_eq!(decode_text(&bytes, TYPE_DC | 64), Err(error));
    }
    for value in [0,3,65535] {
        let mut bytes = initial; put16(&mut bytes, 50, value);
        assert_eq!(decode_text(&bytes, TYPE_DC | 64), Err(Error::BackgroundMode));
    }
    for value in [4,16,0x200,65535] {
        let mut bytes = initial; put16(&mut bytes, 48, value);
        assert_eq!(decode_text(&bytes, TYPE_DC | 64), Err(Error::Alignment));
    }
    for n in 0..DC_ATTR_SIZE { assert_eq!(decode_text(&initial[..n], TYPE_DC | 64), Err(Error::Length)); }
}

#[test]
fn color_conversion_and_negative_dimensions_are_explicit() {
    assert_eq!(colorref_to_xrgb(0x00563412), Ok(0x00123456));
    assert_eq!(xrgb_to_colorref(0x00123456), Ok(0x00563412));
    assert_eq!(colorref_to_xrgb(0x02000001), Err(Error::Color));
    for width in [-1,i32::MIN] { assert_eq!(encode_dc_attr(TYPE_DC | 64, width, 1, DcText::default()), Err(Error::Dimensions)); }
    assert_eq!(encode_dc_attr(TYPE_FONT | 64, 1, 1, DcText::default()), Err(Error::Handle));
}

#[test]
fn alignment_combinations_and_signed_current_position_round_trip() {
    for horizontal in [0,2,6] { for vertical in [0,8,24] { for flags in [0,1,256,257] {
        let text = DcText { foreground: 0x123456, background: 0x654321,
            alignment: horizontal | vertical | flags, background_mode: 1,
            current_position: (i32::MIN, i32::MAX) };
        let bytes = encode_dc_attr(TYPE_MEMDC | 64, 10, 20, text).unwrap();
        assert_eq!(decode_text(&bytes, TYPE_MEMDC | 64), Ok(text));
    }}}
}

#[test]
fn copied_geometry_overflow_and_full_record_boundaries_are_rejected() {
    let mut bytes = encode_dc_attr(TYPE_DC | 64, 10, 20, DcText::default()).unwrap();
    put32(&mut bytes, dc::VIS_RECT, i32::MIN as u32);
    put32(&mut bytes, dc::VIS_RECT + 8, i32::MAX as u32);
    assert_eq!(decode_text(&bytes, TYPE_DC | 64), Err(Error::Dimensions));
    let oversized = [0u8; DC_ATTR_SIZE + 1];
    assert_eq!(decode_text(&oversized, TYPE_DC | 64), Err(Error::Length));
    assert_eq!(HandleEntry::decode(&[0u8; ENTRY_SIZE + 1]), Err(Error::Length));
    let final_table = hal::USER_VA_END - TABLE_BYTES as u64;
    let final_attrs = hal::USER_VA_END - DC_ATTR_BYTES as u64;
    assert_eq!(entry_address(final_table, HANDLE_COUNT - 1), Ok(hal::USER_VA_END - ENTRY_SIZE as u64));
    assert_eq!(dc_attr_address(final_attrs, HANDLE_COUNT - 1), Ok(hal::USER_VA_END - DC_ATTR_SIZE as u64));
    assert_eq!(entry_address(final_table + 8, 0), Err(Error::Pointer));
    assert_eq!(dc_attr_address(final_attrs + 8, 0), Err(Error::Pointer));
}

#[test]
#[ignore = "requires WINE_GDI_INCLUDE pinned headers and GDI_LAYOUT_TMP disk artifact parent"]
fn pinned_c_headers_match_every_offset_and_encoded_bytes() {
    use std::{format, io::Write, process::{Command, Stdio}, string::String, vec::Vec};
    let include = std::env::var("WINE_GDI_INCLUDE").expect("pinned include path");
    let temporary = std::env::var("GDI_LAYOUT_TMP").expect("disk artifact parent");
    let binary = std::path::Path::new(&temporary).join(format!("gdi-c-layout-{}", std::process::id()));
    let mut source = String::from("#include <stdio.h>\n#include <stddef.h>\n#include \"windef.h\"\n#include \"winbase.h\"\n#include \"ntgdi.h\"\n");
    for (ty, size) in [("GDI_HANDLE_ENTRY", ENTRY_SIZE), ("DC_ATTR", DC_ATTR_SIZE)] {
        source.push_str(&format!("_Static_assert(sizeof({ty})=={size},\"size\");\n_Static_assert(_Alignof({ty})==8,\"align\");\n"));
    }
    for (field, offset) in [("Object",0),("Owner",8),("Unique",12),("Type",14),("Flags",15),("UserPointer",16)] {
        source.push_str(&format!("_Static_assert(offsetof(GDI_HANDLE_ENTRY,{field})=={offset},\"{field}\");\n"));
    }
    for (field, offset) in [("hdc",dc::HDC),("disabled",dc::DISABLED),("save_level",dc::SAVE_LEVEL),
        ("background_color",dc::BACKGROUND_COLOR),("brush_color",dc::BRUSH_COLOR),("pen_color",dc::PEN_COLOR),
        ("text_color",dc::TEXT_COLOR),("cur_pos",dc::CUR_POS),("graphics_mode",dc::GRAPHICS_MODE),
        ("arc_direction",dc::ARC_DIRECTION),("layout",dc::LAYOUT),("text_align",dc::TEXT_ALIGN),
        ("background_mode",dc::BACKGROUND_MODE),("poly_fill_mode",dc::POLY_FILL_MODE),("rop_mode",dc::ROP_MODE),
        ("rel_abs_mode",dc::REL_ABS_MODE),("stretch_blt_mode",dc::STRETCH_BLT_MODE),("map_mode",dc::MAP_MODE),
        ("char_extra",dc::CHAR_EXTRA),("mapper_flags",dc::MAPPER_FLAGS),("vis_rect",dc::VIS_RECT),
        ("miter_limit",dc::MITER_LIMIT),("brush_org",dc::BRUSH_ORG),("wnd_org",dc::WND_ORG),
        ("wnd_ext",dc::WND_EXT),("vport_org",dc::VPORT_ORG),("vport_ext",dc::VPORT_EXT),
        ("virtual_res",dc::VIRTUAL_RES),("virtual_size",dc::VIRTUAL_SIZE),("font_code_page",dc::FONT_CODE_PAGE),
        ("emf_bounds",dc::EMF_BOUNDS),("emf",dc::EMF),("abort_proc",dc::ABORT_PROC),("print",dc::PRINT)] {
        source.push_str(&format!("_Static_assert(offsetof(DC_ATTR,{field})=={offset},\"{field}\");\n"));
    }
    source.push_str("int main(void) { GDI_HANDLE_ENTRY e={0}; e.Owner.ProcessId=0x1234; e.ExtType=0x41; e.StockFlag=1; e.Generation=0x12; e.Type=1; e.UserPointer=0x12345678; fwrite(&e,1,sizeof(e),stdout);\n");
    source.push_str("DC_ATTR d={0}; d.hdc=0x10040; d.background_color=d.brush_color=0xffffff; d.graphics_mode=GM_COMPATIBLE; d.arc_direction=AD_COUNTERCLOCKWISE; d.background_mode=OPAQUE; d.poly_fill_mode=ALTERNATE; d.rop_mode=R2_COPYPEN; d.rel_abs_mode=ABSOLUTE; d.stretch_blt_mode=BLACKONWHITE; d.map_mode=MM_TEXT; d.vis_rect.right=640; d.vis_rect.bottom=480; d.miter_limit=10.0f; d.wnd_ext.cx=d.wnd_ext.cy=d.vport_ext.cx=d.vport_ext.cy=1; fwrite(&d,1,sizeof(d),stdout); return 0; }\n");
    for compiler in ["gcc", "aarch64-linux-gnu-gcc"] {
        let mut command = Command::new(compiler);
        command.args(["-x", "c", "-std=gnu11", "-fshort-wchar", "-fmax-errors=3", "-D__WINESRC__", "-I", &include]);
        if compiler.starts_with("aarch64") { command.args(["--sysroot=/usr/aarch64-redhat-linux/sys-root/fc42", "-c"]); }
        let target = if compiler == "gcc" { binary.clone() } else { binary.with_extension("arm.o") };
        let mut child = command.arg("-o").arg(&target).arg("-").stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(source.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        if compiler == "gcc" {
            let output = Command::new(&target).output().unwrap();
            assert!(output.status.success());
            let mut expected: Vec<u8> = HandleEntry::for_handle(0x12c10040,0x1234,0x12345678).unwrap().encode().unwrap().to_vec();
            expected.extend_from_slice(&encode_dc_attr(TYPE_DC | 64,640,480,DcText::default()).unwrap());
            assert_eq!(output.stdout, expected);
        }
    }
}
