use super::*;

fn described() -> ClassDescription {
    ClassDescription { style: 0x0003, cb_wnd_extra: 8, cb_cls_extra: 4, background: 6, cursor: 0x1111, icon: 0x2222,
        icon_sm: 0x3333, module: 0x1400_0000, menu_name: 0x67 }
}

fn reply() -> ClassInfoReply {
    ClassInfoReply { wndproc: 0x1_4000_42c0, cb_wnd_extra: 8, instance: 0x1_4000_0000, class_name: 0x7ffd_0000 }
}

fn field(bytes: &[u8; BYTES], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }
fn word(bytes: &[u8; BYTES], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

#[test]
fn the_menu_name_a_class_registered_reaches_the_caller() {
    assert_eq!(field(&encode(&described(), &reply()), 56), 0x67);
}

/// A class registered with MAKEINTRESOURCE names its menu by resource id, and
/// the id is what the caller must read back: window creation loads the menu
/// from this field, so a class whose id did not survive the round trip shows
/// no menu bar at all.
#[test]
fn an_integer_resource_menu_name_reaches_the_caller_as_the_id_itself() {
    let mut class = described();
    class.menu_name = 0x201;
    assert_eq!(field(&encode(&class, &reply()), 56), 0x201);
}

#[test]
fn a_class_registered_without_a_menu_name_reports_none() {
    let mut class = described();
    class.menu_name = 0;
    assert_eq!(field(&encode(&class, &reply()), 56), 0);
}

#[test]
fn the_instance_lands_in_its_own_field_and_never_in_the_icon() {
    let bytes = encode(&described(), &reply());
    assert_eq!(field(&bytes, 24), 0x1_4000_0000);
    assert_eq!(field(&bytes, 32), 0x2222);
}

#[test]
fn every_remaining_field_carries_the_registered_value() {
    let bytes = encode(&described(), &reply());
    assert_eq!(word(&bytes, 0), BYTES as u32);
    assert_eq!(word(&bytes, 4), 0x0003);
    assert_eq!(field(&bytes, 8), 0x1_4000_42c0);
    assert_eq!(word(&bytes, 16), 4);
    assert_eq!(word(&bytes, 20), 8);
    assert_eq!(field(&bytes, 40), 0x1111);
    assert_eq!(field(&bytes, 48), 6);
    assert_eq!(field(&bytes, 64), 0x7ffd_0000);
    assert_eq!(field(&bytes, 72), 0x3333);
}

#[test]
fn a_registration_decodes_to_the_fields_it_was_encoded_from() {
    let bytes = encode(&described(), &reply());
    let fields = decode(&bytes).expect("this layout's own encoding must decode");
    assert_eq!(fields.style, 0x0003);
    assert_eq!(fields.wndproc, 0x1_4000_42c0);
    assert_eq!(fields.cb_cls_extra, 4);
    assert_eq!(fields.cb_wnd_extra, 8);
    assert_eq!(fields.instance, 0x1_4000_0000);
    assert_eq!(fields.icon, 0x2222);
    assert_eq!(fields.icon_sm, 0x3333);
    assert_eq!(fields.cursor, 0x1111);
    assert_eq!(fields.background, 6);
    assert_eq!(fields.menu_name, 0x67);
    assert_eq!(fields.class_name, 0x7ffd_0000);
}

#[test]
fn a_structure_whose_size_is_not_this_layout_decodes_to_nothing() {
    let mut bytes = encode(&described(), &reply());
    assert!(decode(&bytes).is_some());
    bytes[0] = (BYTES as u32 - 8) as u8;
    assert!(decode(&bytes).is_none());
}

#[test]
fn a_negative_extra_size_survives_the_decode_so_the_owner_can_refuse_it() {
    let mut bytes = encode(&described(), &reply());
    bytes[CLS_EXTRA..CLS_EXTRA + 4].copy_from_slice(&(-1i32).to_le_bytes());
    assert_eq!(decode(&bytes).unwrap().cb_cls_extra, -1);
}
